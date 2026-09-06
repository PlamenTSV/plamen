# Program Facts G3-00 parity-launcher runtime-closure amendment

Status: `CONTRACT_ONLY_NON_LINEAGE_STABLE_DRAFT_PENDING_LATE_BOUND_CROSSCHECK_BRIDGE_R3_7`

Disposition: `REPAIR_UNMATERIALIZED_NATIVE_PROVENANCE_AND_EVIDENCE`

Admission: `BLOCKED_PENDING_SEPARATELY_ACCEPTED_CROSSCHECK_V3_LINEAGE_BRIDGE`

Sections 17-20 are retained repair history and section 21 is the non-lineage
R3.7 normative repair closure over the retained sections
1-16 base.  Scenario, review-roster, and digest declarations in that base are
synchronized to the R3.7 denominator; superseded lifecycle/schema expressions
remain visible for review history.  Where any earlier sentence, schema
expression, identity rule, recovery row, or construction-order statement
conflicts with section 21, section 21 controls in full; otherwise the latest
nonconflicting rule controls.  An implementation or review MUST NOT select a
superseded value.

This is the versioned execution, evidence, I/O, and publication successor for
the G3-00 three-way schema-contract parity launcher. It changes no closed v1
object and grants no process-spawn or native-host authority. `MUST`, `MUST NOT`,
`REQUIRED`, `SHOULD`, and `MAY` have RFC 2119 meaning.

## 1. Stable inputs, review disposition, and precedence

The following identities were independently recomputed from the current bytes.
They are the complete design inputs to this amendment, but not a complete
current admission lineage:

| Class | Path | Bytes | SHA-256 |
|---|---|---:|---|
| accepted semantic parent | `architecture/program-facts-g3-00-schema-vector-clarification-amendment.md` | 80,218 | `f03b07bea209dde4cf2cf8dcebd3e4c618a5fd56196c4448594a9d744136f7fa` |
| accepted parent receipt | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_VECTOR_CLARIFICATION_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | 15,568 | `3db4b56a2132bbd5d8dd7cb59bb68cdb4e32aa5f109da55420b05b786fee5e92` |
| first launcher candidate | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/capture_schema_contract_parity_evidence_v1.py` | 45,280 | `dad142df8c95b432066073caf6981a4129a42edb6bc206a178cbcbcc57f865b8` |
| pending candidate handoff | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_IMPLEMENTATION_HANDOFF.PENDING.v1.json` | 6,504 | `22d0b950d825634c25b4a1bdbf75d0a46d9a1c7a67392d7cdfd7157f48162557` |
| original red history | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/LAUNCHER_FIXTURE_FIRST_RED_EVIDENCE.v1.json` | 1,370 | `b66a0b525194588d80b927ada6d29063a6f3f4161088285345ea5d3f19e3d81b` |
| later 13-method fixture | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/test_capture_schema_contract_parity_evidence_v1.py` | 16,991 | `790c661bb1f4293c3bf7b5cf6e779cfab93867cb7bd5c9e4ac3fc7aed5aa0fc8` |
| 19-method repair red | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/LAUNCHER_REPAIR_RED_V2_EVIDENCE.v1.json` | 9,939 | `e41588b4ee765b14de634c3c6200d130a7323746d6add566477817b524612e65` |

Only the first two rows are accepted normative authority. The other five rows
are immutable candidate/history inputs and have no admission, adoption,
capture, runtime, review, or release authority.

The independent launcher review disposition supplied to this amendment author
is `REPAIR`. No stable independent-review artifact was supplied, so this
document does not invent, name, or hash one. The four findings are design inputs:

1. the original red receipt stopped in `setUpClass` at `FileNotFoundError`, ran
   zero test methods, and cannot prove fixture-before-repair chronology for the
   13-method fixture added later;
2. `(python, source)` with `environment={}` does not isolate CPython startup,
   user/site paths, `.pth`, startup customizers, or transitive imports;
3. publishing before the final three-read/link checks can leave a canonical-
   looking file after failure or crash; and
4. repeated path opens permit symlink/hardlink substitution and TOCTOU.

The 19-method repair red is valid evidence that all 19 methods executed against
the pinned first candidate: one baseline-pin check passed and 18 expected repair
checks failed with zero setup errors. It is still non-authoritative and is not
the complete successor denominator in section 10.

Where this amendment conflicts with the accepted clarification's launcher,
outer-evidence, output-path, stable-read, or publication language, this
amendment controls only after its own independent receipt passes. The complete
`parity` parsed value and its semantics remain exactly the accepted
`plamen.program_facts_gate3_schema_contract_parity.v1` contract. Every other
accepted clarification rule remains unchanged.

## 2. Immutable v1 and the acyclic v2 successor

The following v1 strings, sources, historical records, and any files ever
created under them remain immutable:

- `plamen.program_facts_gate3_schema_contract_parity.v1`;
- `plamen.program_facts_gate3_schema_contract_parity_evidence.v1`;
- `PROGRAM_FACTS_GATE3_SCHEMA_CONTRACT_PARITY_EVIDENCE_V1`;
- the first launcher candidate and its pending handoff;
- the original zero-method red and the later 13-method fixture; and
- every v1 mapped `process_evidence/*.parity_evidence.v1.json` path.

No v2 implementation may overwrite, reinterpret, repin, migrate in place, or
retroactively validate one of those objects. The proposed R3 successor paths
are exactly the following; listing a path does not assert that its source is the
current accepted implementation:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_AMENDMENT_INDEPENDENT_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_LAUNCHER_V2_SCENARIO_MANIFEST.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/test_capture_schema_contract_parity_evidence_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/LAUNCHER_RUNTIME_CLOSURE_V2_FIXTURE_FIRST_RED_EVIDENCE.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/LAUNCHER_RUNTIME_CLOSURE_V2_GREEN_EVIDENCE.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/parity_bootstrap_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_BOOTSTRAP_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/build_private_runtime_v1.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/RUNTIME_BUILDER_V1_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_RUNTIME_BUILD_PLAN_LOCK.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_RUNTIME_BUILD_PLAN_LOCK_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/GENERATOR_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/EVALUATOR_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/CROSSCHECK_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/capture_schema_contract_parity_evidence_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/collect_windows_native_images_v1.cpp
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_LAUNCHER_RUNTIME_CLOSURE.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_LAUNCHER_RUNTIME_CLOSURE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_V2_IMPLEMENTATION_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_V2_PRE_AGGREGATE_LINEAGE.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/locks/<role-lower>.lock.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/<lock_quarantine_id>/lock-quarantine.intent.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/<lock_quarantine_id>/move-progress/0000000000000000.moved.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/<lock_quarantine_id>/lock-quarantine.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/<lock_quarantine_id>/observed-lock.v2.bin
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/transaction.head.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/head-staging/<head_revision>/head.next.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/head-history/<head_revision>/head.previous.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/head-backups/<head_revision>/head.displaced.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/journals/<journal_ordinal>.journal.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/attempts/<attempt_ordinal>/attempt.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/attempts/<attempt_ordinal>/candidate.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/attempts/<attempt_ordinal>/native-images.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/attempts/<attempt_ordinal>/evidence.staged.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/transactions/<transaction_id>/attempts/<attempt_ordinal>/completion.staged.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/<transaction_id>
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/<transaction_id>/<quarantine_id>/quarantine.intent.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/<transaction_id>/<quarantine_id>/move-progress/<artifact_ordinal>.moved.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/<transaction_id>/<quarantine_id>/quarantine.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/<transaction_id>/<quarantine_id>/artifacts/<artifact_ordinal>/payload.v2.bin
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/<transaction_id>/<quarantine_id>/profile/<writable_kind>/tree
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/base-input-snapshots/<base_snapshot_id>/input-snapshot.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/base-input-snapshots/<base_snapshot_id>/tree
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/candidate-sets/<candidate_set_id>/candidate-set.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/candidate-sets/<candidate_set_id>/tree
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-captures/<base_snapshot_id>/<vector_capture_run_id>/vector-bundle.candidate.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-captures/<base_snapshot_id>/<vector_capture_run_id>/vector-bundle.capture-receipt.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/input-snapshots/<snapshot_id>/input-snapshot.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/input-snapshots/<snapshot_id>/tree
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/generator.accepted.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/evaluator.accepted.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/crosscheck.accepted.v2.json
```

`<transaction_id>`, `<quarantine_id>`, `<lock_quarantine_id>`, and
`<vector_capture_run_id>` are the exact
lowercase IDs defined in sections 9/14; `<role-lower>` is exactly `generator`, `evaluator`, or
`crosscheck`; `<attempt_ordinal>` is the canonical unsigned decimal spelling
`0` through `7` with no leading zero; and `<journal_ordinal>` is exactly 16
lowercase decimal digits, zero-padded on the left. `<head_revision>` uses the
same encoding and equals the journal ordinal installed by that head.
`<artifact_ordinal>` is the
same 16-digit spelling of the artifact's UTF-8 source-path order, and
`<writable_kind>` is exactly `profile-root`, `localappdata`, `temp`, or `tmp`.
`<base_snapshot_id>`, `<candidate_set_id>`, and `<snapshot_id>` are the lowercase
`pfg3bs-`, `pfg3cs-`, and `pfg3is-` identities defined by the generic snapshot
interface in sections 5/14; they identify private construction inputs, never
accepted vectors or reviews.
`<vector_capture_run_id>` is the lowercase `pfg3vcr-` identity in sections
5/14. The coordination-lock move-progress ordinal is the literal all-zero
16-digit value because that quarantine has exactly one planned move.
These are substitutions, not
implementer-selected paths. The three `*.accepted.v2.json` files are completion
markers, not copies of the evidence. A consumer obtains v2 evidence only by
validating a completion marker and then opening its exact transaction-scoped
evidence identity. Discovery, globbing, newest-file selection, and an unmarked
transaction file are forbidden.

The v2 dependency order is the following total DAG: this amendment; amendment
receipt; deterministic rendering of all 25 schemas; transport bootstrap,
deterministic runtime-builder, and the three unreviewed successor producer
source bytes; five independent pre-manifest source-semantics reviews; the
closed runtime build-plan/lock and its independent review; deterministic
private runtime-bundle construction from only the reviewed build inputs;
post-bundle import inventory and runtime manifest; independent closure review; scenario manifest and the immutable
52-method harness; complete RED run against the pinned v1 launcher; no-spawn v2
launcher; complete GREEN run; implementation review containing all five
pre-manifest source identities/reviews, the launcher identity, and closure
identities; the separately authored native-image
collector source; a separately amended/reviewed materializer that first seals an
immutable base-input synthetic repository from the closed read-only predecessor
set; a distinct fourth vector-bundle capture that runs only against that base;
derived immutable vector-snapshot materialization from the base plus private
aggregate candidate set; a separate native-host contract/build/run/receipt that
pins the derived snapshot, collector source, and built image; the three
completed v2 role chains; an independent pre-aggregate lineage mapping
that projects those chains onto the accepted clarification's three exact v1
evidence requirements while binding the GREEN successor lineage; G2 per-schema
and aggregate review using that mapping; and only then a separately reviewed
activation/adoption decision.
Import origins are resolved only against the already constructed bundle. The
build-plan/lock names the earlier builder source/review and offline locked
inputs; its review names that plan. The manifest names the earlier build pair
and source reviews; its closure review names the manifest. No source review
names the build plan, runtime manifest, or closure review, and no artifact names
or hashes itself or a later receipt.

## 3. Common closed primitives, limits, and bitsets

`CJ`, `CF`, UTF-16/JCS object-key order, `file_identity`, portable relative
path, and SHA-256 retain the accepted clarification meanings. `CJ(x)` contains
no LF; `CF(x) = CJ(x) || 0x0a`. Every JSON parser in this boundary rejects a
BOM, CR, invalid UTF-8, duplicate object key, float token, `NaN`, infinity,
integer outside `[-9007199254740991,9007199254740991]`, depth over 256, and
noncanonical bytes. Every JSON schema is Draft 2020-12, has the exact required
vocabularies, uses `additionalProperties:false` for every object, lists every
property in `required`, and has no permissive fallback branch.

The limits are exact:

| Object | Limit |
|---|---:|
| producer stdout and complete v2 evidence `CF` | 33,554,432 bytes |
| producer stderr | 1,048,576 bytes; accepted value is zero bytes |
| bootstrap status frame, including header and `CF(status)` | 1,048,576 bytes |
| any control JSON, including manifest, marker, review, journal, and receipt | 16,777,216 bytes |
| one producer source | 16,777,216 bytes |
| one runtime member | 67,108,864 bytes |
| whole private runtime bundle | 268,435,456 bytes |
| runtime members / allowed modules / import events | 20,000 / 20,000 / 100,000 |
| transaction attempts per exact transaction ID | 8 |

The measured approximately 17.5 MiB parity object is evidence, not a control
document; the 32 MiB limit applies to it. The accepted 16 MiB control ceiling is
not widened.

The accepted parent object remains separately named
`PARENT_V1_AUTHORITY_CEILING` and is byte-for-byte:

```json
{"active_head_update":false,"clean_certification":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"package":false,"production_publication":false,"provider_launch":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false}
```

It has exactly 17 fields and is used only where the accepted v1 parity/evidence
contract requires it. The exact successor object is separately named
`V2_NONAUTHORITY_CAPABILITY_BITSET` and is:

```json
{"active_head_update":false,"admission":false,"adoption":false,"audit":false,"capture":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"evidence":false,"finding":false,"install":false,"native_spawn":false,"package":false,"production":false,"provider":false,"publication":false,"push":false,"refutation":false,"release":false,"replay":false,"runtime":false,"schema":false,"severity":false,"suppression":false,"terminal_negative":false,"vector":false}
```

It has exactly 28 fields. Every v2 manifest, scenario, red/green execution
record, source/closure/amendment/implementation review, journal, attempt, head,
lock, quarantine, candidate, evidence, staged marker, and completion marker
contains this exact 28-field object under `authority_ceiling`; no v2 receipt
uses the 17-field parent object. The literal projection back to v1 is:

```text
active_head_update <- active_head_update
clean_certification <- clean_certification
confidence <- confidence
consumer <- consumer
cutover <- cutover
finding <- finding
package <- package
production_publication <- production AND publication
provider_launch <- provider AND native_spawn
refutation <- refutation
release <- release
replay <- replay
runner <- runtime AND native_spawn
runtime <- runtime
severity <- severity
suppression <- suppression
terminal_negative <- terminal_negative
```

The remaining v2-only fields `admission`, `adoption`, `audit`, `capture`,
`commit`, `evidence`, `install`, `push`, `schema`, and `vector` have no v1
counterpart and remain false. This mapping never widens parent authority.

The exact independence bitset for this amendment's independent review is:

```json
{"amendment_author_separate":true,"clarification_reviewer_separate":true,"crosscheck_author_separate":true,"evaluator_author_separate":true,"fixture_author_separate":true,"generator_author_separate":true,"launcher_v1_author_separate":true,"launcher_v2_implementer_separate":true,"native_host_validator_separate":true,"no_self_generated_evidence":true,"production_implementer_separate":true,"runtime_bundle_builder_separate":true,"runtime_closure_reviewer_separate":true,"schema_builder_separate":true,"workspace_clean":true}
```

A regular-file `handle_identity` is the closed object
`{root_id,path,kind:"REGULAR_FILE",volume_id,file_id,nlink,size_bytes,sha256}`.
`root_id` and `path` are portable strings; `volume_id` and `file_id` are
lowercase host-native identity strings fixed by a host profile. Regular files
require `nlink:1`, exact size, and SHA-256 except only the closed system-image
exception in section 4.1.

A directory never uses that content identity. Its stable
`directory_locator` is exactly `{root_id,path,volume_id,file_id,owner,
access_policy}` and identifies the retained open directory plus its expected
owner and mode/DACL digest without claiming that mutable descendants are
content. An immutable tree may additionally use
`immutable_directory_identity`, exactly `{locator,descendant_count,
descendant_manifest_sha256}`; the digest preimage is the concatenation of
`CJ(handle_identity)||LF` for the complete UTF-8-path-sorted descendant regular-
file list. Only the read-only runtime bundle uses that optional manifest.
Repository cwd, transaction directories, AppContainer profile/writable roots,
and quarantine directories use only `directory_locator`, so later authorized
writes do not stale or self-reference their identity. An unavailable or
unreplayable file or directory locator rejects the object. A `module_origin` is the closed object
`{module_name,origin_kind,origin_path,file_identity,distribution}` where
`origin_kind` is `BUILTIN`, `FROZEN`, `BUNDLE_SOURCE`, or `BUNDLE_EXTENSION`;
builtin/frozen rows use `origin_path:null`, `file_identity:null`, and
`distribution:null`; bundle rows use an exact bundle-relative path and member
identity; third-party rows name one exact distribution, while standard-library
rows use `distribution:null`.

## 4. Closed v2 artifacts and identities

The following self-contained schema files, and no others for this boundary, are
created only after this amendment passes:

```text
rules/schemas/program_facts_g3_00_parity_launcher_runtime_closure_amendment_review.v1.schema.json
rules/schemas/program_facts_parity_runtime_build_plan_lock.v1.schema.json
rules/schemas/program_facts_parity_runtime_build_plan_lock_review.v1.schema.json
rules/schemas/program_facts_parity_runtime_closure.v2.schema.json
rules/schemas/program_facts_parity_runtime_closure_review.v1.schema.json
rules/schemas/program_facts_parity_source_review.v1.schema.json
rules/schemas/program_facts_parity_candidate.v2.schema.json
rules/schemas/program_facts_parity_evidence.v2.schema.json
rules/schemas/program_facts_parity_completion.v2.schema.json
rules/schemas/program_facts_parity_scenario_manifest.v1.schema.json
rules/schemas/program_facts_parity_scenario_execution_evidence.v1.schema.json
rules/schemas/program_facts_parity_launcher_implementation_review.v1.schema.json
rules/schemas/program_facts_parity_transaction_journal.v2.schema.json
rules/schemas/program_facts_parity_staged_marker.v2.schema.json
rules/schemas/program_facts_parity_transaction_lock.v2.schema.json
rules/schemas/program_facts_parity_coordination_lock_quarantine.v1.schema.json
rules/schemas/program_facts_parity_quarantine.v2.schema.json
rules/schemas/program_facts_parity_quarantine_locator.v1.schema.json
rules/schemas/program_facts_parity_transaction_head.v2.schema.json
rules/schemas/program_facts_parity_attempt.v2.schema.json
rules/schemas/program_facts_parity_native_image_receipt.v2.schema.json
rules/schemas/program_facts_parity_vector_bundle_candidate.v1.schema.json
rules/schemas/program_facts_parity_vector_bundle_capture_receipt.v1.schema.json
rules/schemas/program_facts_parity_vector_capture_transaction.v2.schema.json
rules/schemas/program_facts_parity_pre_aggregate_lineage.v1.schema.json
```

Their complete Draft-2020-12 construction is the literal template and root table
in section 14. Every rendered schema copies the complete `$defs`, substitutes
only its table `$id` and root `$ref`, is serialized as `CF`, and is independently
schema-checked. The schema author may not add optional members, widen a
type/enum/limit, infer a default, or choose another ordering.

### 4.0 Runtime build-plan/lock and reviewed builder

The private runtime is constructed only from a passing
`plamen.program_facts_parity_runtime_build_plan_lock.v1` artifact and its
independent review. The plan is non-authoritative and binds the exact reviewed
`build_private_runtime_v1.py` source, its `RUNTIME_BUILDER` source review, the
reviewed transport-bootstrap source/review as an installed bundle input, the
three role-ordered producer sources and their passing source reviews solely as
forbidden-output identities,
builder interpreter/toolchain host projections, one offline
`python-3.12.10-embed-amd64.zip` input, and exactly these six wheels in this
order:

```text
attrs-26.1.0-py3-none-any.whl | py3-none-any
jsonschema-4.26.0-py3-none-any.whl | py3-none-any
jsonschema_specifications-2025.9.1-py3-none-any.whl | py3-none-any
referencing-0.37.0-py3-none-any.whl | py3-none-any
rpds_py-0.30.0-cp312-cp312-win_amd64.whl | cp312-cp312-win_amd64
typing_extensions-4.15.0-py3-none-any.whl | py3-none-any
```

Every archive row carries its exact portable input path, filename, tag, byte
length, and SHA-256; no name-only or index resolution is permitted. The
toolchain rows carry canonical absolute paths plus retained path-bearing handle
identities for the builder interpreter and every extraction/verification tool.
The plan's build rules are the literal closed object requiring offline input
handles only, zero network attempts, lexicographic UTF-8 archive/member order,
path normalization before extraction, rejection of absolute/parent/drive/
device/reparse/symlink/hardlink/duplicate/case-fold/Unicode-normalization
collisions, regular files and directories only, fixed directory/file modes,
timestamps normalized to zero, LF-only generated policy files, no bytecode,
no ambient environment or package index, and three-read verification of the
completed immutable tree. The builder writes only a fresh private staging root,
then seals and retained-handle validates the exact `PRIVATE_RUNTIME` bundle;
it never edits an existing bundle.

The plan records the complete expected logical bundle-member roster, but no
output path, output inode, build log, or post-build observation. Its logical
`build_id` covers that closed input/expected-output lock without host paths or
physical identities and therefore does not claim
cross-host physical equality; its full artifact and review are host-bound by
the toolchain rows. The independent pre-build reviewer reopens all seven
archives, builder source/review, bootstrap source/review, and toolchain handles, derives the expected
member roster without constructing the bundle, recomputes both
archive-to-plan differences and every producer path/alias/content intersection,
and requires zero extras or intersections. The later runtime
manifest and closure review alone bind the actual output root and members to
those expectations. This ordering contains no plan/output/review
cycle. No archive bytes, plan, review, source, or source review are instantiated
by this Part-0 amendment.

`expected_output_members` is derived only from the seven locked archives, the
earlier bootstrap source bytes, and policy/path-configuration bytes fixed by
`rules`. It contains no builder source/review, producer source/review, build
plan/review, runtime manifest/review, scenario, launcher, evidence, or later
artifact. A member size/hash therefore cannot depend on the actual bundle root,
the plan/review files that name the roster, or any downstream identity.
Every build-review check-evidence identity is drawn only from the amendment/
receipt, rendered schemas, the plan, the earlier builder/bootstrap/producer
sources and reviews, the seven archives, and the locked toolchain. An actual output tree/member,
build log, runtime manifest/review, scenario, launcher, or later artifact in
that review is a closed-schema semantic rejection.

### 4.1 Runtime-closure manifest

`plamen.program_facts_parity_runtime_closure.v2` has exactly:

```text
schema_version, closure_id, disposition, accepted_scope, host_profile, bundle_root, interpreter,
runtime_build, path_configuration, bootstrap, bundle_members, producer_source_exclusions, allowed_distributions,
allowed_modules, import_inventory, input_snapshot_policy, system_loader_boundary,
role_native_image_projections, limits,
authority_ceiling, closure_body_sha256
```

The fields are closed as follows:

- `host_profile` is exactly `{host_profile_id,os_family,os_version,os_build,
  architecture,filesystem_profile}`. There is no `ANY`, prefix, or range
  value. `host_profile_id = "pfg3hp-" || SHA-256(CJ({domain:
  "PROGRAM_FACTS_G3_PARITY_HOST_PROFILE_V1",host_profile:(host_profile without
  host_profile_id)}))[0:32]`.
- `bundle_root` is exactly `{root_id,absolute_path,physical_identity,owner,
  access_policy}`. `root_id` is `PRIVATE_RUNTIME`; `absolute_path` is canonical,
  host-native, and recorded rather than inferred; `physical_identity` is the
  immutable `immutable_directory_identity`; its locator owner/access policy
  equals the two outer fields. `owner` is an exact SID on Windows or decimal UID
  on POSIX; and `access_policy` is the exact DACL/mode digest in the host profile.
  It is private, local, read-only during execution, and not the ambient runtime.
- `interpreter` is exactly `{implementation:"cpython",version:"3.12.10",
  cache_tag:"cpython-312",abi_tag,platform_tag,executable_absolute_path,
  executable,python_library_members}`. The executable path is absolute,
  canonical, inside `bundle_root`, and byte-identical to the complete executable
  `handle_identity`. `python_library_members` is a nonempty duplicate-free
  UTF-8-path-sorted list of exact bundle-member paths.
- `runtime_build` is exactly `{plan,review,build_id}` and joins the passing
  section-4.0 build-plan/lock and independent review. The plan's expected
  member roster equals this manifest's actual `bundle_members` in both
  directions. The actual `bundle_root` is first introduced here and therefore cannot
  feed back into the pre-build plan or review.
  The plan's three forbidden producer identities equal the manifest's
  `producer_source_exclusions[*].source` rows and its three review identities
  equal the import inventory's role source reviews. Its bootstrap source and
  review equal the manifest's `bootstrap` pair.
- `path_configuration` is exactly `{kind,member,lines,resolved_sys_path,
  import_site}`. On Windows
  `kind` is `WINDOWS_PYTHON312_DOT_PTH_V1`, `member` is exactly
  `python312._pth`, `lines` is exactly `[".","Lib","DLLs","vendor"]`,
  `resolved_sys_path` is exactly the four canonical absolute paths obtained by
  resolving those relative lines under the bound bundle root in the same order,
  and `import_site` is false. The file contains those four LF-terminated lines and
  no `import site`, blank, absolute, parent, environment, registry, or user path.
  Another OS requires a separately reviewed equally closed profile; absence of
  one means no spawn.
- `bootstrap` is exactly `{kind:"FIXED_PARENT_BOOTSTRAP_V1",source,
  source_review,template_utf8_sha256,instantiated_argv_sha256,capabilities}`.
  `source` and `source_review` are the exact section-2 bootstrap and passing
  source-review file identities. `capabilities` is exactly
  `["VERIFY_FLAGS","VERIFY_PATH","INSTALL_IMPORT_DENYLIST",
  "READ_BOUND_SOURCE","EXPOSE_OUTER_CONTEXT","REPORT_PRE_GATE_STATUS",
  "EXECUTE_BOUND_SOURCE","REPORT_IMPORTS"]`. It contains
  no parity, schema traversal, witness, proof, vector, or producer-specific
  algorithm. Its exact six-string argv is
  `[interpreter.executable_absolute_path,"-I","-S","-B","-c",
  <the UTF-8-decoded reviewed bootstrap source bytes>]`; angle brackets are
  metanotation, not bytes. The source has no template substitutions: it always
  reads the binary control stream from standard input. The exact digest is
  `instantiated_argv_sha256 = SHA-256(CJ({domain:
  "PROGRAM_FACTS_G3_PARITY_BOOTSTRAP_ARGV_V1",argv:<that six-string array>}))`.
  `CONTROL_READ` is one complete ordered byte protocol and no other discovery
  channel: eight ASCII bytes `PFG3CTL2`, one unsigned 64-bit big-endian
  `control_length`, exactly `control_length` bytes equal to strict
  `CF(bootstrap_control)`, one unsigned 64-bit big-endian `source_length`,
  exactly `source_length` raw selected-producer source bytes, and EOF. The
  control length is `1..16777216`, includes its one final LF, and its payload
  must parse and reserialize byte-identically as `CF`; source length is
  `1..16777216` and equals the control source length. Short reads, overflow,
  another magic/version, BOM/CR/noncanonical control, missing EOF, or any
  trailing byte rejects before status or producer execution.

  `bootstrap_control` contains the complete parent-authenticated outer context:
  transaction ID, attempt ordinal, role/principal, selected portable source and
  its absolute/path-bearing identity, launcher, runtime manifest/review/closure,
  input snapshot and byte-identical candidate-set projection, host receipt,
  requested output, candidate, transaction-evidence and completion paths, the
  START_GATE and STATUS_WRITE child handle values, and the exact 28-field
  authority ceiling. The bootstrap verifies every join and raw-source
  size/SHA-256 before naming the bytes `bound_source_bytes`. It exposes an
  recursively immutable `__plamen_outer_context__` mapping containing those already bound
  envelope values so the producer can serialize its candidate envelope; that
  mapping has no `parity`, schema/proof/vector payload, algorithm callback, or
  mutable setter and cannot supply or change producer parity logic.

  Before reading the gate, the bootstrap writes to the dedicated STATUS_WRITE
  pipe exactly eight ASCII bytes `PFG3STS2`, a u64 big-endian status length,
  exactly that many bytes equal to `CF(bootstrap_status)`, then closes its write
  handle. Header plus payload is at most 1,048,576 bytes. The status binds the
  outer-context digest, source/frame digest, parent-resolved source binding,
  lexical child source-path/depth checks,
  all three producer-source denial probes, and `ready_for_gate:true`. The parent requires strict
  canonical parsing, exact EOF, and every binding/check before it releases the
  gate. START_GATE then consists of exactly byte `0x01` followed by EOF; a
  missing, early, different, repeated, or trailing byte rejects. Only after
  that sequence does the bootstrap call
  `compile(bound_source_bytes,source_absolute_path,"exec",
  flags=0,dont_inherit=True,optimize=0)`, recursively walks the resulting code
  object's code-valued constants and requires every `co_filename` to equal that
  exact absolute path, sets globals `__name__` to `"__main__"` and `__file__`
  to the same path, sets `sys.argv` exactly to `[source_absolute_path]`, performs
  the exact lexical path/depth/root check without resolving, statting, or
  reopening that path, and only then executes the code object. No relative,
  live-checkout, cwd-derived,
  aliased, or producer-supplied filename participates. After gate, stdout is
  exactly one `CF(candidate)` at most 33,554,432 bytes with EOF, while stderr
  is exactly zero bytes with EOF; status text never appears on either stream.
- `bundle_members` is the complete UTF-8-path-sorted list of closed rows
  `{path,size_bytes,sha256,kind,executable}`. Paths are unique and cover every
  bundle byte, including the executable, Python DLL/shared libraries, stdlib,
  extension modules, private `vendor`, distribution metadata/RECORD, bootstrap
  policy, and path-configuration file. Directories, `.pyc`, `.pyo`,
  `__pycache__`, `.pth` other than the exact non-executable `python312._pth`
  configuration, and `sitecustomize.py`/`usercustomize.py` are forbidden.
- `producer_source_exclusions` is the exact role-ordered three-row list
  `{role,source,canonical_path_intersection_count:0,alias_intersection_count:0,
  content_identity_intersection_count:0,complete_bidirectional:true}` for the
  generator, evaluator, and cross-check source file identities. None of those
  canonical paths, no case/Unicode/short-name/link/reparse alias, and no bundle
  member with the same `(size_bytes,sha256)` may exist in `bundle_members`.
  Complete bundle-to-producer and producer-to-bundle comparisons both have
  empty path, alias, and content-identity intersections. The transport-only
  bootstrap may be a bundle member; all three producer sources arrive only in
  the authenticated CONTROL_READ source frame.
- `allowed_distributions` is an exact name-sorted list of closed rows
  `{name,version,metadata_members,record_sha256}`. Its distribution roster is
  exactly `attrs==26.1.0`, `jsonschema==4.26.0`,
  `jsonschema-specifications==2025.9.1`, `referencing==0.37.0`,
  `rpds-py==0.30.0`, and `typing_extensions==4.15.0`. Extras and any seventh
  distribution are forbidden. Every installed file is in both its RECORD
  projection and `bundle_members`; both differences are empty.
- `allowed_modules` is the complete module-name-sorted list of distinct
  `module_origin` rows. Every source, extension, builtin, and frozen module
  reachable at startup or through a static import, literal dynamic import,
  package entry point, schema format selection, or lazy execution path appears
  exactly once. Namespace packages and unbounded dynamic names are forbidden.
- `import_inventory.role_import_closures` contains exactly three role-sorted rows
  `{role,entry_source,source_review,allowed_module_names,allowed_distribution_names,
  producer_module_names}`. Generator and evaluator may use the exact six
  distributions above. Cross-check uses none and only its accepted stdlib
  closure. `producer_module_names` is the singleton module for that row. The
  three producer singleton sets are disjoint; no role's allowed module set
  contains either peer producer, the v1/v2 launcher, a production Plamen
  module, target code, or a second producer implementation.
- `import_inventory` is exactly `{inventory_id,construction_method,
  source_reviews,role_import_closures,module_origins,
  producer_exclusions,producer_exclusions_sha256,inventory_body_sha256}`.
  `construction_method` is exactly
  `STATIC_LITERAL_DYNAMIC_AND_BOUNDED_LAZY_FROM_EXISTING_BUNDLE_V1`;
  `source_reviews` is the exact four-item bootstrap/generator/evaluator/
  cross-check review identity list; `module_origins` is byte-identical as a
  parsed ordered array to `allowed_modules`; and the producer-exclusion digest
  is over `CJ({module_name,reason})||LF` for the complete UTF-8-module-name-
  sorted rejected-name rows. Let `body` omit exactly `inventory_id` and
  `inventory_body_sha256`:

  ```text
  inventory_id = "pfg3ii-" || SHA-256(CJ({
    domain:"PROGRAM_FACTS_G3_PARITY_IMPORT_INVENTORY_V1",
    inventory:body
  }))[0:32]
  inventory_body_sha256 = SHA-256(CJ(import_inventory without only
    inventory_body_sha256))
  ```

  It is a nested manifest value, not a separate receipt or authority-bearing
  file. The later closure review independently rebuilds it from the already
  existing bundle and requires both set differences empty.
- `input_snapshot_policy` is exactly `{kind:
  "IMMUTABLE_SYNTHETIC_REPOSITORY_SNAPSHOT_V1",canonical_layout_required:true,
  live_repository_execution:false,private_candidate_set_only:true,
  materialization_status:"REQUIRES_SEPARATE_ACCEPTED_MATERIALIZATION_AMENDMENT"}`.
  It defines an input interface, not a current snapshot or authority. Producer
  execution is unavailable until a later independent amendment supplies a
  valid `input_snapshot_binding` from section 14. That amendment first seals a
  `base_input_snapshot_binding` from the enumerated predecessor set. Only the
  distinct vector-bundle construction may read that base; it does not execute
  evaluator or cross-check and never uses live repository bytes as a capture
  cwd. The derived snapshot is created only after its candidate set is closed.
- `system_loader_boundary` is exactly `{trust_model,host_identity,
  allowed_system_images}`. `host_identity` is exactly `{os_family,os_version,
  os_build,architecture,kernel_identity,loader_identity}`; each kernel/loader
  identity is the exact `{kind,absolute_path,physical_identity,owner_sid,
  dacl_sha256,signature,os_build}` host projection, never a portable
  `file_identity`. `trust_model` is
  `TRUSTED_KERNEL_AND_OS_LOADER_NOT_PYTHON_ATTESTED`. A Windows image row is
  exactly `{canonical_path,physical_identity,content_identity,owner_sid,
  dacl_sha256,signature,os_build,winsxs_aliases}`; `signature` is exactly
  `{status:"VALID_MICROSOFT",signer_thumbprint,chain_sha256}` and
  `winsxs_aliases` is the complete UTF-16-sorted list of
  `{path,volume_id,file_id}` aliases for the same file ID. Only these exact
  System32/WinSxS rows may have `nlink > 1`; every alias, owner/DACL, signature,
  hash, file ID, and build must match. If complete alias enumeration cannot be
  proved, Windows is unavailable. Every other runtime/repo/input/output file
  requires `nlink == 1`. This boundary is distinct from Python import closure.
- `role_native_image_projections` is the exact role-sorted three-row array
  `{role,expected_images,projection_sha256}`. Each `expected_images` array is the
  complete load-order projection for that role from its initial executable
  event through process-tree zero; ordinals are contiguous from zero. Its rows
  are exactly `{load_ordinal,event,canonical_path,debug_hfile_identity,
  content_identity,origin}`. The digest preimage is the concatenation, in
  `load_ordinal` order, of `CJ(row)||LF`, and `projection_sha256` is SHA-256 of
  those bytes. Every projected `BUNDLE` row joins to one executable,
  shared-library, or extension-module `bundle_member`; every projected `SYSTEM`
  row joins to one `allowed_system_images` row. Thus each role projection is a
  subset of the allowed native-image universe, not an assertion that every
  allowed image loads. It must include the interpreter executable, every Python
  shared library, and every extension module reachable by that role. The three
  arrays are host/profile inputs fixed before spawn; a missing required image or
  any observed row not in the exact role projection rejects the run.
- `limits` is exactly `{stdout_max_bytes:33554432,stderr_max_bytes:1048576,
  control_max_bytes:16777216,source_max_bytes:16777216,
  status_frame_max_bytes:1048576,
  runtime_member_max_bytes:67108864,runtime_bundle_max_bytes:268435456,
runtime_member_max_count:20000,module_max_count:20000,
  import_event_max_count:100000,attempt_max_count:8,
  timeout_seconds:3600}` and `authority_ceiling` is the exact 28-field object.
  `disposition` is exactly `DECLARED_EXACT_PRIVATE_RUNTIME_CLOSURE_ONLY` and
  `accepted_scope` is exactly
  `["RUNTIME_CLOSURE_INPUT_NO_SPAWN_AUTHORITY"]`; neither is execution or
  adoption authority.

Let `identity_body` omit exactly `closure_id` and `closure_body_sha256`:

```text
closure_id = "pfg3rc-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_RUNTIME_CLOSURE_V2",
  closure:identity_body
}))[0:32]
closure_body_sha256 = SHA-256(CJ(full manifest without only closure_body_sha256))
manifest file = CF(full manifest)
```

The manifest cannot hash its later review. A separately authored closure
review pins the complete manifest file identity and independently re-enumerates
the bundle tree, distributions, modules, imports, and both set differences.

### 4.2 Producer candidate statement

The producer writes stdout only. Its parsed object
`plamen.program_facts_gate3_schema_contract_parity_candidate.v2` has exactly:

```text
schema_version, candidate_id, transaction_id, attempt_ordinal, role, principal,
source, launcher, runtime_closure, input_snapshot, host_receipt, requested_output, candidate_path,
parity, runtime_observation, authority_ceiling, candidate_body_sha256
```

`role`, `principal`, and source binding are the accepted clarification's exact
three distinct roles/principals with the exact v2 source paths from section 2.
`launcher` is the exact v2 launcher source identity and principal projection;
`runtime_closure` is exactly `{manifest,review,closure_id}`; and `host_receipt`
is exactly `{identity,schema_version,disposition,host_profile_id,role,
input_snapshot,snapshot_entry_validation,readable_member_view}`.
`input_snapshot` is the exact section-5 closed projection and is parsed-value
identical to the host receipt's projection. The parent separately validates the
complete manifest file bound by its `identity`. The control stream supplies every prelaunch binding
after parent verification.
`requested_output` is the exact mapped v2 completion-marker path and
`candidate_path` is the exact deterministic attempt path. `transaction_id` and
`attempt_ordinal` equal the parent attempt. `parity` is the exact accepted v1 parsed value;
`CJ(parity)` and `parity_body_sha256` must agree across all three roles.
`runtime_observation` has exactly `{sys_executable,sys_flags,sys_path,
startup_hook_observations,source_execution_binding,loaded_modules,import_events,
bytecode_write_count}`:

- `sys_executable` is the exact absolute manifest interpreter path;
- `sys_flags` is exactly `{isolated:1,no_site:1,no_user_site:1,
  dont_write_bytecode:1,safe_path:true,ignore_environment:1}`;
- `sys_path` is exactly the manifest path-configuration projection;
- `startup_hook_observations` is exactly
  `{site_imported:false,pth_executed:false,sitecustomize_imported:false,
  usercustomize_imported:false,pythonstartup_executed:false,
  registry_path_used:false,environment_path_used:false}`;
- `source_execution_binding` records the exact snapshot source handle,
  canonical absolute compile filename, complete recursive `co_filename` list,
  `__name__`, `__file__`, one-item `sys.argv`, and native cwd; every dynamic
  path value equals the parent control/execution binding as specified below;
- `loaded_modules` is the unique module-name-sorted exact origin list;
- `import_events` preserves audited import order and every row has exactly
  `{ordinal,module_name,resolved_origin}`; its set and order must be reproducible;
- every loaded/imported name is in the role closure, every observed origin
  equals the manifest row, and all manifest role-required imports are observed
  or deterministically proven lazy by the fixture matrix; and
- `bytecode_write_count` is zero.

The candidate authority ceiling is exactly the 28-field
`V2_NONAUTHORITY_CAPABILITY_BITSET`. Its IDs are:

```text
candidate_id = "pfg3pc-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_SCHEMA_PARITY_CANDIDATE_V2",
  candidate:(full candidate without candidate_id and candidate_body_sha256)
}))[0:32]
candidate_body_sha256 = SHA-256(CJ(full candidate without only candidate_body_sha256))
stdout = CF(full candidate)
```

### 4.3 Launcher evidence and completion marker

The launcher persists accepted candidate stdout unchanged at `candidate_path`,
using the section-7 stable-write epoch, before constructing evidence. Its
complete file identity is the evidence's `candidate.identity`; a candidate that
exists only in memory or stdout cannot be published.

`plamen.program_facts_gate3_schema_contract_parity_evidence.v2` has exactly:

```text
schema_version, evidence_id, transaction_id, attempt_ordinal, role, producer,
launcher, execution, runtime_closure, input_snapshot, isolation, native_image_receipt, candidate, parity,
transaction_evidence_path, completion_path, authority_ceiling,
evidence_body_sha256
```

`producer` is exactly `{principal,source}`. `launcher` is exactly
`{principal,source}`, uses the accepted launcher principal, and binds the v2
source identity. `execution` is exactly `{interpreter,argv,producer_arguments,
control,bootstrap_status,cwd,input_snapshot,environment,inherited_handles,handle_accounting,shell,
stdout_max_bytes,stderr_max_bytes,status_frame_max_bytes,timeout_seconds}`. `interpreter` is exactly `{absolute_path,physical_identity,
content_identity,implementation,version,abi_tag,platform_tag}` and equals the
manifest's exact execution projection: `absolute_path` equals
`manifest.interpreter.executable_absolute_path`, `physical_identity` equals
`manifest.interpreter.executable`, `content_identity` is that handle's exact
size/hash projection, and implementation/version/ABI/platform tags are equal.
`cwd` is exactly `{logical:"IMMUTABLE_SYNTHETIC_REPOSITORY_ROOT",
absolute_path,physical_identity}`; its absolute path and directory locator equal
the input snapshot's root. `execution.input_snapshot` and the outer
`input_snapshot` are parsed-value identical. `control` is parsed-value
identical to the strict CONTROL_READ control payload; `bootstrap_status` is the
strict pre-gate STATUS_WRITE payload validated by the parent. Together they
join transaction/attempt/role/principal, source, launcher, runtime, snapshot/
candidate set/host receipt, output/evidence paths, authority, status and gate
handle values to candidate, cwd, input snapshot, and inherited handles. Each
inherited-handle row is exactly `{ordinal,purpose,parent_handle_id,
child_handle_value,access,direction,physical_identity}` in ordinal order;
`purpose` is `CONTROL_READ`, `STDOUT_WRITE`, `STDERR_WRITE`,
`START_GATE_READ`, or `STATUS_WRITE`. The control and gate are child-read-only;
the other three streams are child-write-only. Only a handle backed by a file has a non-null
`physical_identity`. `handle_accounting` is exactly
`{inherited_allowlist_count:5,inherited_allowlist_complete:true,
os_created_handles_classified_separately:true}`. The five-row list covers only
handles inherited from the parent; kernel/loader/runtime-created child handles
are separately observed and classified and do not make the inherited list
larger. Its values are: the manifest interpreter; argv beginning
with that exact absolute path and then exactly `-I`, `-S`, `-B`, `-c`, and the
fixed instantiated bootstrap; `producer_arguments:[]`; exact control/status;
immutable snapshot cwd; empty environment; an exact host-profile five-handle allowlist; `shell:false`; section-3
stream limits; and 3,600 seconds. No PATH, Python variable, locale override,
secret, startup variable, or shared producer injection exists.

`runtime_closure` is exactly `{manifest,review,closure_id,
parent_pre_spawn_verified:true,child_observation_matched:true}`. `manifest` and
`review` are exact file identities. The parent validates all closure and source
bytes before spawn and retains their handles through process-tree zero. The
child observation confirms but never establishes that trust.

`isolation` is a closed host-receipt projection with exactly `{os_family,
backend_id,host_receipt,token_or_namespace_identity,snapshot_entry_validation,
readable_member_view,network_denied,filesystem_denied,child_creation_denied,
process_tree_zero}`;
every boolean is true. Its role-specific readable view is parsed-value
identical to the host receipt's view, its entry validation is parsed-value
identical to the receipt's complete native enumeration, and it denies the
selected source plus both peer producer sources at the child OS/filesystem
boundary. This amendment supplies no
passing `host_receipt`.

`native_image_receipt` is the exact per-run file identity and content
projection `{identity,receipt_id,ordered_image_set_sha256}` created by the
trusted parent collection in section 8. It is deliberately absent from the
prelaunch transaction-ID preimage. `candidate` is exactly
`{identity,candidate_id,candidate_body_sha256}`; `parity` is byte-identical as a parsed value
to `candidate.parity`; the launcher never recomputes producer semantics.
`transaction_evidence_path` and `completion_path` are the exact section-2 paths.
The evidence authority ceiling remains exactly the 28-field
`V2_NONAUTHORITY_CAPABILITY_BITSET`: the later valid marker, not a
boolean inside evidence, establishes capture completion.

```text
evidence_id = "pfg3pe2-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_GATE3_SCHEMA_CONTRACT_PARITY_EVIDENCE_V2",
  evidence:(full evidence without evidence_id and evidence_body_sha256)
}))[0:32]
evidence_body_sha256 = SHA-256(CJ(full evidence without only evidence_body_sha256))
evidence file = CF(full evidence)
```

The completion marker
`plamen.program_facts_gate3_schema_contract_parity_completion.v2` has exactly:

```text
schema_version, completion_id, transaction_id, attempt_ordinal, state, role,
principal, producer, launcher, runtime_closure, host_receipt,
input_snapshot, native_image_receipt, candidate, evidence, completion_path, commit_primitive,
commit_linearization, completion_state, disposition, accepted_scope,
authority_ceiling,
completion_body_sha256
```

`state` is `COMMITTED`; `producer` and `launcher` are their exact closed
principal/source objects; `runtime_closure`, `host_receipt`,
`input_snapshot`, `native_image_receipt`, and `candidate` are byte-identical to evidence;
`evidence` is exactly `{identity,evidence_id,evidence_body_sha256}`;
`completion_path` equals the role mapping; `commit_primitive` is exactly one of
`LINUX_RENAMEAT2_NOREPLACE_DIRFD_FSYNC_V1` or
`WINDOWS_SETFILEINFORMATIONBYHANDLE_RENAME_NO_REPLACE_V1`;
`commit_linearization` is exactly `FINAL_MARKER_CREATE_ONLY_PUBLICATION`;
`completion_state` is exactly `{"capture_complete":true}`; and
`disposition` is exactly `CAPTURE_COMPLETE_ONLY`, `accepted_scope` is exactly
`["G3_00_PARITY_CAPTURE_COMPLETION_ONLY"]`; and
`authority_ceiling` is the exact 28-field bitset. The marker cannot name its own
file identity.

```text
completion_id = "pfg3pcm-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_GATE3_SCHEMA_PARITY_COMPLETION_V2",
  completion:(full marker without completion_id and completion_body_sha256)
}))[0:32]
completion_body_sha256 = SHA-256(CJ(full marker without only completion_body_sha256))
marker file = CF(full marker)
```

The candidate/evidence/completion join is exact and bidirectional. The following
values must be byte-identical across all applicable objects: `transaction_id`,
`attempt_ordinal`, `role`, `principal`, producer source, launcher
principal/source, runtime manifest/review/closure ID, host-receipt identity/
schema/disposition/profile/role/entry validation/readable view, complete input-snapshot projection and aggregate private
candidate-set projection, candidate ID/body digest/file identity, requested
output/completion path, parity parsed value/body digest, native-image receipt
identity/ID/set digest, and the exact 28 authority fields. Evidence's producer
equals candidate principal/source. Marker's producer equals evidence producer.
Marker's evidence ID/body/file identity equals the staged evidence inode. The
three role mappings are closed; a cross-role path or identity cannot join. Each
join is checked before marker staging and again only in a new recovery epoch
when a visible marker is reconciled. There is no post-publication validation in
the committing epoch.

The staged-marker schema accepts exactly the completion-marker parsed value;
the staged file is `CF`-identical to the eventual final marker. Its
non-authority derives solely from its exact transaction-scoped staged path. No
field changes during publication, so handle-relative rename preserves the
validated pathless inode-content identity, size, and digest while the
path-bearing identity is reprojected from staging to the final path.

### 4.4 Fourth vector-bundle capture output and receipt

The distinct fourth capture has a closed output even though this amendment
supplies no concrete base-snapshot instance or capture authority. Its producer
stdout is exactly eight ASCII bytes `PFG3VBC1`, one unsigned 64-bit big-endian
`candidate_length`, exactly that many bytes equal to
`CF(vector_bundle_candidate)`, and EOF. `candidate_length` is
`1..16777216`; stderr is exactly zero bytes with EOF, exit is zero, and the
process tree is zero. The trusted parent persists only the exact `CF` candidate
payload (not the header or length) through an exclusive one-handle three-read
epoch at:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-captures/<base_snapshot_id>/<vector_capture_run_id>/vector-bundle.candidate.v1.json
```

Only the two displayed IDs are substituted. A second parent-written receipt is exclusively created,
three-read validated, and made durable at the same directory's
`vector-bundle.capture-receipt.v1.json`. Neither path is discovered by scanning.

`plamen.program_facts_parity_vector_bundle_candidate.v1` has exactly
`{schema_version,vector_bundle_id,capture_run_id,base_snapshot_id,
base_logical_content_sha256,capture_source,payloads,payload_set_sha256,
disposition,accepted_scope,authority_ceiling,vector_bundle_body_sha256}`.
`capture_source` is the exact logical `snapshot_file_identity` selected by the
base manifest, with path exactly
`review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/capture_schema_contract_parity_evidence_v2.py`.
`payloads` is exactly 12 rows in `snapshot_vector_paths` order;
each closed row is `{path,size_bytes,sha256,encoding,cf_utf8}`, with
`encoding:"UTF8_CF_INLINE_STRING_V1"`. UTF-8 encoding `cf_utf8` must be exactly
one strict `CF` JSON document, and its measured length/digest must equal the
row. The payload-set preimage is the concatenation of
`CJ({path,size_bytes,sha256}) || 0x0a` in that order. The output contains no
accepted-vector ID, per-vector review, payload-tree identity, materialization
receipt, promotion marker, or adoption artifact.

```text
vector_bundle_id = "pfg3vb-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_VECTOR_BUNDLE_V1",
  base_snapshot_id,base_logical_content_sha256,capture_source,
  payload_set_sha256
}))[0:32]
vector_bundle_body_sha256 = SHA-256(CJ(full candidate without only
  vector_bundle_body_sha256))
persisted candidate file = CF(full candidate)
```

The parent receipt
`plamen.program_facts_parity_vector_bundle_capture_receipt.v1` has exactly
`{schema_version,receipt_id,capture_run_id,base_snapshot,source_binding,
run_binding,output,payload_projection,disposition,accepted_scope,
authority_ceiling,receipt_body_sha256}`. `base_snapshot` is the full
host-bound base projection. `source_binding` binds the candidate's logical
source row to its base-root `handle_identity`, the parent-resolved canonical
absolute path, and the exact lexical child path/depth/root checks. `run_binding`
binds the actual backend, interpreter, argv, empty environment, base-root cwd,
framing digest, zero stderr/exit, and process-tree-zero observation. `output`
binds the exact persisted candidate `file_identity`, its ID/body digest, and the
complete framed-stdout content identity. `payload_projection` repeats the exact
12 `{path,size_bytes,sha256}` rows and payload-set digest. Every join to the
candidate is parsed-value equality.

`capture_run_id` is host-bound and is derived before either output path:

```text
capture_run_id = "pfg3vcr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_VECTOR_CAPTURE_RUN_V1",
  base_snapshot,source_binding,
  execution:{backend_id,interpreter,argv,cwd,environment}
}))[0:32]
receipt_id = "pfg3vbr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_VECTOR_BUNDLE_CAPTURE_RECEIPT_V1",
  receipt:(full receipt without receipt_id and receipt_body_sha256)
}))[0:32]
receipt_body_sha256 = SHA-256(CJ(full receipt without only receipt_body_sha256))
```

The receipt is non-authoritative run provenance, not a G0 materialization
receipt or host-isolation permit. The later accepted materializer must validate
the section-15 marker-last completion, observation, candidate, and receipt
chain and bind its closed projection into the candidate-set
manifest before it may construct a payload tree. This contract deliberately
fixes the interface and path derivation while leaving all concrete G0/source/
host identities absent until their separately reviewed predecessor exists.

## 5. Parent-bound startup, imports, and trusting-trust boundary

The parent launcher, not Python source running under the selected interpreter,
authenticates the exact private bundle, executable, runtime libraries, path
configuration, stdlib, vendor dependencies, producer source, bootstrap
template, and host boundary before process creation. It retains deny-write and
deny-delete handles for all executable/import/input bytes until process-tree
zero. A child can only report agreement with those bindings. It cannot prove
that the interpreter, launcher parent, OS loader, kernel, administrator, or
filesystem enforcing them is honest. Stronger trusting-trust assurance requires
a separately reviewed native/signed verifier or reproducible independent build;
neither is claimed here.

Before any capture, a separately accepted materialization amendment must first
seal the complete closed predecessor bytes as one immutable synthetic
`base_input_snapshot_manifest` and tree. Only after that base is immutable may
a distinct fourth, non-authoritative vector-bundle capture execute. That capture
runs with its authenticated source at its canonical repository-relative path
and with `cwd` equal to the retained base-snapshot root. Before denying child
path access, the parent resolves that source component-by-component through the
retained base handles, proves its canonical absolute path and physical identity,
and records both in the section-4.4 receipt. The child performs only a lexical
absolute-path equality and depth check: its supplied `__file__` must equal that
parent-resolved string and lexical `Path(__file__).parents[3]` must equal the
supplied base root. The child must not call `resolve`, `stat`, `open`, or any
other content/metadata reopen on `__file__`.
It may read only that base and must produce the single framed section-4.4
candidate containing exactly the 12 vector payload bytes; it creates no payload
tree or snapshot member. The trusted parent persists the candidate and its run
receipt at their exact ID-derived paths. The later accepted materializer is the
sole constructor of the candidate-set manifest and deterministic private
payload store at `candidate-sets/<candidate_set_id>/tree/<canonical-vector-path>`.
That store has exactly 12 immutable regular files at the exact section-14
vector paths and has no other entry, directory other than required prefixes,
alias, or mount/volume transition. For each row the materializer UTF-8 encodes
the candidate's `cf_utf8`, requires exact strict-CF/size/hash equality, and
writes those exact bytes through a freshly exclusively created payload handle;
it never reserializes the parsed vector. The materializer-written candidate-set
manifest binds the exact vector candidate/receipt projection, complete logical
roster, complete freshly observed path-bearing physical roster,
absolute/physical payload root, three-read completion, and both missing/extra
set differences at zero. The capture is not
`GENERATOR`, `EVALUATOR`, or `CROSSCHECK`, emits no parity evidence or
completion marker, and grants no admission or promotion.

The materializer must then create a new immutable derived G1 vector snapshot from
exactly `(the complete G0 base tree, in which all 12 target vector paths are
absent) UNION (the exact 12 candidate payload files at those paths)`. A target
collision in G0, a missing/extra candidate, unequal logical/physical row,
case/Unicode/short-name/link/reparse alias, or any third overlay source rejects.
It never modifies the base or payload tree. It writes and validates the closed `input_snapshot_manifest` and
binding in section 14 before any parity transaction ID is chosen. All three
parity roles run only against that same derived snapshot/candidate-set binding.
Inside the derived tree, all 12 subject schemas, provider registry, private
candidate vectors, and the three v2 source files occupy their canonical
repository-relative paths. Each role's `cwd` is the derived snapshot root. The
parent resolves the selected source under retained root/ancestor handles before
launch and binds that canonical absolute string plus physical identity into
control. The bootstrap compiles only the delivered bytes with that string, and
the producer performs only lexical equality/depth checks: `__file__`, compile
filename, every recursive `co_filename`, and the sole argv item equal the
parent-resolved string, while lexical `Path(__file__).parents[3]` equals the
supplied immutable root. `Path(__file__).resolve(strict=True)` and every other
child metadata/content reopen are forbidden because the selected and peer
source paths are intentionally unreadable to the child token.

No future accepted-vector identity, per-schema review, aggregate review,
promotion marker, or adoption artifact is an input to the base, candidate-set,
or derived-snapshot logical identity. Later review and promotion outputs are an
append-only generation set outside both snapshots and never mutate either
tree. The construction edge is strictly one-way: immutable G0 base plus the
materializer-owned payload produces immutable G1, and only later G1 evidence
may feed staged G2 review/promotion. No G2 file, review, marker, live aggregate,
or adoption artifact feeds G0, the payload, or G1. A live checkout, mutable
overlay, path fallback, post-bind copy, or later
review/publication path is never a capture cwd or input. No accepted
materialization amendment, base snapshot, candidate set, or derived snapshot
instance exists now, so all four captures remain construction-blocked.

The launch must satisfy all of these conditions:

1. the interpreter is an exact canonical absolute path in the reviewed private
   bundle, not `sys.executable` from the ambient launcher installation;
2. the executable is invoked with at least and exactly in this revision
   `-I -S -B`; the fixed `-c` bootstrap is launcher policy, not producer input;
3. the Windows bundle's `python312._pth` completely controls search paths,
   contains no `import site`, and is itself manifest-bound; other OSes require
   a separately reviewed equal-strength mechanism;
4. `site`, `.pth` execution, user site, `sitecustomize`, `usercustomize`,
   `PYTHONSTARTUP`, registry path additions, cwd/script-directory injection,
   and all environment-selected paths are absent;
5. a deny-by-default import guard compares every import name and resolved origin
   to the selected role closure. Unexpected names, namespace packages, missing
   origin, origin drift, distribution drift, lazy-import drift, native-image
   drift, or manifest disagreement terminates before candidate acceptance;
6. no producer imports, executes, reads as code, or shares an algorithm module
   with another producer. The private runtime bundle contains none of the three
   producer paths and no same-content/case/Unicode/short-name/link/reparse alias
   of any producer, as proved by both complete set-difference directions. The
   launcher bootstrap is limited to the eight transport
   capabilities in section 4.1 and supplies no parity answer;
7. each role receives a distinct host-enforced readable-member view over the
   common immutable snapshot. It can read only the categorized shared contract/
   schema/registry/vector/launcher inputs. The selected source and both peer
   producer sources are denied for canonical open, raw read, alias traversal,
   and inherited-handle access by the child token. The selected source bytes
   reach the child only in the authenticated CONTROL_READ source frame; no
   producer source handle is inherited. Static import/source analysis is not
   that proof;
8. the source bytes are read through a retained parent-bound handle, delivered
   from the exact immutable snapshot member to the fixed bootstrap, compiled
   with that member's canonical absolute path as `filename`, recursively checked
   so every code object's `co_filename` is identical, and executed only after
   globals `__name__="__main__"`, `__file__=<that path>`, and
   `sys.argv=[<that path>]` are installed; and
9. the physical logical source path remains parent-locked, root-confined, and
   byte-identical under the snapshot root through process-tree zero. The child
   may name that canonical path for `__file__`, argv, and `co_filename` but may
   validate it only lexically and may not resolve, stat, or reopen it; a live
   or mutable path cannot substitute its bytes for the bound stream.

An evaluator dependency import may therefore succeed only from the private
manifested vendor root. Ambient installation, user-site installation, network
installation, editable checkout, wheel cache, or package-manager lookup is a
hard failure. The six-distribution closure is complete only after an
independent static/literal-dynamic walk and executed lazy-path matrix converge.

## 6. Exact parity and provenance binding

The three v2 evidence objects may differ in role, producer, candidate,
transaction, isolation execution, and file-envelope fields. Their `parity`
values may not differ at all. Each implementation independently constructs the
accepted v1 subjects, occurrences, atoms, dispositions, proofs, vectors,
witnesses, four pattern streams, 11 stream identities, totals, joins, and
`parity_body_sha256`. Comparison uses byte-identical `CJ(parity)`, ordered row
equality, and both set-difference directions. Majority vote, count-only,
digest-only, or one producer importing another remains forbidden.

Cross-host comparison is deliberately narrower than same-host capture. The
base-snapshot ID/logical digest, candidate-set ID/logical digest, derived-
snapshot ID/logical digest, and `parity_body_sha256` are logical values and may
be required equal when two hosts were materialized from identical logical
members and the same logical vector-capture source/bundle projection. No rule
claims cross-host equality of absolute roots, physical
directory/file identities, interpreter or loader envelopes, runtime/native
image observations, host receipts, transaction IDs, candidate/evidence IDs or
bytes, or completion markers. Within one selected derived snapshot and native
host transaction set, all three roles must join the exact same snapshot and
candidate-set projections and emit byte-identical `CJ(parity)`.
Bootstrap control, compile/`co_filename`/`__file__`/argv values, cwd, role
readable views, and native entry identities remain only in the host-specific
outer envelope and never enter `parity` or a logical snapshot/candidate-set ID.

### 6.1 Closed pre-aggregate evidence lineage

The accepted clarification requires three exact v1 process-evidence roles before
per-schema and aggregate G3-00 review. V2 evidence is not byte-identical to those
v1 envelopes: its source paths, launcher, isolation, transaction, and completion
fields intentionally differ. This amendment therefore forbids silently treating
a v2 file as a v1 file and closes the successor mapping before any G2 per-schema
or aggregate review. After all three valid v2 completion chains exist, an
independent lineage validator writes exactly:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_V2_PRE_AGGREGATE_LINEAGE.v1.json
```

The closed artifact
`plamen.program_facts_g3_00_parity_pre_aggregate_lineage.v1` has exactly
`{schema_version,lineage_id,clarification,clarification_review,amendment,
amendment_review,scenario_manifest,harness,green_evidence,
implementation_review,launcher,runtime_closure,role_lineages,
common_parity_projection,reviewer,independence,checks,disposition,
accepted_scope,authority_ceiling,lineage_body_sha256}`. `role_lineages` is the
exact generator/evaluator/cross-check tuple. Each row contains exactly
`{role,legacy_requirement,successor_source,successor_source_review,
evidence,completion,parity_projection,outer_envelope_equal,
outer_envelope_equality_required,projection_result}`.

`legacy_requirement` is a literal requirement projection, never a claim that a
v1 artifact was created. Its schema version is
`plamen.program_facts_gate3_schema_contract_parity_evidence.v1`; its exact
role/principal and legacy source/output paths are the three section-11 rows of
the accepted clarification. `successor_source` is respectively the exact
section-2 generator-v2, evaluator-v2, or crosscheck-v2 file identity; its review
is the corresponding passing source review; and `evidence` plus `completion`
bind the exact valid v2 chain. `parity_projection` contains the complete
`CJ(parity)` content identity and `parity_body_sha256`. `projection_result` is
the literal `EXACT_ACCEPTED_V1_PARITY_VALUE_AND_ROLE_PROVENANCE_WITH_V2_ENVELOPE`.
The validator opens all six v2 files, checks every completion/evidence join,
requires all three complete parity parsed values and `CJ` bytes equal to the
accepted v1 contract, and explicitly records that outer-envelope equality is
false and neither asserted nor required.

The GREEN successor chain is not implied. `scenario_manifest`, `harness`,
`green_evidence`, `implementation_review`, `launcher`, and `runtime_closure`
are exact file identities. The CROSSCHECK row must additionally bind the exact
`crosscheck_schema_contracts_stdlib_v2.py` identity and its passing review, and
that same source/launcher/runtime chain must be the one in its completed v2
evidence. A v1 crosscheck, RED-only run, different green launcher, missing
implementation review, or source-review substitution rejects the lineage.

The five ordered checks are
`LIN-01-LEGACY-REQUIREMENT-PROJECTIONS`,
`LIN-02-V2-COMPLETION-CHAINS`, `LIN-03-EXACT-PARITY-PROJECTION`,
`LIN-04-GREEN-CROSSCHECK-V2-SUCCESSOR`, and
`LIN-05-ACYCLIC-NONAUTHORITY`; all must pass. The validator is separate from
every producer, launcher, fixture, implementation-review, materializer,
per-schema-review, and aggregate-review author. Its only passing disposition is
`PASS_PRE_AGGREGATE_V2_EVIDENCE_LINEAGE_MAPPING_ONLY`, and its authority ceiling
is the exact 28-field all-false object.

```text
lineage_id = "pfg3lin-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_PRE_AGGREGATE_LINEAGE_V1",
  lineage:(full lineage without lineage_id and lineage_body_sha256)
}))[0:32]
lineage_body_sha256 = SHA-256(CJ(full lineage without only lineage_body_sha256))
```

For every downstream per-schema review and aggregate checks G3A-07/G3A-08, the
successor evidence set is exactly the accepted clarification amendment/receipt,
this lineage identity, and the three mapped v2 evidence/completion pairs. Those
reviews must validate the lineage and all six mapped artifacts; they may not
keep the old five-identity count while substituting v2 bytes. This mapping is
completed before G2 review, has no vector/review output in its own preimage, and
does not depend on G3-01. G3-01 may later consume it but cannot retroactively
establish G3-00 parity lineage.

Every final evidence identity binds, directly or transitively:

- the accepted clarification amendment and receipt through v1 `parity.contracts`;
- the v2 launcher source and principal;
- the selected producer source and principal;
- exact absolute interpreter, runtime bundle, closure manifest/review,
  path configuration, bootstrap, distributions, module origins, import events,
  and system-loader boundary;
- the complete immutable input-snapshot binding, physical root, and aggregate
  private candidate-set identity shared by all three roles;
- the native host-isolation receipt and its exact backend/host identity;
- the exact native entry-name/prefix enumeration, role-specific physical
  readable-member/ACL projection, and exact selected-plus-two-peer source
  denial proof,
  without changing the common logical snapshot identity;
- exact argv, empty environment, cwd, inherited-handle set, limits, exit zero,
  empty stderr, process-tree zero, and candidate stdout identity; and
- the transaction-scoped evidence path and final completion-marker path.

A malformed, missing, extra, unstable, oversized, self-written, differently
canonicalized, or incompletely bound field fails closed. A producer cannot
write its transaction evidence or completion path; the child has no ACL/capable
handle for either. It writes only stdout.

## 7. One-handle stable I/O epoch

Every security-relevant input and output is accessed through a retained handle
epoch. This includes roots and ancestors, amendment/receipts, schemas, scenario
and runtime manifests, launcher and producer sources, interpreter and every
runtime/import member, input-snapshot manifest/root/member, aggregate candidate-
set manifest, native entry enumeration and role-readable-view member/denial evidence, dependency metadata,
host receipt, child stdout/stderr,
vector candidate/receipt, transaction evidence, journal, quarantine intent/
progress/complete record, pre-aggregate lineage, and completion marker.
`Path.read_bytes`, an
unchecked path reopen, or three separately opened descriptors is forbidden.

For each leaf, the exact algorithm is:

1. retain the trusted root handle and every traversed ancestor handle; reject an
   untrusted owner/DACL or mode, group/world/producer-writable ancestor, mount or
   volume escape, symlink, junction, reparse point, device, socket, pipe, or
   unsupported filesystem;
2. observe the leaf path without following links; open it relative to or under
   the retained root with no-follow semantics and no conflicting write/delete
   sharing; compare the pre-open path identity with the descriptor identity;
3. require a regular file, exact trusted root, expected owner/DACL or mode, an
   available stable physical identity, and the applicable size cap. Require
   `nlink == 1` except for an exact section-4 Windows System32/WinSxS
   `system_image` row, which instead requires its recorded link count and
   complete alias set;
4. record descriptor metadata, seek the same descriptor to offset zero, read to
   a verified EOF three times, and require byte identity; `fstat`/handle metadata
   before every read and after the third must remain identical;
5. re-observe the path with no-follow semantics before the first and after the
   third read, and require both path identities to equal the open descriptor;
6. compare exact size/SHA-256 to every pre-bound identity; and
7. retain that same handle through its last security use. Interpreter execution
   uses descriptor-bound exec on an accepted Linux successor or a held Windows executable handle that
   denies replacement; producer/input bytes use inherited bound handles or a
   parent-authenticated stream, never a later path reopen.

On Linux, the accepted primitive requires `openat`/`openat2` beneath retained
directory FDs, `O_NOFOLLOW|O_CLOEXEC`, `O_DIRECTORY` for directories,
`fstatat(...,AT_SYMLINK_NOFOLLOW)`, `fstat`, `lseek`, `read`, local-filesystem
device/inode identity, `st_nlink == 1`, and `fexecve` or
`execveat(...,AT_EMPTY_PATH)` for the interpreter. If any primitive or reliable
local durability/identity property is unavailable, the backend fails closed.
Snapshot validation additionally enumerates every retained directory FD,
requires raw entry-name bytes to be ASCII and exactly equal to the logical
roster/prefix projection, and rejects any unlisted directory, entry, mount, or
device transition.

On Windows, the accepted equivalent requires component-wise `CreateFileW` with
`OPEN_EXISTING`, `FILE_FLAG_OPEN_REPARSE_POINT`, directory backup semantics,
and sharing that denies write and delete; `GetFileInformationByHandleEx` for
file ID, volume, standard/link, attribute/tag, and basic information;
`GetFinalPathNameByHandleW` root confinement; `SetFilePointerEx` plus `ReadFile`
for all three reads; and before/after no-follow path-handle comparisons. Every
ancestor handle is retained. Only a reviewed local NTFS/ReFS profile with stable
file IDs and link counts can pass. A remote, FAT, path that cannot be opened
relative to the retained trusted root without a race, unavailable file ID,
reparse point, unlisted hardlink, incomplete System32/WinSxS alias set, or
conflicting share fails closed. The held interpreter
and DLL/source handles remain open through process-tree zero.
For the snapshot, `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)` (or a
separately reviewed equal-strength handle-relative enumeration) records the
native name, file ID, and alternate-name fields of every child; every
`ShortNameLength` is zero. Exact case/spelling and the complete
allowed-directory-prefix set must match before spawn; case-fold or Unicode-
normalization collisions and any extra directory/nonregular entry reject.

Output staging uses the same rules with exclusive create. The descriptor used
for writing is rewound and is the descriptor used for all three validation
reads. No validation is performed through a canonical-path reopen.

## 8. Native isolation remains unavailable

All production dispatch in v2 returns a fixed `ISOLATION_UNAVAILABLE_<OS>`
error before process creation until a separate native-host contract, fixture
run, and independent receipt are accepted and their identities are added to an
accepted successor closure. The v2 source contains no dormant `os.fork`,
`_execute_linux`, partial macOS sandbox, or callable unaccepted backend. There
is no Windows, Linux, macOS, amd64, arm64, container, CI, or local-host authority
in this amendment.

A future Windows-amd64 profile is implementable only as a conditional design:

The host isolation receipt for every such run must contain the exact
`input_snapshot_projection` selected before the transaction ID; the parent must
validate the complete manifest binding selected by that projection. The receipt
proves its absolute root/physical locator/immutable descendant digest in the
same retained-handle epoch and binds its ACL grants. A host receipt for a
different snapshot or candidate set is not reusable. It also binds the exact
role, complete `snapshot_entry_validation`, and complete
`role_readable_member_view`; the native enumeration must equal the ASCII
logical roster and allowed-directory-prefix set before launch. The child token
must fail canonical, raw-data, alias, and inherited-handle access to the
selected and both peer producer sources even though their bytes remain members
of the common immutable tree. Parent-retained source access is not inherited by
the child.

- use `CreateAppContainerProfile` followed by ordinary-user `CreateProcessW`
  with `STARTUPINFOEX`, `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`,
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, `EXTENDED_STARTUPINFO_PRESENT`,
  `CREATE_SUSPENDED`, `CREATE_UNICODE_ENVIRONMENT`, and
  `DEBUG_ONLY_THIS_PROCESS`. `SECURITY_CAPABILITIES.AppContainerSid` is the
  exact profile SID, `Capabilities` is null, and `CapabilityCount` is zero.
  `lpApplicationName` is the exact bound interpreter absolute path;
  `lpCommandLine` is a private mutable UTF-16 buffer produced from the exact
  six-item `execution.argv` by CPython's documented Windows/CRT quoting rules,
  and reparsing must reproduce those six strings byte-for-byte before launch.
  Before constructing that buffer, the parent also requires `execution.argv`
  to equal the manifest bootstrap's exact six-string array and recomputes
  `bootstrap.instantiated_argv_sha256` from the section-4.1 domain-separated
  `CJ({domain,argv})` preimage; a tuple or digest mismatch fails before launch.
  `STARTUPINFOEX.StartupInfo.dwFlags` contains `STARTF_USESTDHANDLES`;
  `hStdInput` is exactly the `CONTROL_READ` child value, `hStdOutput` exactly
  `STDOUT_WRITE`, and `hStdError` exactly `STDERR_WRITE`. The strict canonical
  control payload supplies and binds the `START_GATE_READ` and `STATUS_WRITE`
  child values as defined in section 4.1; no environment variable, inherited ambient descriptor scan,
  or conventional magic handle number is used.
  `bInheritHandles` is true solely for the five handles in the attribute-list
  projection; every other parent handle is non-inheritable and the suspended
  launch audit proves no other parent handle was inherited. OS-created process,
  thread, section, loader, and runtime handles are classified separately and
  are not falsely counted as parent-inherited handles.
  `CreateProcessAsUserW` is forbidden in this baseline and may appear only in a
  separately reviewed privileged-host profile that proves its token and
  privilege prerequisites. `CreateProcessInSandbox` is neither required nor a
  probed design input;
- create/read back the exact AppContainer SID with zero capabilities, verify
  suspended-child `TokenIsAppContainer`, exact `TokenAppContainerSid`, empty
  `TokenCapabilities`, exact integrity level, zero network capabilities, and no
  NetworkIsolation loopback exemption before assigning/resuming the child;
- grant explicit per-role DACL access only: read/execute to the private runtime,
  read to the categorized shared snapshot inputs in that role's readable-member
  view, write only to non-authoritative transaction staging, and no child
  filesystem access to the selected source, either peer source, or completion-marker
  publication. While suspended, the parent proves the attribute-list/inherited-
  handle set contains no producer-source handle. After OS resume but while
  `START_GATE_READ` remains withheld, the fixed bootstrap performs and reports
  canonical-path, raw-data, case/alternate/link-alias probes for the selected
  source and both peers;
  it then emits and closes the one strict STATUS_WRITE frame. The parent
  releases the exact one-byte gate and permits producer execution only after
  the complete status and every denial probe validate; an early/malformed
  status or gate is terminal for that attempt;
- the deterministic AppContainer profile name is
  `Plamen.G3Parity.<first-24-hex-of-host_profile_id>.<role-lower>`. Its SID, profile root
  from `GetAppContainerFolderPath`, root volume/file ID, owner, complete DACL,
  and initial empty descendant set are recorded in the attempt before launch.
  The profile's Windows-created writable `LOCALAPPDATA`, `TEMP`, and `TMP`
  locations are enumerated by canonical absolute path and retained-handle
  identity before launch, are absent from `sys.path`, the import allowlist, and
  executable search, and have deny-execute DACLs. Every created descendant is
  recorded in the attempt journal and is deleted through retained directory
  handles during precommit cleanup or moved as an intact tree to the exact
  deterministic quarantine path; a discovered ambient path is never trusted.
  The root is absent from `sys.path`, the runtime manifest, DLL search, cwd, and
  every inherited handle; it is non-executable/non-importable and may contain
   only journal-named staging. Cleanup deletes only exact recorded children and
   calls `DeleteAppContainerProfile`; failure moves the exact profile identity
   plus its complete stopped descendant manifest as one intact
   `WRITABLE_PROFILE_TREE` quarantine entry and blocks retry. Any unexpected
   nonregular descendant is retained in that tree manifest rather than skipped
   or followed. A reviewed profile-free alternative requires
  a successor amendment;
- set child-process-restricted and image-load mitigation, assign before
  resume to a non-breakaway Job with active-process limit one and kill-on-close,
  and inherit only the exact control, stdout, stderr, gate, and status handles;
- restrict DLL search, bind all bundle-owned images, and accept only the closed
  host-build System32 image allowlist; and
- collect every native image in the trusted parent through process-debug
  `CREATE_PROCESS_DEBUG_EVENT`/`LOAD_DLL_DEBUG_EVENT` handles from before resume
  until process-tree zero. The exact collector principal is
  `collector:openai-codex/g3-00-native-image-collector`, its role is
  `NATIVE_IMAGE_COLLECTOR`, and its source identity has the constant repository
  path `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/collect_windows_native_images_v1.cpp`;
  the later native-image receipt also pins
  the separately built collector image. A null/unresolvable debug-event `hFile`, missing event,
  debugger escape, or incomplete unload/exit sequence fails. The ordered receipt
  rows are exactly `{load_ordinal,event,process_id,image_base,requested_path,
  debug_hfile_identity,canonical_path,content_identity,origin,
  evidence_reference}`; `origin` is the closed `BUNDLE`/`SYSTEM` tagged union
  in section 14, and the system branch carries the complete reviewed system-
  image row. `requested_path` is nullable and advisory only. Canonical path,
  physical identity, and content identity are derived through the retained
  non-null event `hFile`; a disagreement with the requested string rejects.
  The rows are persisted at the deterministic attempt path. Projecting each row
  to `{load_ordinal,event,canonical_path,debug_hfile_identity,content_identity,
  origin}` must be exactly equal, in order and bytes as parsed values, to the
  manifest's expected projection for that role. Its set is therefore a subset
  of the bundle/system allowlist universe, while still covering the interpreter,
  all Python shared libraries, and every role-reachable extension; it is not
  required to equal all allowed system images. Child module reporting is only a
  cross-check. Evidence references this receipt, but the transaction-ID preimage
  cannot because the receipt does not exist before launch; and
- independently demonstrate TCP and UDP failure for IPv4/IPv6 loopback,
  every `localhost` result, private, and public destinations. `localhost`
  resolution may succeed only through the pinned hosts/cache prestate while a
  trusted packet observer records zero DNS packets. Separately call a bypass-
  cache resolver for the fresh name
  `pfg3-<transaction-id-32hex>.example.com`; it must fail and the observer must
  record zero outbound DNS packets. Resolver failure alone is insufficient.
  Empty-capability AppContainer is the ordinary-user baseline;
  administrator-only WFP evidence may strengthen but is not the sole path.

That design becomes available only through host-backed proof on the exact OS
build and filesystem profile. Current-host API presence, documentation, inert
fixtures, or source inspection is not such proof.

Future Linux requires a separately governed per-architecture runtime plus new
user/net/PID/mount namespaces, namespace PID 1 lifecycle, read-only runtime and
input mounts, tmpfs output, loopback down and empty routes, exact uid/gid maps,
cgroup-v2 pre-exec assignment/kill/population zero, Landlock acknowledgement,
zero capabilities, no-new-privileges, seccomp denial including socket paths and
io_uring bypasses, AF_UNIX policy, parent-death/fork-escape proof, and exact FD
closure. Future macOS requires a separately reviewed signed runtime and native
network/process-tree boundary. Neither design is activated here.

For receipt image row `i`, let `native_projection(i)` be exactly
`{load_ordinal,event,canonical_path,debug_hfile_identity,content_identity,
origin}` copied from that row. The observed digest is not a mathematical set
hash; its legacy field name is retained while its ordered preimage is closed:

```text
ordered_image_set_preimage = CONCAT for i = 0..len(images)-1 in increasing order:
  CJ(native_projection(images[i])) || 0x0a
ordered_image_set_sha256 = SHA-256(ordered_image_set_preimage)
```

There is no header, separator beyond each row's one `0x0a`, or trailer beyond
the final row's required `0x0a`.

`load_ordinal` must equal the zero-based array index. The receipt's
`expected_projection` must be parsed-value identical to the one manifest row
whose `role` equals the receipt role; its `expected_images` must equal the
ordered `native_projection(images[i])` array, and all three digests must be
equal: the recomputed observed digest, `expected_projection.projection_sha256`,
and `ordered_image_set_sha256`. These equality and coverage rules are semantic
validation in addition to the closed schema.

## 9. Marker-last crash-safe transaction

The completion marker is the sole commit event. All evidence bytes remain
under the clearly non-authoritative `transactions/<transaction_id>/` namespace
until the final marker is published. No consumer treats that namespace,
temporary file, journal state, evidence body, exit code, or log text as capture
authority.

The transaction ID is deterministic:

```text
transaction_id = "pfg3ptx-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_SCHEMA_PARITY_TRANSACTION_V2",
  role:<role>,
  launcher:<v2 launcher file_identity>,
  producer:<producer file_identity>,
  interpreter:<execution_interpreter>,
  runtime_closure:<manifest file_identity>,
  runtime_closure_review:<review file_identity>,
  input_snapshot:<input_snapshot_projection>,
  candidate_set:<candidate_set_projection>,
  host_receipt:<native host-receipt file_identity>,
  completion_path:<exact mapped marker path>
}))[0:32]
```

Equal inputs select the same transaction. A retry first reconciles that
transaction and never chooses a random/new suffix to bypass conflicting bytes.
`candidate_set` is byte-identical to `input_snapshot.candidate_set`; both are
known and parent-validated before launch. Neither projection contains an
accepted/future per-vector identity or review. A snapshot, physical root,
aggregate candidate-set, execution-interpreter, or host receipt change
necessarily selects a different transaction.

Raw candidate/evidence byte equality is required only when both objects claim
the same `(transaction_id,attempt_ordinal)` and the same journal-bound artifact
kind/path. A raw mismatch there is hard nondeterminism and quarantines that
attempt. Across distinct legitimate attempts, raw bytes are expected to differ.
The comparison instead uses exact
`stable_semantic_projection = {role,principal,source,launcher,runtime_closure,
input_snapshot,candidate_set,host_receipt,requested_output,parity}` where
`candidate_set` is the nested snapshot projection. It excludes transaction/
candidate/evidence IDs, attempt ordinal, candidate/evidence paths, PIDs, handle
values, native-image event/image-base/run envelopes, and other per-run
observations. Exact `CJ(parity)` and every stable producer/source/runtime/
snapshot binding must match across attempts. Any parity byte difference or
stable-binding difference is hard nondeterminism; differing excluded envelopes
alone are permitted and cannot authorize a ninth attempt or replacement.

Each attempt ordinal `n` is in `0..7` and has
`attempt_id = "pfg3pa-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_PARITY_ATTEMPT_V2",transaction_id,attempt_ordinal:n}))[0:32]`.
Its immutable attempt file has exactly `{schema_version,attempt_id,
transaction_id,attempt_ordinal,role,state,paths,inputs,
profile_writable_roots,created_descendants,artifacts,last_error,disposition,
accepted_scope,authority_ceiling,attempt_body_sha256}`. The attempt body digest
is SHA-256 of `CJ` after removing only `attempt_body_sha256`; its state is
always `PREPARED`, its initial descendant list is empty, and every later state
or descendant is recorded only in a new immutable journal. The attempt inode is
never overwritten.
All paths are produced only by substituting the exact transaction ID, ordinal,
and role-lower (`generator|evaluator|crosscheck`) into section 2. An `artifact_ref`
is exactly `{kind,path,inode_content_identity}`. Its path is the artifact's
current or historical locator; its pathless identity binds volume/file ID,
link count, size, and bytes in the retained epoch. An
artifact slot is exactly `{status:"ABSENT"}`, `{status:"CURRENT",artifact}`,
or `{status:"PREDECESSOR",artifact}`. `CURRENT` requires the exact path to name
that exact inode now; `PREDECESSOR` records a prior immutable/moved/deleted
artifact and forbids treating its old path as current. A journal never names
itself as a current artifact.

For every head exchange/history/archive/backup move and staged-marker-to-final
publication, the old and new paths are the exact mapped pair and differ, while
their `inode_content_identity` values are parsed-value identical before/after.
A regular-artifact quarantine move uses that same rule. An intact-tree move
instead compares its pathless root-directory plus descendant-manifest identity;
a nonregular move compares its no-follow file-ID/native-metadata identity. A
path-bearing `handle_identity` is never called equal after rename; it is
reprojected at the new path, and only the applicable pathless projection is
used for the cross-rename join.

The immutable attempt root is written before its own content identity exists.
In that root, `artifacts.lock` is `CURRENT` and every other artifact slot,
including `artifacts.attempt`, is `ABSENT`; it never hashes or references itself.
The genesis journal, created only after the attempt file is stable, is the first
object that records `artifacts.attempt` as `CURRENT`.

Journals are immutable ordinal files, not rewrites. A journal has exactly
`{schema_version,journal_id,transaction_id,journal_ordinal,previous_journal,
attempt_ordinal,attempt_id,role,state,paths,inputs,artifacts,child_capture,last_error,
created_descendants,disposition,accepted_scope,authority_ceiling,
journal_body_sha256}`. `paths` contains the exact lock, head,
journal, attempt, candidate, native-image, staged-evidence, staged-marker,
completion, deterministic quarantine root, and revision-specific
head-stage/history/backup paths. No ID-derived quarantine record path exists
in an attempt or pre-error journal.
`artifacts` contains the ten exact artifact slots. `previous_journal` is null
only at ordinal zero and otherwise the exact prior journal `artifact_ref`.
Genesis journal ordinal and head revision are both zero. Every transition adds
exactly one to the prior journal ordinal, uses that same number as the new head
revision, and rejects a gap, reuse, wrap, or noncanonical 16-digit path.
`child_capture` is null in `PREPARED`. It becomes the exact immutable bounded
transport projection only in `CHILD_COMPLETE` and is byte-identical in every
later journal for that attempt. An `ABORTED`, `QUARANTINED`, or `EXHAUSTED`
journal preserves the immediate predecessor's null-or-exact value and never
fabricates a child capture; `COMMITTED` necessarily carries the exact value.
It proves transport capture, not candidate validity.

```text
journal_id = "pfg3pj-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_JOURNAL_V2",
  journal:(full journal without journal_id and journal_body_sha256)
}))[0:32]
journal_body_sha256 = SHA-256(CJ(full journal without only journal_body_sha256))
```

The mutable transaction head has exactly `{schema_version,head_id,
transaction_id,head_revision,predecessor_head_body_sha256,journal,
transaction_state,attempt_ordinal,disposition,accepted_scope,
authority_ceiling,head_body_sha256}`.
Genesis uses revision zero and null predecessor; every successor increments one
and names the complete predecessor body digest. `journal` is the exact immutable
journal `artifact_ref`.

```text
head_id = "pfg3ph-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_TRANSACTION_HEAD_V2",
  head:(full head without head_id and head_body_sha256)
}))[0:32]
head_body_sha256 = SHA-256(CJ(full head without only head_body_sha256))
```

Attempt states and edges are exactly:

```text
PREPARED[n] -> CHILD_COMPLETE[n] -> CANDIDATE_STAGED[n]
  -> NATIVE_IMAGES_VALIDATED[n] -> EVIDENCE_STAGED[n]
  -> EVIDENCE_VALIDATED[n] -> MARKER_STAGED[n]
PREPARED[n]|CHILD_COMPLETE[n]|CANDIDATE_STAGED[n]|EVIDENCE_STAGED[n]
  |NATIVE_IMAGES_VALIDATED[n]|EVIDENCE_VALIDATED[n]|MARKER_STAGED[n]
  -> ABORTED[n]|QUARANTINED
ABORTED[n] -> PREPARED[n+1]                    only when n < 7
ABORTED[7] -> EXHAUSTED
MARKER_STAGED[n] -> COMMITTED                  only by final marker publication
ABSENT_HEAD + valid exact marker -> COMMITTED  recovery of ambiguous publication
```

Only `COMMITTED`, `QUARANTINED`, and `EXHAUSTED` are transaction-terminal.
`ABORTED[n]` is attempt-terminal only. Every transition creates/fsyncs/validates
one new immutable journal, then CAS-advances the head from the exact prior bytes,
except that final-marker publication itself establishes `COMMITTED` and a
pre-genesis conflict may establish `QUARANTINED` without a head. Any post-marker
`COMMITTED` journal/head projection is recovery metadata, never part of commit.
After `ABORTED[n]` is durable, the owning process completes the exact role-lock
release lifecycle. `PREPARED[n+1]` may be created only after a fresh exact-role
lock acquisition and retained-handle epoch; its journal records that new lock
as `CURRENT`, while the prior immutable journal remains the only reference to
the released predecessor lock. A retry never carries an unlocked inode forward
as current coordination state.

For the journal's `artifacts` slots, `C` means `CURRENT`, `A` means `ABSENT`,
`P/A` means `PREDECESSOR` if the artifact existed in any earlier state and
otherwise `ABSENT`, and `P` means a required predecessor. This matrix is exact:

| State | lock | head | journal | attempt | candidate | native_images | staged_evidence | staged_marker | quarantine | completion |
|---|---|---|---|---|---|---|---|---|---|---|
| `PREPARED` | C | A at genesis, otherwise P | A at genesis, otherwise P | C | A | A | A | A | A | A |
| `CHILD_COMPLETE` | C | P | P | C | A | A | A | A | A | A |
| `CANDIDATE_STAGED` | C | P | P | C | C | A | A | A | A | A |
| `NATIVE_IMAGES_VALIDATED` | C | P | P | C | C | C | A | A | A | A |
| `EVIDENCE_STAGED` | C | P | P | C | C | C | C | A | A | A |
| `EVIDENCE_VALIDATED` | C | P | P | C | C | C | C | A | A | A |
| `MARKER_STAGED` | C | P | P | C | C | C | C | C | A | A |
| `ABORTED` | C | P | P | C | P/A | P/A | P/A | P/A | A | A |
| `COMMITTED` | C | P | P | C | C | C | C | P | A | C |
| `QUARANTINED` | C | P/A | P/A | P/A | P/A | P/A | P/A | P/A | C | A |
| `EXHAUSTED` | C | P | P | P | P/A | P/A | P/A | P/A | A | A |

Terminal rows capture the last transaction journal while the owned lock is
still held; the mandatory post-terminal POSIX unlink-while-locked or Windows
disposition/delete-on-close plus close/barrier lifecycle changes
coordination state only and does not rewrite immutable transaction history.

The current journal is represented by the head's `journal` reference only,
never by the journal's own `artifacts.journal`; the current head does not exist
until after its journal is durable, so each journal's `artifacts.head` is
necessarily absent at genesis or predecessor thereafter. `COMMITTED` records
the staged-marker inode as predecessor because the no-replace rename changed
its path and records the same inode at the final path as current completion.
For Linux revision `r>0`, the complete next head is exclusively created and
validated at `head-staging/<r16>/head.next.v2.json`; retained directory FDs then
perform `renameat2(next,current,RENAME_EXCHANGE)`. The displaced predecessor at
the staging path must equal the journal-bound predecessor bytes and is moved
no-replace to `head-history/<r-1 as 16 digits>/head.previous.v2.json`; both
directories are fsynced. Any mismatch is exchanged back before quarantine.
Genesis uses `renameat2(RENAME_NOREPLACE)` from revision-zero staging to the
current head path.

Darwin/macOS has no accepted lock, head-CAS, or marker-publication primitive in
this amendment. A Darwin/macOS host requires a separately reviewed
`renameatx_np` head/marker successor plus Darwin-specific locking,
descriptor-relative confinement, and file/directory durability before it can
be selected; it cannot inherit the Linux enum or the Linux recovery rows below.
This amendment defines no dormant macOS backend.

For Windows revision `r>0`, the validated next head uses the same staging path;
`ReplaceFileW(current,next,head-backups/<r-1 as 16 digits>/
head.displaced.v2.json,0,NULL,NULL)` runs while the role lock is held. The
backup must equal the complete predecessor, is moved no-replace to the exact
history path, and the host-proven directory/volume durability barrier runs for
all touched directories. Genesis uses the handle-relative no-replace rename.
No `ReplaceFileW` flag is relied upon for durability. A mismatch restores the backup
before quarantine. A host lacking these exact CAS and barrier semantics is
unavailable.

Head-CAS scratch paths are deliberately not journal state slots: they exist only
between a durable journal and its head publication. Their complete recovery
matrix, under the role lock and a new retained-handle epoch, is:

| Primitive/substep | current head | exact `head_stage` | exact `head_history` | exact `head_backup` | Required recovery |
|---|---|---|---|---|---|
| genesis staged | absent | next revision-zero head | absent | absent | no-replace install stage as current, or quarantine mismatch |
| genesis installed | exact revision-zero head | absent | absent | absent | validate the exact genesis journal/head join and accept `PREPARED[0]` |
| Linux successor staged | exact predecessor | next head | absent | absent | perform exchange |
| Linux exchanged | next head | exact predecessor | absent | absent | move stage no-replace to history |
| Linux archived | next head | absent | exact predecessor | absent | accept transition |
| Windows successor staged | exact predecessor | next head | absent | absent | run `ReplaceFileW` with flags zero |
| Windows replaced | next head | absent | absent | exact predecessor | move backup no-replace to history |
| Windows archived | next head | absent | exact predecessor | absent | accept transition |

Here `absent` means the exact path is absent under its retained parent, and each
named object means the exact path plus pathless inode-content identity in the new journal or its
predecessor. An extra stage/history/backup object, an object at the wrong
revision path, a gap, or any identity mismatch creates deterministic quarantine;
no directory scan selects a candidate. Normal history remains immutable after
the `archived` row. In the `genesis installed` row, recovery must require
revision zero, null predecessor digest, the exact durable ordinal-zero journal,
`transaction_state:"PREPARED"`, attempt ordinal zero, and complete equality to
the head bytes that the genesis journal/attempt deterministically require. A
crash after successful no-replace installation but before the install call
returns or before later bookkeeping therefore resumes from that current head;
absence of stage/history/backup is the expected completed-genesis shape, not an
ambiguity or permission to recreate genesis. `HEAD_STAGE`, `HEAD_HISTORY`, and `HEAD_BACKUP` artifact
references exist only so quarantine can identify such conflicting bytes.

The role lock has exactly `{schema_version,lock_id,role,transaction_id,
owner_process,created_host_monotonic_ns,lock_path,lock_locator,
disposition,accepted_scope,authority_ceiling,lock_body_sha256}` where `owner_process` is exactly
`{pid,process_start_identity,launcher_identity}` and
`lock_id = "pfg3pl-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_PARITY_LOCK_V2",role,transaction_id,
owner_process}))[0:32]`. The root-relative `lock_locator` is captured from the
newly created empty inode before lock JSON
serialization and deliberately contains no content size/hash, so neither the
lock ID nor body digest self-hashes the file that stores it. Linux uses root-relative
`openat(O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_RDWR)`, an OFD write lock with
`F_OFD_SETLK`, file fsync, and directory fsync. Windows uses
`CreateFileW(CREATE_NEW)` with `GENERIC_READ|GENERIC_WRITE|DELETE`, share mode
zero, and no later access upgrade, followed by
`FlushFileBuffers`, and the reviewed directory durability profile. Stale lock
recovery is allowed only after a new epoch proves the Linux OFD lock acquirable
or the Windows DELETE-capable no-share handle openable, the exact recorded process-start
identity absent, and path/locator plus separately reread content identities
unchanged. An unparseable regular lock is stale only when the native lock is
acquired despite the unparseable owner. A nonregular object at the lock path has
no native lock owner to acquire or release; it is captured no-follow with
`native_lock_status:"NOT_APPLICABLE_NONREGULAR"` and coordination-quarantined.

The launcher holds that same kernel/OFD or no-share handle from successful
create/readback through every head CAS and until one of commit, attempt abort,
exhaustion, or transaction quarantine is durable. Release is OS-specific and
never closes the identity-bearing handle before selecting the object to delete.
On POSIX, while the OFD write lock and file descriptor are still held, recovery
revalidates `fstat(lock_fd)` against
`fstatat(parent_fd,basename,AT_SYMLINK_NOFOLLOW)`, calls
`unlinkat(parent_fd,basename,0)`, and proves the exact name absent. Only then does
it unlock/close the OFD and `fsync(parent_fd)`. On Windows, the original
DELETE-capable no-share handle is revalidated against the retained parent and
owned locator, marked delete-pending with
`SetFileInformationByHandle(FileDispositionInfo,{DeleteFile:TRUE})`, then
closed so delete-on-close removes that exact file, followed by the reviewed
parent-directory/volume durability barrier. Path-name `DeleteFileW`, a reopen
for DELETE access, closing before unlink/disposition, and deleting a same-name
replacement are forbidden.

A crash before POSIX `unlinkat` or Windows disposition leaves the exact live or
stale owned inode. A crash after POSIX unlink but before unlock/close leaves the
unlinked locked inode until process death; a crash after Windows disposition
but before close leaves the exact delete-pending handle until process death. A
crash after either close but before the directory barrier leaves an absent path
whose parent barrier must be completed; after forced crash, recovery accepts
only absence or the exact old stale inode that reappeared because deletion was
not durable. It reacquires/opens and repeats the same identity-bound lifecycle
for that exact inode. A different path object, owner, locator, file ID, link
count, or content identity fails closed and enters coordination quarantine.

Recovery always validates an existing final marker before diagnosing the role
lock. A valid marker is adopted unconditionally; stale-lock cleanup is then a
separate coordination operation and never quarantines or demotes the committed
transaction. A stale or malformed role lock is moved, never unlinked by name,
to a separate coordination-lock quarantine. Its family ID is
`lock_quarantine_id = "pfg3lq-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_PARITY_COORDINATION_LOCK_QUARANTINE_V1",role,error_code,
lock_path,observed_lock}))[0:32]`; this preimage
requires no transaction ID, head, or journal, so a pre-genesis malformed lock
is recoverable without inventing a transaction. `observed_lock` is an exact
no-follow quarantine entry reference and can represent either a regular lock
inode or a nonregular/reparse conflict at the lock path. The intent, sole
move-progress, complete-record, and payload paths use that ID only after all
preimage values exist.

Quarantine is deterministic:
`quarantine_id = "pfg3pq-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_PARITY_QUARANTINE_V2",transaction_id,role,error_code,
source_head,source_journal,conflicting_entries}))[0:32]`. `source_head` and
`source_journal` are each either the exact prior artifact reference or null. Its
`conflicting_entries` array is UTF-8 source-path ordered and uses a closed tagged
union: a regular transaction artifact carries its `artifact_ref`; an intact
stopped writable-profile tree carries its writable kind, source path, pathless
root-directory identity, complete no-follow descendant count, and descendant
manifest digest; and a nonregular marker/path conflict carries its source path,
native kind, pathless file ID/link identity, and exact native metadata/payload
digest. Thus an AppContainer profile root with all of its writable descendants,
or a symlink/junction/reparse/device/socket/FIFO conflict, is quarantine input
without pretending to be a regular `artifact_ref`.

Only after the family ID exists are the exact intent/final paths and one
destination per entry fixed. The immutable `PREPARED` intent contains the full
source refs and ordered move plan and is exclusively created, file-durable,
three-read validated, and parent-directory durable before the first move. Each
move is handle-relative and no-replace. A regular move preserves its pathless
inode-content identity; a tree move preserves the root directory identity and
complete descendant manifest; a nonregular move preserves its no-follow
pathless/native-metadata identity. After both source/destination directory
barriers, one immutable ordinal progress record binds the intent identity,
planned move, destination identity, source absence, and
`state:"MOVE_DURABLE"`. Only after every progress record is durable may the
immutable final `record_kind:"COMPLETE"` record name the intent and complete
ordered progress roster with `cleanup_disposition:"MOVED_COMPLETE"`. Only that
final record may be referenced by a `QUARANTINED` journal/head.

Recovery opens only the exact intent and ordinal paths. For the first planned
move without a valid progress record, exactly one of these states is resumable:
(a) the source path names the intent-bound identity and the destination is
absent, so recovery performs the move; or (b) the source is absent and the
destination names that exact identity, so recovery completes the directory
barriers and writes progress. An existing valid progress record requires source
absence and the exact destination identity. Both paths present, both absent,
identity drift, a progress gap/reorder, or an unexpected intent/final record
blocks recovery as `QUARANTINE_RECOVERY_AMBIGUOUS`; it never chooses or deletes
anything by discovery. Coordination-lock quarantine uses the identical
PREPARED -> one durable move-progress -> COMPLETE protocol and the same
source-or-destination reconciliation. No glob,
newest-file rule, suffix search, random name, or directory discovery scan exists.
The intent/final records and progress files are not moved entries and name no
later terminal journal/head, so after COMPLETE an optional terminal journal may
reference the final record without a cycle. A conflict found before
any head or journal exists uses both nulls; a conflict after journal zero but
before genesis-head publication uses null head and the exact journal reference.
After a head exists, both are non-null and `source_journal` is byte-identical to
that head's `journal` reference. These three pairs—`(null,null)`, `(null,exact
journal)`, and `(exact head,that head's exact journal)`—are exhaustive; a head
without its journal, unrelated references, or a quarantine self-reference
rejects.
Quarantine therefore never requires constructing `PREPARED` or a source head
first.

For transaction move ordinal `k`, and for the sole coordination move, the
progress identities are fixed before their paths and do not include a result
path:

```text
progress_id = "pfg3qmp-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_QUARANTINE_MOVE_PROGRESS_V2",
  quarantine_id,move_ordinal:k,planned_move
}))[0:32]
coordination progress_id = "pfg3lmp-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_LOCK_QUARANTINE_MOVE_PROGRESS_V1",
  lock_quarantine_id,move_ordinal:0,planned_move
}))[0:32]
```

Every PREPARED/COMPLETE family record's `quarantine_body_sha256` removes only
that field; every move-progress record's `progress_body_sha256` removes only
that field. The family ID remains the already derived transaction or
coordination quarantine ID in every record and is never recomputed from a moved
destination or progress file. Every intent projection identity has artifact kind
`QUARANTINE_INTENT`; every progress projection has kind
`QUARANTINE_PROGRESS`; its path and pathless inode/content identity are the
exact fixed record observed in the retained epoch.

The publication order is:

1. acquire the role publication lock; retained-handle validate absence or exact
   recovery state at every exact transaction/completion/head-staging/history/
   backup path. Any pre-genesis conflict creates quarantine with nullable
   source refs and stops;
2. exclusively create/fsync/validate the immutable attempt record, then journal
   ordinal zero in `PREPARED[0]`, then install revision-zero head. Only that
   successful head publication establishes `PREPARED`; failure cleans exact
   newly owned paths or creates pre-head quarantine;
3. launch only through an accepted native backend; validate the complete
   bounded pre-gate status before releasing the exact one-byte gate; capture
   bounded candidate stdout and zero-byte stderr through EOF; prove exit zero,
   isolation, cleanup, and process-tree zero; then durably journal/head-CAS
   `CHILD_COMPLETE[n]` with the exact status/stdout/stderr capture digests before
   parsing or persisting candidate bytes;
4. parse and validate the complete captured candidate; persist the exact stdout
   bytes without reserialization at the exact attempt path, validate their
   single-link inode and equality to `child_capture.stdout`, record
   `CANDIDATE_STAGED[n]`, collect
   and validate the parent-trusted native-image receipt, record
   `NATIVE_IMAGES_VALIDATED[n]`, then construct v2 evidence
   in memory and require its measured `CF` size at most 33,554,432 bytes;
5. exclusively create the transaction evidence, write it, flush/fsync it, and
   perform all three descriptor-bound reads, schema/identity/digest/parity/
   closure checks on that same inode; journal `EVIDENCE_STAGED[n]` then
   `EVIDENCE_VALIDATED[n]` through immutable journals/head CAS;
6. construct the marker from that exact evidence identity; exclusively stage,
   write, flush/fsync, and perform all three descriptor-bound marker validation
   reads; validate path/root/single-link identity and journal `MARKER_STAGED[n]`;
7. publish the already validated marker create-only at the mapped completion
   path. This publication is the sole `COMMITTED` linearization point; and
8. perform the host-profile directory durability barrier, then execute only the
   exact OS-specific owned-inode role-lock unlink-or-disposition/close/parent-
   barrier lifecycle and
   best-effort private journal projection/cleanup. No parity, candidate,
   evidence, or marker semantic validation occurs after publication; a lock
   cleanup failure is coordination evidence and cannot demote a valid marker.

Linux marker publication requires retained source/destination directory FDs and
`renameat2(...,RENAME_NOREPLACE)` from the validated single-link staged inode,
followed by destination-directory `fsync`. Windows opens the staged marker with
`DELETE` access while denying other write/delete sharing, retains the exact
destination-directory handle for identity evidence, and uses
`SetFileInformationByHandle` with `FileRenameInfoEx` only under the section-19.8
profile; `FILE_RENAME_INFO.RootDirectory` is NULL, the name is the exact bound
full-absolute destination path, `Flags` is exactly zero,
and therefore replace-existing semantics and every nonzero rename flag are absent.
The host receipt must prove that this no-replace operation is supported, rejects
an existing target, and preserves the same file ID. After the rename, a separate
postcondition.  No ordinary-user protected-root destination-directory plus
volume power-loss barrier is available in this draft; no rename flag or receipt
is treated as a durability primitive.  Windows is therefore unavailable for
power-loss publication and remains process-crash-only. `MoveFileExW`,
delete-then-move, path-only rename, copy, replace, and hardlink publication are
forbidden.

There is intentionally no second durable acceptance marker: that would create
an infinite durability recursion. If the marker path exists and validates on
recovery, the transaction is `COMMITTED`, including when publication succeeded
but the API reported an error, the launcher crashed immediately afterward, or
the directory durability barrier failed. A post-marker fsync failure is a
durability/availability uncertainty to report; it is not permission to delete
or demote a valid visible marker. No validation or fallible semantic step may
follow the commit event.

Exact recovery is:

| Observation | Result |
|---|---|
| valid marker binds exact transaction/evidence/input identities, with any lock state | adopt `COMMITTED` first; never spawn, delete, replace, or transaction-quarantine it; reconcile stale lock separately |
| no marker/head/journal; malformed or stale role lock | prove the exact owner-absence basis and native lock acquirability where regular (or non-applicability where nonregular), derive the transaction-independent coordination-lock quarantine ID from the exact no-follow entry, complete intent/progress/quarantine, and retry lock acquisition |
| marker absent; exact revision-zero current head and genesis journal exist while head stage/history/backup are absent | validate the complete genesis join and resume from `PREPARED[0]`; never recreate or quarantine merely because the install acknowledgment was lost |
| marker absent; head names `PREPARED[n]`, `CHILD_COMPLETE[n]`, or `CANDIDATE_STAGED[n]` | create immutable `ABORTED[n]`; a staged candidate without a complete native-image receipt is never resumable because lost debug events cannot be reconstructed; if n<7 create `PREPARED[n+1]`, else `EXHAUSTED` |
| marker absent; head names `NATIVE_IMAGES_VALIDATED[n]` or `EVIDENCE_STAGED[n]` | reopen every journal-bound path in one new epoch; resume only from the exact persisted complete native-image receipt and only if every pathless inode/content identity and state-allowed presence matches, else quarantine |
| marker absent; head names `EVIDENCE_VALIDATED[n]` or `MARKER_STAGED[n]` | in the new epoch revalidate referenced evidence/staged marker inodes; publish exact marker or quarantine |
| marker exists but is malformed, aliased, multi-linked, unstable, or mismatched | quarantine the marker and transaction under a deterministic role/transaction quarantine path; block automatic retry |
| marker absent but canonical marker temp/path identity is ambiguous | quarantine and block; never infer absence from an error code |
| exact quarantine or coordination-quarantine PREPARED intent exists without COMPLETE | reconcile each fixed move in ordinal order from its exact source-or-destination identity, durably append missing progress, then create COMPLETE; never scan |
| exact transaction-quarantine COMPLETE exists without terminal `QUARANTINED` journal/head | validate intent, every ordinal progress record, and every destination identity, then append only the terminal journal/head; never repeat a move |
| `ABORTED[7]` with no marker | append `EXHAUSTED`; never create ordinal 8 |
| transaction bytes conflict, cleanup/lock/path identity fails | quarantine and block |
| terminal abort/exhaust/quarantine with owned role lock | after terminal durability, use only the verified owned inode for POSIX unlink-while-locked or Windows disposition/delete-on-close, then close/barrier and durably reconcile every release crash seam before another acquisition |

Recovery first validates the exact final marker without acquiring or trusting
the role lock. If no valid marker exists, transactional recovery acquires the
exact role lock and opens a new retained-handle epoch; after marker adoption,
only the separate coordination cleanup may acquire/reconcile the native lock.
Transactional recovery starts from the fixed role mapping and transaction ID, opens the exact
head path (never a directory search), follows its exact immutable-journal and
artifact paths, and compares each exact path plus the pathless inode-content
identity recorded by the prior epoch. Quarantine recovery similarly starts from
the exact ID-derived intent path and its fixed progress paths, never from the
contents of a quarantine directory. Old descriptors, path existence alone,
and a matching digest with a different file ID are insufficient. No recovery
path reconstructs a native-image receipt from module reporting, logs, requested
image names, or a partial debug stream; only the exact durable
`NATIVE_IMAGES_VALIDATED` receipt crosses that resume boundary.
The journal-bound input-snapshot manifest, aggregate candidate-set projection,
absolute root locator, complete descendant/entry-roster digest, producer source
member, per-role readable-member/selected-plus-two-peer denial projection, and host-receipt
snapshot join are all reopened and compared before resume. Recovery
never falls back to the live repository or substitutes a newly materialized
equal-content tree with a different physical root; such a change selects a new
transaction or quarantines the conflicting old one.

Before-marker failure leaves no admitted-looking object: only the explicitly
non-authoritative transaction namespace may remain. Cleanup targets only exact
recorded handles/identities, never a glob or discovered name. A cleanup failure
quarantines. Retry replays the journal, marker, evidence, and input identities;
it does not unlink a prior valid marker or republish equal bytes.

## 10. Exact fixture-first successor denominator

After the exact ordered 39 stable successor inputs, including the reviewed
runtime build-plan/lock pair and the constructed
runtime bundle's manifest and its independent closure review, exist—but before
any v2 launcher source byte exists—a fixture author separate from the v2
implementer writes the exact scenario manifest and the single exact section-2
successor harness. That immutable harness first runs all
rows against the pinned first launcher candidate from section 1. It must not
load a missing v2 source in class setup. After repair, the same harness bytes
apply the same scenario IDs to v2. The immutable scenario manifest has exactly
52 rows, in this order:

| IDs | Exact scenario and required result |
|---|---|
| `LRC2-00` | exact section-1 candidate/input pins pass; all other rows execute even if this row fails |
| `LRC2-01` | argv lacks any of `-I -S -B`, or child flags disagree: reject before evidence |
| `LRC2-02` | cwd/script directory, `PYTHONPATH`, `PYTHONHOME`, user site, registry path, or shared startup path becomes importable: reject |
| `LRC2-03` | `.pth`, `sitecustomize`, `usercustomize`, or `PYTHONSTARTUP` sentinel executes: reject and sentinel remains absent |
| `LRC2-04` | exact interpreter/runtime build plan/review/toolchain/archive or acyclic expected-member lock, aggregate candidate set/payload, snapshot manifest, or immutable physical root/member roster drifts: reject before spawn |
| `LRC2-05` | one bundle member is missing, extra, reordered, path-aliased, same-size substituted, or equals/aliases a producer source: manifest/replay reject |
| `LRC2-06` | one locked wheel or distribution name/version/filename/tag/size/hash/METADATA/RECORD/file drifts, or an extra distribution appears: reject |
| `LRC2-07` | `jsonschema`, `referencing`, `attrs`, `jsonschema-specifications`, `rpds-py`, or `typing_extensions` resolves outside vendor or with unexpected origin: reject |
| `LRC2-08` | unexpected stdlib/native module, namespace package, lazy import, dynamic import, image without authoritative debug-event `hFile`, or native-image role-projection/origin mismatch appears: reject |
| `LRC2-09` | any producer imports a peer/launcher/production/target module, filesystem-opens the selected or either peer source, reaches one through case/link/alias or a runtime-bundle copy, or receives any producer-source handle: reject at the role filesystem boundary |
| `LRC2-10` | bootstrap supplies/imports shared producer parity logic or mutates a producer answer: reject; transport-only bootstrap passes |
| `LRC2-11` | child runtime/path attestation matches but parent bundle/snapshot binding is absent, wrong, live, or disagrees with host receipt; compile filename, recursive `co_filename`, `__name__`, `__file__`, one-item argv, cwd, or `parents[3]` root differs: reject |
| `LRC2-12` | input/source/runtime leaf, vector-capture output/receipt, base/payload/derived logical-physical roster, or overlay union has a link/reparse/nonregular/root/volume escape, untrusted or non-ASCII/misspelled/colliding/missing/extra member, target collision, incomplete prefix/descendant enumeration, mutable overlay, reused source physical identity, hardlink alias, or unsupported filesystem: reject |
| `LRC2-13` | non-system source/launcher/interpreter/bundle/dependency/input/evidence/marker is a hardlink with `nlink != 1`: reject; this does not mutate a reviewed System32/WinSxS row |
| `LRC2-14` | identical-byte inode/file-ID replacement before descriptor open, between pre-observation and open, or before first read: reject |
| `LRC2-15` | replacement/truncation between read one/two/three or metadata drift on the open descriptor: reject |
| `LRC2-16` | identical-byte path replacement after read three but before final path observation: reject |
| `LRC2-17` | Windows FILE_ID_INFO exact 16/32-lowercase-hex identity/share/reparse/root/lock check or Linux no-follow/dev/inode/openat/OFD check is unavailable or malformed, lock ownership changes, or Darwin/macOS is selected without its separately reviewed successor: fail closed |
| `LRC2-18` | child writes any mapped completion/evidence path or receives an unlisted handle/ACL: reject and no marker |
| `LRC2-19` | CONTROL/source/STATUS framing, bounds, EOF, status-before-gate, exact one-byte gate, stdout/stderr, exit, timeout, or process-tree contract differs: reject and no marker |
| `LRC2-20` | BOM, CR, missing/extra LF, invalid UTF-8, duplicate key, float/nonfinite/unsafe number, depth, pretty/noncanonical JSON, or control-size violation: reject |
| `LRC2-21` | vector-candidate/receipt, parity candidate/evidence/marker, pre-aggregate v1-to-v2 lineage/GREEN crosscheck chain, or snapshot/candidate-set join has a missing/extra/wrong field, future vector/review preimage dependency, schema version, ID, digest, role, principal, path, source, closure, execution, isolation, or authority bit: reject |
| `LRC2-22` | v1 parity row/order/join/stream identity/body digest changes while v2 envelope is rehashed: reject exact parity |
| `LRC2-23` | producer candidates differ only in outer envelope: allowed; any `CJ(parity)` difference: reject all three |
| `LRC2-24` | failure at lock, transport, CHILD_COMPLETE, candidate/native receipt, evidence/head including acknowledged-or-lost genesis install, quarantine PREPARED/move-progress/COMPLETE, or OS-specific lock unlink/disposition/close/barrier seam: no false marker; deterministic abort/resume/quarantine |
| `LRC2-25` | staged-evidence schema/digest/parity validation fails: no marker and only private staging/quarantine remains |
| `LRC2-26` | failure before/after marker stage create, write, file fsync, each of three reads, or final validation: no final marker |
| `LRC2-27` | marker final-path collision, symlink/hardlink/reparse alias, create-only primitive ambiguity, or stale lock after a valid marker: preserve/adopt the valid marker and never overwrite or transaction-quarantine it |
| `LRC2-28` | crash immediately before marker publication: uncommitted; recover/resume exact transaction |
| `LRC2-29` | publication succeeds then API errors/crashes before directory barrier or lock release completes: valid marker recovers as committed and lock cleanup remains separate |
| `LRC2-30` | post-marker directory fsync fails: record durability uncertainty without deleting/demoting a valid marker |
| `LRC2-31` | any semantic validation is injected after marker publication: fixture fails because no such seam may exist |
| `LRC2-32` | transaction cleanup and role-lock cleanup use exact owned handles; regular artifacts, intact writable-profile trees, and nonregular conflicts use deterministic PREPARED/progress/COMPLETE transaction or coordination quarantine with no discovered-path deletion |
| `LRC2-33` | retry accepts an exact installed genesis head, uses the same transaction/snapshot physical root, aborts nonresumable CANDIDATE_STAGED, resumes only from persisted NATIVE_IMAGES_VALIDATED, compares the stable semantic projection across attempts, rejects ordinal eight, and never respawns after valid marker |
| `LRC2-34` | same-attempt raw artifact mismatch or cross-attempt parity/stable-binding mismatch is nondeterminism; excluded run-envelope differences across attempts are allowed |
| `LRC2-35` | malformed/mismatched marker transaction-quarantines; pre-genesis malformed lock coordination-quarantines without transaction ID; valid marker plus stale head/lock is adopted first |
| `LRC2-36` | completion consumer is offered unmarked transaction evidence, marker without evidence, or evidence without exact marker: reject |
| `LRC2-37` | Windows zero-capability/token/DACL/job/child proof, exact snapshot/payload host binding, physical-member validation, complete role-readable/selected-plus-two-peer denial view, five-handle mapping, CONTROL/STATUS/GATE protocol support, or inherited-versus-OS-created handle accounting is missing: no spawn authority |
| `LRC2-38` | pinned localhost name resolution may succeed only with zero DNS packets and all resolved-address sockets denied; any IPv4/IPv6/loopback/private/public TCP/UDP success rejects, and the fresh bypass-cache external name must not resolve, must emit zero outbound DNS packets, and all external socket attempts must fail |
| `LRC2-39` | Linux or macOS selected without separately accepted exact host receipt: fail before process creation |
| `LRC2-40` | v2 source exposes dormant partial native backend or `os.fork`: construction review fails |
| `LRC2-41` | old v1 output/history is overwritten, treated as v2, or used to backfill red chronology: reject |
| `LRC2-42` | fixed and revisioned locators use path/content-only first anchors and role/operation OFD serialization across every recovery and concurrency seam |
| `LRC2-43` | regular/directory/nonregular identities include exact raw or explicitly normalized xattr, ACL, security-descriptor, EA, and ADS streams |
| `LRC2-44` | Linux alone has a power-loss-durable same-mount no-replace move; Windows is process-crash-only and macOS is unavailable |
| `LRC2-45` | reviewed source, bootstrap mode, non-self-referential control/status/gate frames, parent binding, and operation/run path split are exact |
| `LRC2-46` | the one-attempt capture has the exact 14-state transition universe, 13-row/17-slot ordinary artifact matrix, 12 adjacent and 11 quarantine edges, full complement, marker-last publication, and no retry, scan, or backfill |
| `LRC2-47` | every containment policy has closed exact semantics/bytes, an operation-private cgroup instance, persisted typed native evidence, and the success root embeds the exact confirmed post-operation join |
| `LRC2-48` | static, revision, quarantine, and run paths are disjoint derived families and every persisted path equals its family derivation |
| `LRC2-49` | control, status, and authorization are registered persisted roots whose file bytes and native transport frames are independently recomputed |
| `LRC2-50` | a malformed fixed intent before genesis uses the headless family, exact destination metadata joins, and legacy entry types without inventing event/head/transaction identity |
| `LRC2-51` | `SPAWN_MAY_HAVE_OCCURRED` recovery kills/proves empty without fabricated process identity and moves only the vector-scoped closed private artifact set |

The table is explanatory. The exact canonical `scenarios` parsed array embedded
in the manifest, with no member omitted or added, is:

<!-- BEGIN PARITY_SCENARIO_ROSTER_R3_5 -->
```json
[
{"category":"BASELINE","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_EXPECTED_ACCEPTANCE","mutation":{"kind":"SINGLE","value":"Recompute all seven section-1 path/size/SHA-256 triples and require exact equality."},"ordinal":0,"red_expectation":"PASS_BASELINE_PIN","scenario_id":"LRC2-00"},
{"category":"STARTUP","expected_error_precedence":1,"expected_first_error":"STARTUP_FLAGS","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["remove -I","remove -S","remove -B","report one mismatching sys.flags value"]},"ordinal":1,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-01"},
{"category":"STARTUP","expected_error_precedence":2,"expected_first_error":"STARTUP_PATH","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["inject cwd","inject script directory","inject PYTHONPATH","inject PYTHONHOME","inject user site","inject registry path","inject shared startup path"]},"ordinal":2,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-02"},
{"category":"STARTUP","expected_error_precedence":3,"expected_first_error":"STARTUP_HOOK","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["execute poison.pth sentinel","import sitecustomize sentinel","import usercustomize sentinel","execute PYTHONSTARTUP sentinel"]},"ordinal":3,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-03"},
{"category":"RUNTIME_CLOSURE","expected_error_precedence":4,"expected_first_error":"RUNTIME_IDENTITY","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["replace interpreter path","replace interpreter bytes","replace Python runtime library","replace path configuration","replace stdlib member","replace bootstrap bytes","replace runtime-builder source","replace runtime build-plan identity","replace runtime build-review identity","make expected runtime member identity depend on actual bundle root build review runtime manifest or closure review","replace CPython archive identity","replace builder toolchain identity","replace private root identity","replace input-snapshot manifest identity","replace aggregate candidate-set identity","replace candidate-payload physical root","replace immutable snapshot physical root","replace one physical-member roster row"]},"ordinal":4,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-04"},
{"category":"RUNTIME_CLOSURE","expected_error_precedence":5,"expected_first_error":"RUNTIME_MEMBER_SET","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["omit one member","add one member","reorder members","alias one path","same-size substitute one member","place producer source at its canonical path inside runtime bundle","place same-content producer source under a case Unicode short-name link or reparse alias inside runtime bundle"]},"ordinal":5,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-05"},
{"category":"RUNTIME_CLOSURE","expected_error_precedence":6,"expected_first_error":"DISTRIBUTION_CLOSURE","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["change locked wheel filename","change locked wheel tag","change locked wheel size or hash","change distribution name","change distribution version","change METADATA","change RECORD","change installed file","add seventh distribution"]},"ordinal":6,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-06"},
{"category":"RUNTIME_CLOSURE","expected_error_precedence":7,"expected_first_error":"DEPENDENCY_ORIGIN","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["resolve jsonschema outside vendor","resolve referencing outside vendor","resolve attrs outside vendor","resolve jsonschema-specifications outside vendor","resolve rpds-py outside vendor","resolve typing_extensions outside vendor"]},"ordinal":7,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-07"},
{"category":"RUNTIME_CLOSURE","expected_error_precedence":8,"expected_first_error":"MODULE_ORIGIN","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["load unexpected stdlib module","load unexpected native module","load namespace package","load unlisted lazy import","load unlisted dynamic import","load system image outside allowlist","omit System32 or WinSxS alias","mismatch system-image volume or file ID","mismatch system-image owner DACL signature hash or OS build","omit native-image receipt event","native image event has null or unresolvable debug hFile","requested path disagrees with hFile-derived canonical path","observed image projection differs from exact role projection","collector principal source or binary differs"]},"ordinal":8,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-08"},
{"category":"IMPORT_INDEPENDENCE","expected_error_precedence":9,"expected_first_error":"PRODUCER_SOURCE_ACCESS","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["generator imports evaluator","generator imports crosscheck","evaluator imports generator","evaluator imports crosscheck","crosscheck imports generator","crosscheck imports evaluator","producer imports launcher","producer imports production module","producer imports target code","generator raw-opens evaluator source","generator raw-opens crosscheck source","evaluator raw-opens generator source","evaluator raw-opens crosscheck source","crosscheck raw-opens generator source","crosscheck raw-opens evaluator source","producer filesystem-opens its selected source","producer reads selected source through case-varied link or reparse alias","producer reads peer source through case-varied path","producer reads peer source through symlink junction or reparse alias","producer receives inherited producer-source handle","runtime bundle contains peer source at canonical bundle path","runtime bundle contains same-content peer source under alternate path or alias"]},"ordinal":9,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-09"},
{"category":"IMPORT_INDEPENDENCE","expected_error_precedence":10,"expected_first_error":"SHARED_PRODUCER_STARTUP","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["bootstrap imports producer helper","bootstrap supplies parity row","bootstrap mutates parity answer","shared hook changes producer globals"]},"ordinal":10,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-10"},
{"category":"RUNTIME_CLOSURE","expected_error_precedence":11,"expected_first_error":"PARENT_BINDING_REQUIRED","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["supply matching child runtime observation while deleting parent_pre_spawn_verified binding","supply matching canonical child paths while deleting parent input-snapshot binding","bind child to live repository while claiming immutable snapshot","host receipt names a different snapshot or candidate set","compile bound source with wrong filename","one recursive code object has wrong co_filename","set globals __name__ other than __main__","set globals __file__ to wrong path","set sys.argv empty or add a second item","source path has wrong lexical depth so parents[3] differs from the parent-resolved snapshot root","child calls Path(__file__).resolve strict or otherwise reopens the selected-source path","cwd uses equal-content alias instead of bound snapshot root"]},"ordinal":11,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-11"},
{"category":"HANDLE_IO","expected_error_precedence":12,"expected_first_error":"PATH_ALIAS","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["symlink leaf","junction ancestor","reparse leaf","nonregular leaf","root escape","untrusted-root member","producer source resolves from live repository","mutable synthetic overlay","base physical roster omits or adds a member","candidate payload physical roster omits or adds a member","derived physical roster omits or adds a member","base contains one target vector path","candidate payload misses one target vector","candidate payload adds a thirteenth vector","vector capture frame magic length CF or EOF differs","vector capture candidate or receipt base source run payload join differs","vector capture creates the candidate payload tree instead of the materializer","candidate payload file is outside candidate-sets slash candidate-set-id slash tree","candidate manifest omits the exact vector-candidate and receipt projection","derived overlay contains a third-source row","derived physical member reuses a base or payload file ID","derived physical member is a hardlink reflink identity reuse or has nlink other than one","snapshot descendant digest is computed from logical rows instead of physical handles","snapshot logical path contains non-ASCII","native entry case or spelling differs from logical roster","case-fold collision between snapshot entries","Unicode-normalization collision between snapshot entries","allowed directory-prefix set omits a required prefix","allowed directory-prefix set adds an extra prefix","native enumeration contains an extra directory","native enumeration contains a nonregular entry","snapshot member crosses mount or volume","snapshot member has hardlink alias","snapshot member has reparse alias","snapshot member exposes DOS 8.3 alternate name","filesystem profile cannot prove exact entry semantics"]},"ordinal":12,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-12"},
{"category":"HANDLE_IO","expected_error_precedence":13,"expected_first_error":"NLINK_NOT_ONE","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["hardlink source","hardlink launcher","hardlink interpreter","hardlink bundle member","hardlink dependency","hardlink input","hardlink evidence","hardlink marker"]},"ordinal":13,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-13"},
{"category":"HANDLE_IO","expected_error_precedence":14,"expected_first_error":"PATH_IDENTITY_PREOPEN","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["identical-byte replacement before descriptor open","replacement between pre-observation and open","replacement after open before first read"]},"ordinal":14,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-14"},
{"category":"HANDLE_IO","expected_error_precedence":15,"expected_first_error":"DESCRIPTOR_UNSTABLE","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["truncate between reads one and two","rewrite between reads two and three","metadata drift on retained descriptor"]},"ordinal":15,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-15"},
{"category":"HANDLE_IO","expected_error_precedence":16,"expected_first_error":"PATH_IDENTITY_POSTREAD","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SINGLE","value":"Replace path with identical bytes after read three and before final path observation."},"ordinal":16,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-16"},
{"category":"HANDLE_IO","expected_error_precedence":17,"expected_first_error":"STABLE_IO_UNAVAILABLE","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["Windows file ID unavailable","Windows share denial unavailable","Windows reparse check unavailable","Windows root confinement unavailable","Windows no-share role-lock primitive unavailable","Windows role-lock handle lacks DELETE access from creation","Windows FileDispositionInfo delete-on-close unavailable","Linux O_NOFOLLOW unavailable","Linux device/inode unavailable","Linux openat beneath-root unavailable","Linux OFD role-lock primitive unavailable","role-lock path no longer names owned inode","select Darwin/macOS without separately reviewed renameatx_np locking durability successor","Windows FILE_ID_INFO zero VolumeSerialNumber is rendered without exactly 16 lowercase hex digits","Windows FILE_ID_INFO high-bit VolumeSerialNumber is interpreted as signed","Windows FILE_ID_INFO maximum VolumeSerialNumber is converted through a JSON number or binary64","Windows FILE_ID_INFO VolumeSerialNumber uses uppercase plus sign decimal or alternate width","Windows FILE_ID_INFO FILE_ID_128 is rendered with fewer or more than 32 lowercase hex digits","Windows FILE_ID_INFO high-bit FILE_ID_128 is interpreted as a signed or host integer","Windows FILE_ID_INFO FILE_ID_128 is truncated to 64 bits","Windows FILE_ID_INFO FILE_ID_128 bytes are GUID-reordered or reversed","Windows FILE_ID_INFO raw 24-byte struct does not project to the two canonical strings","Windows FILE_ID_INFO canonical string loses a leading zero nibble during round trip","Windows FILE_ID_INFO boundary value is rounded changed or normalized after canonical JSON","Windows FILE_ID_INFO identity is accepted from numeric signed truncated alternate-case or alternate-width input"]},"ordinal":17,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-17"},
{"category":"HANDLE_IO","expected_error_precedence":18,"expected_first_error":"CHILD_WRITE_OR_HANDLE","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["child writes completion path","child writes evidence path","inherit unlisted handle","grant child marker-directory write DACL"]},"ordinal":18,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-18"},
{"category":"TRANSPORT_SCHEMA","expected_error_precedence":19,"expected_first_error":"PROCESS_TRANSPORT","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["CONTROL magic differs","CONTROL u64 length is truncated or overflows","CONTROL payload is not strict CF JSON","CONTROL exceeds 16777216 bytes","raw source frame length mismatches control source","raw source frame exceeds 16777216 bytes","CONTROL_READ has trailing byte after source","STATUS magic differs","STATUS u64 length is truncated or overflows","STATUS payload is not strict CF JSON","STATUS frame exceeds 1048576 bytes","STATUS outer-context source or producer-source-denial digest mismatches","STATUS_WRITE lacks EOF","gate arrives before validated status","gate byte is missing or not 0x01","gate has extra byte before EOF","stdout is not exactly one CF candidate plus EOF","stdout exceeds 33554432 bytes","stderr contains one byte","stderr exceeds 1048576 bytes","exit nonzero","timeout after 3600 seconds","process tree nonzero"]},"ordinal":19,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-19"},
{"category":"TRANSPORT_SCHEMA","expected_error_precedence":20,"expected_first_error":"CANONICAL_JSON","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["prepend BOM","insert CR","remove final LF","append second LF","invalid UTF-8","duplicate key","float token","nonfinite token","unsafe integer","depth 257","pretty JSON","control document exceeds 16777216 bytes"]},"ordinal":20,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-20"},
{"category":"TRANSPORT_SCHEMA","expected_error_precedence":21,"expected_first_error":"CLOSED_SCHEMA","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["missing required field","extra field","wrong schema version","wrong identity","wrong body digest","wrong role","wrong principal","wrong path","wrong source","wrong runtime build binding","wrong closure","wrong execution","wrong bootstrap control outer binding","wrong bootstrap status binding","wrong isolation","wrong 28-field authority","missing input-snapshot binding","candidate evidence marker snapshot join mismatch","candidate payload projection mismatch","vector-bundle candidate omits base source run or payload provenance","vector-bundle receipt output identity frame digest or payload projection mismatches","pre-aggregate lineage omits one v2 evidence completion pair or claims full v1 envelope equality","pre-aggregate lineage fails to bind GREEN scenario harness implementation review launcher runtime or exact crosscheck-v2 source review chain","future vector or review identity inserted into transaction preimage","portable interpreter file_identity used in transaction preimage","portable kernel or loader file_identity used in host boundary","path-inclusive handle identity compared equal across rename","staged marker pathless inode-content identity differs after publication rename","head predecessor pathless inode-content identity differs after archive rename","transaction-quarantine regular tree or nonregular payload pathless identity differs after move"]},"ordinal":21,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-21"},
{"category":"PARITY","expected_error_precedence":22,"expected_first_error":"PARITY_MISMATCH","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["change parity row","change row order","change join","change stream identity","change parity body digest then rehash envelope"]},"ordinal":22,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-22"},
{"category":"PARITY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES","mutation":{"kind":"MIXED_SUBCASES","values":[{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ACCEPT","label":"outer envelopes differ and CJ parity is equal"},{"expected_error_precedence":23,"expected_first_error":"PARITY_MISMATCH","expected_outcome":"REJECT","label":"CJ parity differs by one byte"}]},"ordinal":23,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-23"},
{"category":"TRANSACTION","expected_error_precedence":24,"expected_first_error":"EVIDENCE_STAGE_FAULT","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["fault after status validation before gate write","fault after gate EOF before stdout EOF","fault after process-tree zero before CHILD_COMPLETE journal","fault after CHILD_COMPLETE journal before candidate parse","fault after CANDIDATE_STAGED before native-image receipt durability","fault after native-image receipt durability before NATIVE_IMAGES_VALIDATED journal","fault before evidence create","fault after evidence create","fault after each evidence write","fault before and after evidence file fsync","fault before each of three reads","fault before final path recheck","fault before and after each journal/head file or directory fsync","fault after successful genesis head install before return with stage history and backup absent","fault after next-head stage durability","fault after Linux head exchange before history archive","fault after Windows head replacement before backup archive","fault after head history archive before durability barrier","fault after quarantine ID derivation before PREPARED intent creation","fault after quarantine PREPARED intent durability before first move","fault after a quarantine move before source and destination directory barriers","fault after quarantine move barriers before ordinal progress durability","fault after ordinal progress durability before the next move","fault after all move progress before COMPLETE record durability","fault after quarantine COMPLETE durability before terminal journal and head","fault after coordination-lock quarantine move before its sole progress record","fault before POSIX role-lock unlink or Windows delete disposition","fault after POSIX role-lock unlink before OFD unlock","fault after POSIX OFD unlock before close","fault after Windows role-lock delete disposition before close","fault after role-lock close before parent-directory durability barrier"]},"ordinal":24,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-24"},
{"category":"TRANSACTION","expected_error_precedence":25,"expected_first_error":"EVIDENCE_VALIDATION","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["staged evidence schema mismatch","staged evidence digest mismatch","staged evidence parity mismatch"]},"ordinal":25,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-25"},
{"category":"TRANSACTION","expected_error_precedence":26,"expected_first_error":"MARKER_STAGE_FAULT","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["fault before marker create","fault after marker create","fault after each marker write","fault before and after marker file fsync","fault before each of three marker reads","fault before final marker validation"]},"ordinal":26,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-26"},
{"category":"TRANSACTION","expected_error_precedence":27,"expected_first_error":"MARKER_COLLISION","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["existing invalid final marker","final symlink","final hardlink","final reparse point","no-replace primitive ambiguous","implementation transaction-quarantines a valid existing marker because role lock is stale"]},"ordinal":27,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-27"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_EXPECTED_RECOVERY","mutation":{"kind":"SINGLE","value":"Crash immediately before marker publication with exact MARKER_STAGED journal/head."},"ordinal":28,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-28"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_EXPECTED_RECOVERY","mutation":{"kind":"SINGLE","value":"Publish marker successfully, return API error, and crash before directory barrier or owned role-lock release completes; adopt marker first and reconcile lock separately."},"ordinal":29,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-29"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_EXPECTED_RECOVERY","mutation":{"kind":"SINGLE","value":"Inject destination-directory durability failure after successful marker publication."},"ordinal":30,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-30"},
{"category":"TRANSACTION","expected_error_precedence":31,"expected_first_error":"POST_COMMIT_VALIDATION_FORBIDDEN","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SINGLE","value":"Add any semantic validation callback after final marker publication."},"ordinal":31,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-31"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES","mutation":{"kind":"MIXED_SUBCASES","values":[{"expected_error_precedence":32,"expected_first_error":"PRECOMMIT_FAULT","expected_outcome":"ABORT_ATTEMPT","label":"exact precommit cleanup succeeds"},{"expected_error_precedence":32,"expected_first_error":"CLEANUP_FAILED","expected_outcome":"QUARANTINE_TRANSACTION","label":"exact transaction cleanup fails"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"stale or malformed role lock uses PREPARED progress COMPLETE coordination quarantine without a transaction ID"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"transaction quarantine moves one intact writable-profile directory tree with complete descendant identity"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"transaction quarantine moves one nonregular marker or reparse conflict by no-follow identity"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash after move before progress resumes from exact destination identity and source absence"},{"expected_error_precedence":32,"expected_first_error":"QUARANTINE_RECOVERY_AMBIGUOUS","expected_outcome":"REJECT","label":"quarantine source and destination are both absent both present or identity-mismatched"},{"expected_error_precedence":32,"expected_first_error":"COORDINATION_LOCK_RENAME_MISMATCH","expected_outcome":"REJECT","label":"coordination-lock quarantine payload identity differs after rename"},{"expected_error_precedence":32,"expected_first_error":"DISCOVERED_PATH_CLEANUP_FORBIDDEN","expected_outcome":"REJECT","label":"discovered-path cleanup or quarantine scan attempted"}]},"ordinal":32,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-32"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES","mutation":{"kind":"MIXED_SUBCASES","values":[{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"exact revision-zero current head with genesis journal and absent stage history backup resumes PREPARED zero"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"ABORTED[n] to PREPARED[n+1] for n 0 through 6"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"ABORTED[7] to EXHAUSTED"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"CANDIDATE_STAGED transitions to ABORTED without reconstructing lost debug events"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"NATIVE_IMAGES_VALIDATED resumes from exact persisted complete receipt"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"new attempt has equal stable semantic projection and different excluded run envelope"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ADOPT_COMMITTED","label":"valid marker prevents respawn"},{"expected_error_precedence":33,"expected_first_error":"ATTEMPT_LIMIT","expected_outcome":"REJECT","label":"attempt ordinal 8 rejected"},{"expected_error_precedence":33,"expected_first_error":"SNAPSHOT_RECOVERY_MISMATCH","expected_outcome":"QUARANTINE_TRANSACTION","label":"retry substitutes equal-content snapshot with different physical root"}]},"ordinal":33,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-33"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES","mutation":{"kind":"MIXED_SUBCASES","values":[{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ACCEPT","label":"distinct attempts differ only in IDs paths PIDs handle values image bases and run envelopes while stable semantic projections match"},{"expected_error_precedence":34,"expected_first_error":"NONDETERMINISTIC_OUTPUT","expected_outcome":"QUARANTINE_TRANSACTION","label":"same attempt and journal-bound candidate path has different raw bytes"},{"expected_error_precedence":34,"expected_first_error":"NONDETERMINISTIC_OUTPUT","expected_outcome":"QUARANTINE_TRANSACTION","label":"same attempt and journal-bound evidence path has different raw bytes"},{"expected_error_precedence":34,"expected_first_error":"NONDETERMINISTIC_OUTPUT","expected_outcome":"QUARANTINE_TRANSACTION","label":"distinct attempts have different CJ parity"},{"expected_error_precedence":34,"expected_first_error":"NONDETERMINISTIC_OUTPUT","expected_outcome":"QUARANTINE_TRANSACTION","label":"distinct attempts differ in stable producer source runtime snapshot or output binding"}]},"ordinal":34,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-34"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES","mutation":{"kind":"MIXED_SUBCASES","values":[{"expected_error_precedence":35,"expected_first_error":"MALFORMED_MARKER","expected_outcome":"QUARANTINE_TRANSACTION","label":"malformed marker"},{"expected_error_precedence":35,"expected_first_error":"MARKER_JOIN_MISMATCH","expected_outcome":"QUARANTINE_TRANSACTION","label":"mismatched marker"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"pre-genesis malformed lock completes intent progress and coordination quarantine without transaction ID"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"incomplete transaction quarantine resumes from exact PREPARED intent and fixed ordinal progress paths"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ADOPT_COMMITTED","label":"valid marker with stale head"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ADOPT_COMMITTED","label":"valid marker with stale or malformed role lock is adopted before separate lock cleanup"}]},"ordinal":35,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-35"},
{"category":"TRANSPORT_SCHEMA","expected_error_precedence":36,"expected_first_error":"COMPLETION_JOIN","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["unmarked transaction evidence","marker without evidence","evidence without exact marker","candidate/evidence/marker equality join mismatch"]},"ordinal":36,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-36"},
{"category":"NATIVE_NO_SPAWN","expected_error_precedence":37,"expected_first_error":"WINDOWS_HOST_PROOF_REQUIRED","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["CreateProcessW flags missing","STARTF_USESTDHANDLES missing","hStdInput is not CONTROL_READ","hStdOutput is not STDOUT_WRITE","hStdError is not STDERR_WRITE","start gate or status handle not discovered from strict control payload","STATUS_WRITE is not child write-only","CapabilityCount nonzero","token readback missing","profile root identity missing","profile DACL executable or importable","profile cleanup failure not quarantined","five-handle inherited allowlist differs","OS-created child handle counted as inherited","Job assignment missing","child creation not denied","host receipt omits input-snapshot binding","host receipt binds different snapshot or candidate set","host receipt omits candidate-payload physical root","host receipt omits physical-member bijection","host receipt omits snapshot entry-name validation","host receipt omits role-readable member view","host receipt omits bootstrap protocol contract","role-readable view lists the selected or a peer producer source","selected-source canonical raw case link or alias access succeeds","peer-source canonical open or raw read succeeds","peer-source case link or alias read succeeds","producer-source handle is inherited","runtime bundle contains producer source path or same-content alias","snapshot tree ACL grants unexpected write or execute"]},"ordinal":37,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-37"},
{"category":"NATIVE_NO_SPAWN","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES","mutation":{"kind":"MIXED_SUBCASES","values":[{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ACCEPT","label":"pinned localhost may resolve with zero DNS packets while every resolved-address socket fails and the fresh bypass-cache external name does not resolve, the observer records zero outbound DNS packets, and every external socket fails"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"IPv4 TCP succeeds"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"IPv4 UDP succeeds"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"IPv6 TCP succeeds"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"IPv6 UDP succeeds"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"loopback socket succeeds"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"localhost resolved-address socket succeeds"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"private socket succeeds"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"public socket succeeds"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"localhost emits DNS packet"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"fresh bypass-cache external name resolves"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"fresh external-name DNS packet observed"},{"expected_error_precedence":38,"expected_first_error":"WINDOWS_NETWORK_PROOF","expected_outcome":"REJECT","label":"fresh external-address socket succeeds"}]},"ordinal":38,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-38"},
{"category":"NATIVE_NO_SPAWN","expected_error_precedence":39,"expected_first_error":"ISOLATION_UNAVAILABLE_OS","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["select Windows without accepted host receipt","select Linux without accepted host receipt","select macOS without accepted host receipt"]},"ordinal":39,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-39"},
{"category":"NATIVE_NO_SPAWN","expected_error_precedence":40,"expected_first_error":"DORMANT_BACKEND_FORBIDDEN","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["v2 source contains os.fork","v2 source contains dormant Linux executor","v2 source contains dormant macOS executor","v2 source contains callable unaccepted backend"]},"ordinal":40,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-40"},
{"category":"HISTORY","expected_error_precedence":41,"expected_first_error":"V1_IMMUTABLE","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["overwrite v1 source","overwrite v1 output","reinterpret v1 as v2","backfill red chronology from later fixture"]},"ordinal":41,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-41"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES","mutation":{"kind":"MIXED_SUBCASES","values":[{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash before transaction fixed locator publication performs no move"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"transaction locator durable before permanent ID intent resumes exact intent creation"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"transaction permanent intent durable before first move resumes from fixed locator"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"coordination ACTIVE locator durable before permanent ID intent resumes exact intent creation"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"coordination permanent intent durable before lock move resumes selected family"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash after move before both directory barriers resumes by exact destination identity"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash after barriers before progress publishes exact progress"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash after progress before COMPLETE resumes next ordinal or COMPLETE"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash after COMPLETE before locator retirement resumes retirement"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash after retirement staging before CAS resumes exact CAS"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash after locator CAS before history archive resumes exact archive"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash after locator history archive before barrier completes exact barrier"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"fixed transaction locator discovers a pre-genesis quarantine"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"fixed transaction locator discovers a post-genesis quarantine"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"later corrupt role lock selects revision plus one after prior RETIRED locator"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"distinct new lock at source and exact old lock at destination resumes old family"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_ID_CYCLE","expected_outcome":"REJECT","label":"transaction locator path or bytes enter family ID preimage"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_INCOMPLETE_INTENT","expected_outcome":"REJECT","label":"locator points to an intent without embedding its complete parsed value"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_FAMILY_MISMATCH","expected_outcome":"REJECT","label":"locator family ID and embedded prepared intent disagree"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_ROLE_PATH_MISMATCH","expected_outcome":"REJECT","label":"role and fixed locator path disagree"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_TRAVERSAL","expected_outcome":"REJECT","label":"locator or derived path contains traversal or alternate spelling"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_REVISION_REUSE","expected_outcome":"REJECT","label":"same coordination locator revision is overwritten or reused"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_ABA","expected_outcome":"REJECT","label":"coordination locator is reset deleted or returned to an earlier body"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_PREDECESSOR_MISMATCH","expected_outcome":"REJECT","label":"locator predecessor digest or revision increment is wrong"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_CONCURRENT_CAS","expected_outcome":"REJECT","label":"two writers claim the same next locator revision"},{"expected_error_precedence":42,"expected_first_error":"QUARANTINE_RECOVERY_AMBIGUOUS","expected_outcome":"REJECT","label":"same old coordination lock identity exists at source and destination"},{"expected_error_precedence":42,"expected_first_error":"QUARANTINE_RECOVERY_AMBIGUOUS","expected_outcome":"REJECT","label":"old coordination lock identity exists at neither source nor destination"},{"expected_error_precedence":42,"expected_first_error":"DISCOVERY_FORBIDDEN","expected_outcome":"REJECT","label":"recovery scans globs probes suffixes or selects newest locator"},{"expected_error_precedence":42,"expected_first_error":"LOCATOR_RETIREMENT_MISMATCH","expected_outcome":"REJECT","label":"locator retirement omits or mismatches the selected family COMPLETE record"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"first transaction locator authority is fixed protected-root path plus exact CF content only"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"first durable progress binds the previously unbound permanent intent artifact identity"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"coordination writer holds one OFD lease through predecessor read exchange history install and both directory barriers"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"second writer blocks then re-reads the installed successor only after acquiring the OFD lease"},{"expected_error_precedence":42,"expected_first_error":"FIRST_ANCHOR_UNOBSERVABLE_IDENTITY","expected_outcome":"REJECT","label":"first locator or genesis head claims inode continuity before the file exists"},{"expected_error_precedence":42,"expected_first_error":"KERNEL_SERIALIZATION_VIOLATION","expected_outcome":"REJECT","label":"locator or capture head validates or exchanges without the role or operation OFD lease"},{"expected_error_precedence":42,"expected_first_error":"KERNEL_SERIALIZATION_VIOLATION","expected_outcome":"REJECT","label":"writer releases the lease before displaced-head history and both directory barriers are durable"},{"expected_error_precedence":42,"expected_first_error":"KERNEL_SERIALIZATION_VIOLATION","expected_outcome":"REJECT","label":"second writer continues from a predecessor observed before lock acquisition"},{"expected_error_precedence":42,"expected_first_error":"KERNEL_SERIALIZATION_VIOLATION","expected_outcome":"REJECT","label":"two writers publish distinct bodies for one next revision despite serialization"},{"expected_error_precedence":42,"expected_first_error":"SERIALIZATION_ANCHOR_TAMPER","expected_outcome":"REJECT","label":"fixed serialization anchor is replaced truncated renamed deleted or rebound to equal bytes on another inode"}]},"ordinal":42,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-42"},
{"category":"HANDLE_IO","expected_error_precedence":43,"expected_first_error":"QUARANTINE_IDENTITY_INVALID","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["regular descendant uses alternate relative-path spelling","directory descendant carries regular-file inode_content_identity","nonregular descendant carries regular-file inode_content_identity","descendant path has noncanonical native-component encoding or decodes to empty dot parent separator NUL device or reserved spelling","descendant rows are reordered or duplicate a path","tree manifest omits a directory ancestor","tree manifest omits or adds a native descendant","tree root is duplicated as a descendant row","POSIX symlink omits exact raw target bytes","Windows reparse or junction omits exact FSCTL_GET_REPARSE_POINT bytes","native metadata uses the wrong OS-tagged branch or omits a closed metadata member","native_metadata_sha256 preimage omits payload bytes or an included metadata field","tree manifest header row count order size or digest preimage differs","regular directory and nonregular branch identities are compared across branches","xattr row stores only a digest without exact raw name and value bytes","xattr value claims PRESENT but omits bytes or claims ABSENT with a value","xattr empty PRESENT value is collapsed into ABSENT","xattr sizing or read error is interpreted as empty or absent","xattr names are duplicate reordered contain NUL or use text collation","Linux POSIX ACL xattrs appear in both general xattrs and ACL slots","Linux ACL is text-rendered or normalized instead of preserving raw kernel xattr bytes","Linux access or default ACL slot omits its explicit absent or present tag","macOS ACL is rendered with acl_to_text or reorders native ACE ordinals","macOS ACL qualifier permission or flag source bytes are omitted from normalized ACE rows","POSIX metadata aggregate changes header xattr ACL order or length framing","symlink or nonregular metadata is collected path-only outside the serialization lease","before and after no-follow identities differ around fallback metadata capture","Windows security descriptor is represented by SDDL or a digest instead of raw BackupRead bytes","Windows self-relative security descriptor validation fails or is omitted","Windows EA rows are duplicate malformed reordered or omit raw flags and value bytes","Windows ADS rows include unnamed primary data or reorder unsigned UTF-16 code units","Windows ADS name has odd UTF-16LE byte count or an unsupported BackupRead stream ID appears","BackupRead ends early or reports unreadable requested metadata and is treated as complete","Windows metadata aggregate changes security EA ADS order or framing","native metadata capture profile substitutes an unreviewed collector source or API profile","metadata byte length or SHA-256 disagrees with decoded bytes"]},"ordinal":43,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-43"},
{"category":"NATIVE_NO_SPAWN","expected_error_precedence":44,"expected_first_error":"QUARANTINE_MOVE_UNSUPPORTED","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["pre-spawn quarantine pair roster omits one possible writable root","source and deterministic destination volume IDs differ","Linux rename returns EXDEV","Linux renameat2 omits RENAME_NOREPLACE or adds another flag","plain POSIX renameat is used as an asserted no-replace primitive","Windows FileRenameInfoEx uses any nonzero flag","Windows uses MoveFileEx copy delete delete-then-move or path-only rename","macOS lacks reviewed renameatx_np RENAME_EXCL volume support","move reopens source by pathname instead of retaining its handle","destination is discovered by scan or implementer suffix","source-directory durability barrier is missing or incomplete","destination-directory durability barrier is missing or incomplete","required Windows volume durability barrier is missing or inferred from a rename flag","recovery reacquires a root handle with different root volume or file identity","Linux source and destination STATX_MNT_ID differ even when st_dev is equal","Linux source and destination st_dev differ even when mount ID spelling is equal","Linux staged regular file is renamed before file fsync","Linux staged tree omits bottom-up fsync of one directory","Linux move publishes progress before both retained parent directory FDs are fsynced","Linux one-directory barrier is reused when retained parent FDs identify different directories","Linux head transition claims kernel CAS instead of lease-serialized validate then RENAME_EXCHANGE","Windows FileRenameInfoEx is paired with a buffer type other than FILE_RENAME_INFO","Windows process-crash capability is accepted as power-loss-durable authority","Windows payload FlushFileBuffers is treated as a parent-directory namespace barrier","Windows MoveFileEx MOVEFILE_WRITE_THROUGH ReplaceFileW admin volume flush or receipt boolean authorizes COMMITTED","Windows capability publishes MOVE_DURABLE despite unavailable ordinary-user namespace barrier","macOS renameatx_np RENAME_EXCL or regular-file F_FULLFSYNC is accepted as directory power-loss durability","macOS empirical power-cut fixture or API probe enables spawn","non-Linux profile enters the accepting quarantine_move_profile union","platform capability records accepting_authority true while authority ceiling is all false","Windows FILE_RENAME_INFO allocation stops at FileName offset plus FileNameLength or omits the explicit zero terminator alignment tail","Windows SetFileInformationByHandle success is trusted without exact-leaf reopen source absence and FILE_ID_INFO equality"]},"ordinal":44,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-44"},
{"category":"TRANSPORT_SCHEMA","expected_error_precedence":45,"expected_first_error":"VECTOR_SOURCE_PROCESS_BINDING","green_expectation":"PASS_EXPECTED_REJECTION","mutation":{"kind":"SUBCASES","values":["fourth capture uses a different bootstrap source","fourth capture omits or substitutes the bootstrap independent review","fourth capture argv is not the exact six-item reviewed-bootstrap argv","raw capture source is substituted after parent retained-handle validation","source frame length digest or EOF differs","bootstrap compiles bytes other than the delivered source frame","compile filename differs from parent-resolved source absolute path","one recursive code object has a different co_filename","globals __name__ or __file__ sys.argv cwd or environment differs","status is missing malformed late or not bound before gate","actual executable handle PID or process-start identity differs","compiled marshal bytes or code-object projection differs","gate authorization run ID status or process join differs","output framing contract or source_to_process_join_sha256 differs","implementation review omits the distinct vector_capture_source subject","vector_capture_source and launcher subjects do not equal the exact section-2 capture source identity","bootstrap source review lacks VECTOR_CAPTURE_V1 in reviewed_modes","non-bootstrap source review claims VECTOR_CAPTURE_V1 mode","control payload contains capture run ID candidate receipt completion or run paths","capture operation ID preimage includes a run-derived path","child status contains its own status-frame identity parent status binding or run ID","child status contains candidate receipt completion or parent-observed executable handle","control status or gate payload contains the identity of its own frame","control payload is substituted while a copied frame digest is retained","source length prefix raw bytes frame identity or exact EOF is substituted","STATUS_WRITE contains trailing bytes or a second frame","parent accepts a child-supplied status binding instead of constructing and persisting it","run ID is computed before durable status binding","run ID preimage includes candidate receipt completion or the run ID itself","run final paths are derived before the authenticated run ID exists","run authorization omits exact run paths or binds paths for another run ID","gate frame magic u64 length canonical payload or EOF differs","operation paths and run paths are merged into one permissive path object","status control source bootstrap compiled-code process or executable equality predicate is false"]},"ordinal":45,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-45"},
{"category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES","mutation":{"kind":"MIXED_SUBCASES","values":[{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"crash before capture intent create performs no spawn"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_INTENT_PARTIAL","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"crash leaves malformed partial fixed capture intent"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"intent file durable before parent-directory barrier completes barrier"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"attempt record durable before containment construction resumes the exact attempt"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"crash after process create before control completes quarantines without replay after contained kill and reap"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"crash after source or status before gate quarantines without replay after contained kill and reap"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"crash after gate before stdout EOF quarantines without replay after contained kill and reap"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"crash during stdout spool write quarantines without replay after contained kill and reap"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"stdout spool durable before observation quarantines without replay after contained kill and reap"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"observation partial or nondurable quarantines after contained kill reap and complete move"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"durable observation before candidate parse resumes without respawn"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"fault before or after candidate stage create or each candidate write resumes exact stage"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"fault before or after candidate file fsync or each of three reads resumes validation"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"candidate staged event durable before final rename resumes exact inode move"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"candidate rename succeeds before source and destination directory barriers resumes by staged inode at destination"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"candidate published before receipt stage resumes receipt from observation"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"fault before or after receipt stage create or each receipt write resumes exact stage"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"fault before or after receipt file fsync or each of three reads resumes validation"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"receipt staged event durable before final rename resumes exact inode move"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"receipt rename succeeds before source and destination directory barriers resumes by staged inode at destination"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"receipt published before completion stage resumes marker construction"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"fault before or after completion stage create or each marker write resumes exact stage"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"fault before or after completion file fsync or each of three reads resumes validation"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"completion staged event durable before final rename resumes exact inode move"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ADOPT_VECTOR_CAPTURE","label":"completion marker rename succeeds then API reports an error"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ADOPT_VECTOR_CAPTURE","label":"completion marker is valid but destination-directory barrier failed"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ADOPT_VECTOR_CAPTURE","label":"valid completion marker exists with stale capture head or cleanup"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_PREOBSERVATION_UNREPLAYABLE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"pre-observation crash is offered a purity proof or replay authorization"},{"expected_error_precedence":46,"expected_first_error":"ATTEMPT_ORDINAL_INVALID","expected_outcome":"REJECT","label":"attempt ordinal one or any retry exhaustion state is supplied"},{"expected_error_precedence":46,"expected_first_error":"UNJOURNALED_CANDIDATE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"equal-content candidate final lacks the exact staged-inode event"},{"expected_error_precedence":46,"expected_first_error":"UNJOURNALED_RECEIPT","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"equal-content receipt final lacks the exact staged-inode event"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_BACKFILL_OR_SCAN_FORBIDDEN","expected_outcome":"REJECT","label":"recovery scans selects newest or backfills observation receipt or marker from loose files"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"INTENT_DURABLE to ATTEMPT_PREPARED is exact adjacent legal edge 1 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"ATTEMPT_PREPARED to CONTAINMENT_READY is exact adjacent legal edge 2 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"CONTAINMENT_READY to SPAWN_ARMED is exact adjacent legal edge 3 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"SPAWN_ARMED to STATUS_BOUND is exact adjacent legal edge 4 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"STATUS_BOUND to CHILD_OBSERVED is exact adjacent legal edge 5 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"CHILD_OBSERVED to CANDIDATE_STAGED is exact adjacent legal edge 6 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"CANDIDATE_STAGED to CANDIDATE_PUBLISHED is exact adjacent legal edge 7 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"CANDIDATE_PUBLISHED to RECEIPT_STAGED is exact adjacent legal edge 8 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"RECEIPT_STAGED to RECEIPT_PUBLISHED is exact adjacent legal edge 9 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"RECEIPT_PUBLISHED to COMPLETION_STAGED is exact adjacent legal edge 10 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ADOPT_VECTOR_CAPTURE","label":"COMPLETION_STAGED to COMMITTED is exact adjacent legal edge 11 of 12"},{"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"ADOPT_VECTOR_CAPTURE","label":"COMMITTED to ADOPTED is exact adjacent legal edge 12 of 12"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"INTENT_DURABLE to QUARANTINED is exact quarantine edge 1 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"ATTEMPT_PREPARED to QUARANTINED is exact quarantine edge 2 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"CONTAINMENT_READY to QUARANTINED is exact quarantine edge 3 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"SPAWN_ARMED to QUARANTINED is exact quarantine edge 4 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"STATUS_BOUND to QUARANTINED is exact quarantine edge 5 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"CHILD_OBSERVED to QUARANTINED is exact quarantine edge 6 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"CANDIDATE_STAGED to QUARANTINED is exact quarantine edge 7 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"CANDIDATE_PUBLISHED to QUARANTINED is exact quarantine edge 8 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"RECEIPT_STAGED to QUARANTINED is exact quarantine edge 9 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"RECEIPT_PUBLISHED to QUARANTINED is exact quarantine edge 10 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"COMPLETION_STAGED to QUARANTINED is exact quarantine edge 11 of 11 and preserves its 17-slot prefix"},{"expected_error_precedence":46,"expected_first_error":"STATE_EDGE_ILLEGAL","expected_outcome":"REJECT","label":"canonical 14-by-14 ordered-pair enumeration rejects the full 173-pair complement of the 12 adjacent and 11 quarantine edges"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"INTENT_DURABLE exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"ATTEMPT_PREPARED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"CONTAINMENT_READY exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"SPAWN_ARMED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"STATUS_BOUND exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"CHILD_OBSERVED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"CANDIDATE_STAGED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"CANDIDATE_PUBLISHED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"RECEIPT_STAGED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"RECEIPT_PUBLISHED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"COMPLETION_STAGED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"COMMITTED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"ADOPTED exact 17-slot matrix row differs at any enumerated position"},{"expected_error_precedence":46,"expected_first_error":"STATE_ARTIFACT_MATRIX","expected_outcome":"REJECT","label":"one of eleven QUARANTINED source-prefix rows differs or completion final is present"},{"expected_error_precedence":46,"expected_first_error":"RUN_PATH_STATE_MISMATCH","expected_outcome":"REJECT","label":"run paths appear before STATUS_BOUND or are absent from a post-status state"},{"expected_error_precedence":46,"expected_first_error":"STATE_EDGE_ILLEGAL","expected_outcome":"REJECT","label":"COMMITTED or ADOPTED transitions to QUARANTINED"},{"expected_error_precedence":46,"expected_first_error":"STATE_EDGE_ILLEGAL","expected_outcome":"REJECT","label":"a missing event is synthesized from a loose artifact"},{"expected_error_precedence":46,"expected_first_error":"SERIALIZATION_LEASE_MISSING","expected_outcome":"REJECT","label":"event or head transition releases or omits the operation OFD lease"},{"expected_error_precedence":46,"expected_first_error":"CONTROL_STATUS_SLOT_MISMATCH","expected_outcome":"REJECT","label":"STATUS_BOUND lacks current control status or run authorization artifacts"},{"expected_error_precedence":46,"expected_first_error":"PUBLISHED_INODE_MISMATCH","expected_outcome":"REJECT","label":"published final is current without the exact stage inode becoming predecessor"},{"expected_error_precedence":46,"expected_first_error":"TERMINAL_QUARANTINE_INCOMPLETE","expected_outcome":"REJECT","label":"terminal appears before exact quarantine COMPLETE artifact"},{"expected_error_precedence":46,"expected_first_error":"CONTAINMENT_SLOT_SUBSTITUTION","expected_outcome":"REJECT","label":"CONTAINMENT_READY containment-instance slot is absent old opaque cross-operation or substituted by spawn arm"},{"expected_error_precedence":46,"expected_first_error":"SPAWN_ARM_SLOT_SUBSTITUTION","expected_outcome":"REJECT","label":"SPAWN_ARMED spawn-arm slot is absent cross-operation or substituted by containment instance"}]},"ordinal":46,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-46"}
,{
  "category":"HANDLE_IO","expected_error_precedence":47,"expected_first_error":"CONTAINMENT_POLICY_IDENTITY","green_expectation":"PASS_EXPECTED_REJECTION",
  "mutation":{"kind":"SUBCASES","values":["substitute one immutable policy artifact with equal-length bytes","change one policy preimage then preserve the old artifact digest","change policy encoding kind without changing bytes","reorder accessible-root rows","add one writable root","omit one inherited-handle denial row","change one classic-BPF instruction word","change Landlock handled-access mask","change one mount bind from read-only to writable","change network namespace topology","reuse a cgroup path from another operation","bind cgroup instance to another operation ID","attach process after cgroup configuration observation","replace namespace observation with generic file identity","replace cgroup observation with untyped prose","omit post-operation instance","retain one process in cgroup.procs after kill","remove cgroup before the second empty observation","ordinary success root accepts the old vector_containment_observation object","ordinary success root carries typed containment only in an unjoined side object","ordinary success post-operation cgroup differs from the persisted containment instance","ordinary success post-operation process differs from the authenticated status process","ordinary success post-operation policy differs from the intent execution plan","mount root roster has fewer or more than exactly three rows","mount root roster adds an extra readable root","mount root roster makes input or operation-private output executable","mount root roster uses wrong fixed access noexec nodev or nosuid combination","Landlock reported ABI is below the exact minimum","Landlock global handled filesystem mask omits or adds a right","Landlock global handled network mask omits or adds a right","Landlock omits a scope or sets a quiet mask","Landlock per-root allowed mask differs from its exact constant","Landlock accepts best-effort rights or an empty network allow rule","seccomp verifier accepts an allow-all or default-allow program","seccomp verifier accepts an architecture fall-through or wrong audit architecture","seccomp verifier accepts an invalid jump unreachable instruction or nonzero action data","seccomp verifier accepts TRACE TRAP ERRNO LOG or USER_NOTIF","seccomp verifier semantic proof UAPI mapping or independent review is substituted","policy artifact filename does not equal the exact kind and architecture mapping","policy artifact ID formula or policy-set materialization row differs","native call stores only argument or result hashes without exact bytes","native call argument or result bytes do not decode to the typed projection","native call uses an opaque API reordered argument ABI ambiguity or nonzero padding","native call ID observation ID or observation-set formula differs","cgroup instance ID formula or delegated-root physical identity differs","post-operation ID formula or roster order differs","mount handle Landlock seccomp namespace or cgroup roster digest omits a row","success observation reaches vector_containment_observation in rendered defs","native signature roster omits adds reorders or substitutes one of the exact 22 rows","native prototype projection omits a required input output pointer buffer count or capacity relation","named UAPI struct size offset width endianness padding or initialized-field rule differs","nested sock_fprog clone_args or array pointer pointee recursion is absent or exceeds depth one","native result merges return errno and initialized output instead of capturing them separately","read pread64 readlinkat poll fstat statx or clone3 records an uninitialized output byte or stale suffix","seccomp UAPI mapping verifier or encoder region path role slice review or build-plan join differs","Landlock effective policy omits one of the three path-beneath rules","Landlock effective policy substitutes one rule while retaining a copied roster digest","Landlock effective rule order differs from root ordinal order","Landlock rule root ordinal kind selector or parent-fd role does not match its root row","Landlock root or rule roster digest excludes includes or differently frames a row","native FFI STATIC_ONLY or HOST_FIXTURE_EXECUTED state grants production execution","SDK header compiler static assertion or API probe presence is treated as executed host evidence","layout oracle author or reviewer is not independent from the production FFI implementer","host fixture uses a mock test-only helper alternate wrapper or binary instead of the exact production call path","return-status by observed-poststate classifier omits duplicates or aliases one of the exact twelve cells","errno or GetLastError is captured after another allocation log format reopen cleanup or API call","failure interrupted or crash status alone authorizes a retry without exact poststate reconciliation","native host fixture omits one call-boundary post-effect error-capture poststate journal or barrier crash seam"]},
  "ordinal":47,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-47"
},
{
  "category":"HANDLE_IO","expected_error_precedence":48,"expected_first_error":"PATH_FAMILY_MISMATCH","green_expectation":"PASS_EXPECTED_REJECTION",
  "mutation":{"kind":"SUBCASES","values":["supply a static path under the revision family","supply a revision path under the static family","supply a quarantine path before quarantine ID derivation","supply a run path before run ID derivation","feed any derived family path into the operation-ID preimage","feed a run-family path into the run-ID preimage","use noncanonical decimal capture revision","reuse one revision stage path for another revision","use head history path with predecessor revision mismatch","place control record at status path","place authorization record at control path","use quarantine family from another operation","use quarantine path with another quarantine ID","use run path with another run ID","supply equal-content alias instead of derived path","add an unregistered path to any family"]},
  "ordinal":48,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-48"
},
{
  "category":"TRANSPORT_SCHEMA","expected_error_precedence":49,"expected_first_error":"PERSISTED_FRAME_ROOT_MISMATCH","green_expectation":"PASS_EXPECTED_REJECTION",
  "mutation":{"kind":"SUBCASES","values":["control record root is absent from transaction-root registry","status record root is absent from transaction-root registry","authorization record root is absent from transaction-root registry","persisted control root file bytes differ from CF root","persisted status root file bytes differ from CF root","persisted authorization root file bytes differ from CF root","control payload bytes differ from CF payload","control magic differs from PFG3VCT1","control u64 length differs from payload length","source u64 length or raw bytes differ from source identity","control stream contains trailing byte after source","status payload bytes differ from CF payload","status magic or u64 length differs","status stream contains trailing byte","gate payload bytes differ from CF authorization","gate magic or u64 length differs","gate stream contains trailing byte","record path or frame identity is substituted across operations"]},
  "ordinal":49,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-49"
},
{
  "category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES",
  "mutation":{"kind":"MIXED_SUBCASES","values":[
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_INTENT_MALFORMED","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"malformed bytes at the fixed intent path enter the headless pre-genesis quarantine family"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_EVENT_INVENTED","expected_outcome":"REJECT","label":"pre-genesis quarantine supplies an invented event"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_HEAD_INVENTED","expected_outcome":"REJECT","label":"pre-genesis quarantine supplies an invented head"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_TRANSACTION_ID_INVENTED","expected_outcome":"REJECT","label":"malformed intent bytes are parsed to invent a transaction-derived identity"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_OPERATION_BINDING","expected_outcome":"REJECT","label":"quarantine operation ID differs from independently recomputed expected operation ID"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_SOURCE_IDENTITY","expected_outcome":"REJECT","label":"quarantine source is selected by directory scan or content equality"},
    {"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"durable headless prepared record resumes its exact ordinal move"},
    {"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"destination exact and source absent resumes barriers and progress"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_MOVE_AMBIGUOUS","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"both source and destination exist or neither identity is exact"},
    {"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"complete move roster publishes headless COMPLETE then headless terminal"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_TERMINAL_INCOMPLETE","expected_outcome":"REJECT","label":"headless terminal appears before exact COMPLETE"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_RETRY_FORBIDDEN","expected_outcome":"REJECT","label":"headless terminal is used to recreate intent or spawn"},
    {"expected_error_precedence":50,"expected_first_error":"QUARANTINE_TYPE_SCOPE","expected_outcome":"REJECT","label":"a legacy non-vector quarantine root accepts vector_operation_private_tree_entry"},
    {"expected_error_precedence":50,"expected_first_error":"QUARANTINE_TYPE_SCOPE","expected_outcome":"REJECT","label":"a vector root expands or replaces the global legacy quarantine_entry_ref union"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_DESTINATION_METADATA","expected_outcome":"REJECT","label":"pre-genesis progress omits destination metadata before or after the rename"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_DESTINATION_METADATA","expected_outcome":"REJECT","label":"pre-genesis destination-before observation is not exact ENOENT at the planned parent and path"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_METADATA_CHANGED","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"destination security xattr ACL EA ADS reparse or pathless identity changes across the move"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_CROSS_ROOT","expected_outcome":"REJECT","label":"pre-genesis progress or COMPLETE refers to another prepared root or malformed-intent entry"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_DESTINATION_METADATA","expected_outcome":"REJECT","label":"destination parent or relative path changes between before and after observations"},
    {"expected_error_precedence":50,"expected_first_error":"PRE_GENESIS_COMPLETE_JOIN","expected_outcome":"REJECT","label":"pre-genesis COMPLETE omits the repeated malformed-intent entry or sole exact progress reference"}
  ]},"ordinal":50,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-50"
},
{
  "category":"RECOVERY","expected_error_precedence":null,"expected_first_error":null,"green_expectation":"PASS_CLOSED_SUBCASES",
  "mutation":{"kind":"MIXED_SUBCASES","values":[
    {"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"CONTAINMENT_READY durably precedes SPAWN_ARMED"},
    {"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"SPAWN_ARMED recovery classifies an interrupted clone3 as SPAWN_MAY_HAVE_OCCURRED"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_PID_FABRICATED","expected_outcome":"REJECT","label":"uncertain-spawn observation supplies a guessed PID process-start identity or pidfd"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_CGROUP_MISMATCH","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"uncertain-spawn cgroup differs from the durable operation-private instance"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_KILL_MISSING","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"cgroup.kill exact one-byte write evidence is absent"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_NOT_EMPTY","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"cgroup events remains populated or either cgroup.procs observation is nonempty"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_EMPTY_UNSTABLE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"two empty observations are not separated by the required poll barrier"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_HANDLE_LIVE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"a child pidfd pipe or writable-tree handle remains live before move"},
    {"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"kill and stable-empty proof permits fixed-artifact quarantine only"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_ARTIFACT_SCAN","expected_outcome":"REJECT","label":"recovery scans for possible child artifacts"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_ARTIFACT_SCOPE","expected_outcome":"REJECT","label":"recovery moves an artifact outside fixed parent paths or the exact operation-private tree"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_ARTIFACT_IDENTITY","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"fixed artifact move lacks no-follow source-or-destination identity"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_PRIVATE_TREE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"operation-private tree move lacks an intact-tree manifest and same-mount identity"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_EXTERNAL_SIDE_EFFECT","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"policy observation permits network writable host root or descendant process side effect"},
    {"expected_error_precedence":null,"expected_first_error":null,"expected_outcome":"RECOVERY_TRANSITION","label":"all fixed artifacts absent and private tree absent is a valid zero-artifact quarantine roster"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_ZERO_UNJUSTIFIED","expected_outcome":"REJECT","label":"zero-artifact result lacks typed containment and cgroup lifecycle evidence"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_REPLAY_FORBIDDEN","expected_outcome":"REJECT","label":"stable-empty proof is treated as replay authorization"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_RUN_PATH","expected_outcome":"REJECT","label":"uncertain spawn invents a run ID or run-family path before authenticated status"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_STATUS_BACKFILL","expected_outcome":"REJECT","label":"recovery synthesizes status or process identity from a partial pipe"},
    {"expected_error_precedence":51,"expected_first_error":"CAPTURE_TERMINAL_QUARANTINE","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"exact uncertain-spawn evidence and complete moves produce terminal QUARANTINED with no retry"},
    {"expected_error_precedence":51,"expected_first_error":"QUARANTINE_TYPE_SCOPE","expected_outcome":"REJECT","label":"ordinary vector quarantine uses legacy quarantine_entry_ref where vector_quarantine_entry_ref is required"},
    {"expected_error_precedence":51,"expected_first_error":"QUARANTINE_TYPE_SCOPE","expected_outcome":"REJECT","label":"operation-private tree move uses a legacy quarantine_move or leaks into a non-vector root"},
    {"expected_error_precedence":51,"expected_first_error":"VECTOR_QUARANTINE_METADATA_JOIN","expected_outcome":"QUARANTINE_VECTOR_CAPTURE","label":"vector quarantine destination before or after metadata does not join the planned vector move"},
    {"expected_error_precedence":51,"expected_first_error":"POST_OPERATION_BRANCH_MISMATCH","expected_outcome":"REJECT","label":"confirmed-process quarantine uses a generic post-operation union value instead of the confirmed branch"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_DIGEST","expected_outcome":"REJECT","label":"spawn-uncertainty observation digest includes itself or uses a copied digest"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_DIGEST","expected_outcome":"REJECT","label":"spawn-uncertainty observation digest omits or substitutes one body member"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_DIGEST","expected_outcome":"REJECT","label":"spawn-uncertainty observation digest uses the wrong domain or wrapper ordering"},
    {"expected_error_precedence":51,"expected_first_error":"SPAWN_UNCERTAINTY_DIGEST","expected_outcome":"REJECT","label":"spawn-uncertainty digest preimage omits one of kill_requested empty_first empty_second or post_operation"}
  ]},"ordinal":51,"red_expectation":"FAIL_FIRST_CANDIDATE","scenario_id":"LRC2-51"
}
]
```
<!-- END PARITY_SCENARIO_ROSTER_R3_5 -->

Every row has exactly `{category,expected_error_precedence,
expected_first_error,green_expectation,mutation,ordinal,red_expectation,
scenario_id}` in the schema. `mutation` is the closed tagged union
`{kind:"SINGLE",value}`, `{kind:"SUBCASES",values}`, or the closed
`{kind:"MIXED_SUBCASES",values}` whose rows carry exact per-subcase outcome,
nullable error precedence, and nullable first error. Listed subcases execute in
displayed order and the receipt records a result for each. Error precedence is
the ascending integer over active rejecting/faulting subcases only. Baseline
acceptance and an accepting/recovery subcase have null precedence and null first
error and never participate in an error comparison. A composed mutation sorts
active errors by `(expected_error_precedence,scenario ordinal,subcase ordinal)`;
the first tuple's exact error is first. Thus row 0 is not a precedence-0 error,
and rows 23, 32, 33, 34, 35, 38, 42, 46, 50, and 51 use only their per-subcase rules. Ordinals are 0-51, IDs are exact,
and the category enum is `BASELINE`, `STARTUP`, `RUNTIME_CLOSURE`,
`IMPORT_INDEPENDENCE`, `HANDLE_IO`, `TRANSPORT_SCHEMA`, `PARITY`,
`TRANSACTION`, `RECOVERY`, `NATIVE_NO_SPAWN`, or `HISTORY`. The manifest body
digest covers the exact parsed array. `CJ(scenarios)` is exactly 84,801 bytes
with SHA-256
`2eb301a01e60847b1ce096c04b4df086869b216219714be49a70b1b4352b19c5`;
the separate concatenated `CJ(row)||LF` stream is exactly 84,800 bytes with
SHA-256
`70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99`.
The single exact section-2 successor
harness executes exactly 52 top-level methods with zero setup errors and records
exactly 767 ordered subcases in both the red and green run.

The red receipt pins the scenario manifest, that successor harness,
the section-1 first candidate, amendment and receipt, the absolute ambient
interpreter plus its exact path-bearing handle/content projection,
implementation, version, ABI, and platform tags, exact six-string command and
argv digest, cwd, exact empty environment, every result, method
count 52, setup errors zero, and the exact 28-field
`V2_NONAUTHORITY_CAPABILITY_BITSET`. It is written after all 39 stable successor
inputs and their reviews exist but before any v2 launcher source byte. A missing v2 file in setup, a
count-only summary, or the prior zero-method/19-method records is insufficient.
The green receipt uses the same manifest and pins v2 bytes. Red failure is
chronology evidence only; green success is implementation evidence only.

## 11. Independent review schemas and procedures

The amendment receipt path is exactly:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_AMENDMENT_INDEPENDENT_REVIEW.v1.json
```

Its closed schema version is
`plamen.program_facts_g3_00_parity_launcher_runtime_closure_amendment_review.v1`
and it has exactly `{schema_version,review_id,subject,normative_parents,
candidate_inputs,reviewer,independence,checks,findings,open_findings,
disposition,accepted_scope,authority_ceiling,review_body_sha256}`.
`subject` is this amendment identity. `normative_parents` is exactly the first
two section-1 rows. `candidate_inputs` is exactly the remaining five rows in
table order. `independence` and `authority_ceiling` equal section 3.
`accepted_scope` is exactly `["G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_CONTRACT"]`.

`checks` contains exactly these 20 IDs, once and in order, each with
`{check_id,result,evidence}` and nonempty sorted unique file identities:

```text
G3LRC-R01-PREDECESSOR-PINS-AND-HISTORY
G3LRC-R02-IMMUTABLE-V1-ACYCLIC-V2
G3LRC-R03-STARTUP-INTERPRETER-RUNTIME-CLOSURE
G3LRC-R04-DEPENDENCY-ORIGIN-AND-PRODUCER-INDEPENDENCE
G3LRC-R05-PARITY-AND-EVIDENCE-BINDING
G3LRC-R06-DESCRIPTOR-HANDLE-STABLE-IO
G3LRC-R07-MARKER-LAST-TRANSACTION-RECOVERY
G3LRC-R08-EXACT-FIXTURE-FIRST-DENOMINATOR
G3LRC-R09-CLOSED-SCHEMAS-CANONICALIZATION-LIMITS
G3LRC-R10-NATIVE-NO-SPAWN-BOUNDARY
G3LRC-R11-REVIEW-INDEPENDENCE-AND-ADOPTION-DAG
G3LRC-R12-TRUST-AND-AUTHORITY-CEILING
G3LRC-R13-RUNTIME-BUILD-AND-SNAPSHOT-PAYLOAD-CLOSURE
G3LRC-R14-QUARANTINE-LOCATOR-AND-NATIVE-TRANSPORT
G3LRC-R15-AUTHENTICATED-FOURTH-CAPTURE-LIFECYCLE
G3LRC-R16-EXACT-NATIVE-METADATA-STREAMS
G3LRC-R17-CLOSED-CONTROL-STATUS-SOURCE-AND-PATH-BINDING
G3LRC-R18-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION
G3LRC-R19-NO-RETRY-STATE-ARTIFACT-TOTALITY
G3LRC-R20-PLATFORM-AUTHORITY-BOUNDARY
```

`findings` rows are closed
`{finding_id,severity,status,description,evidence}` with severity
`BLOCKING|NONBLOCKING` and status `OPEN|CLOSED`; `open_findings` is the exact
UTF-8-sorted projection of open IDs. Passing requires all checks `PASS`, no open
blocking finding, exact pins/bitsets/scope, strict schema validation, and
disposition
`PASS_G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_FOR_FIXTURE_AND_IMPLEMENTATION_ONLY`.
The only other disposition is `REJECTED`.

```text
review_id = "pfg3lrcr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_REVIEW_V1",
  review:(full receipt without review_id and review_body_sha256)
}))[0:32]
review_body_sha256 = SHA-256(CJ(full receipt without only review_body_sha256))
receipt file = CF(full receipt)
```

The reviewer performs three descriptor-bound reads of every input, validates
this receipt's in-memory Draft-2020-12 schema before the receipt, recomputes all
identities/IDs/digests/order/bitsets, checks the supplied `REPAIR` findings
against source and history without asserting a nonexistent review artifact, and
writes only this receipt. This document does not self-approve or create it.

The receipt reuses the accepted clarification's literal `file_identity`,
`reviewer`, and `finding` schemas without widening them. `review_id` matches
`^pfg3lrcr-[0-9a-f]{32}$`; reviewer `principal_id` matches
`^reviewer:[a-z0-9-]+/[a-z0-9-]+$`; `checks` has exactly 20 items and its ID
enum is the displayed roster; `normative_parents` and `candidate_inputs` are
literal constant arrays. Findings, open findings, and evidence arrays are
duplicate-free and bounded at 10,000,000 items. Authority, independence, scope,
schema version, and disposition are literal constants. No nullable or optional
field exists.

The later implementation review at the section-2 path uses schema version
`plamen.program_facts_g3_00_parity_launcher_v2_implementation_review.v1` and
the same closed reviewer/finding/identity mechanics. Its subjects are exactly
all section-4 schema identities, the 52-method harness, bootstrap, runtime
builder, generator/evaluator/cross-check sources and their five reviews, runtime
build plan/review, runtime manifest/review, scenario
manifest, complete red/green evidence, and v2 launcher source. Its exact checks are
`V2I-01-RED-CHRONOLOGY`, `V2I-02-SCHEMAS`, `V2I-03-RUNTIME-CLOSURE`,
`V2I-04-IMPORT-INDEPENDENCE`, `V2I-05-HANDLE-IO`,
`V2I-06-TRANSACTION-RECOVERY`, `V2I-07-PARITY`,
`V2I-08-NATIVE-NO-SPAWN`, `V2I-09-NONAUTHORITY`, and
`V2I-10-RUNTIME-BUILD-CHAIN`,
`V2I-11-QUARANTINE-LOCATOR-AND-NATIVE-TRANSPORT`, and
`V2I-12-AUTHENTICATED-FOURTH-CAPTURE-LIFECYCLE`,
`V2I-13-EXACT-NATIVE-METADATA-STREAMS`,
`V2I-14-CONTROL-STATUS-SOURCE-AND-PATH-BINDING`,
`V2I-15-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION`,
`V2I-16-NO-RETRY-STATE-ARTIFACT-TOTALITY`, and
`V2I-17-PLATFORM-AUTHORITY-BOUNDARY`. Its subjects separately name and compare
the exact vector-capture source even when it equals the launcher source. Its only passing
disposition is `PASS_G3_00_PARITY_LAUNCHER_V2_CONSTRUCTION_NO_SPAWN_ONLY` and
its authority ceiling is exactly the 28-field
`V2_NONAUTHORITY_CAPABILITY_BITSET`. It is not a host receipt,
process evidence, completion marker, or activation permit.

## 12. Implementation checklist and reproducible acceptance

Implementation occurs only after the amendment receipt passes, in this order:

1. render every section-4/14 closed schema and schema-negative fixture from the
   accepted amendment/receipt; no v1 schema or artifact changes;
2. author the transport-only bootstrap, deterministic runtime builder, and
   exact generator/evaluator/cross-check source bytes without a review dependency;
3. obtain five independent pre-manifest source-semantics reviews. Each reviewer
   is separate from all five authors and reviews only its subject plus the
   amendment/receipt and already rendered schemas, never a build plan, manifest,
   or closure review;
4. create the closed runtime build-plan/lock from exact offline CPython/wheel/
   toolchain inputs, obtain its independent review, then deterministically
   construct and seal the private read-only CPython 3.12.10 bundle. The bundle
   contains the bootstrap and six distributions but no producer source or
   same-content/path alias; no runtime manifest yet exists;
5. only now derive static, literal-dynamic, package/lazy import paths and
   producer exclusions against the existing bundle, create the nested import
   inventory, write the runtime manifest, and obtain its independent closure
   review. The closure reviewer recomputes every bundle/origin difference;
6. create and independently validate the 52-row scenario manifest and exact
   section-2 harness, then run the exact RED receipt against the pinned v1
   launcher with the ordered 39 successor inputs. No v2 launcher byte exists;
7. implement the no-spawn v2 launcher around those reviewed inputs; duplicate no
   producer algorithm and include no dormant native implementation;
8. implement descriptor/handle-bound readers, exact identity/root/link checks,
   deterministic journal, private transaction evidence, marker-last commit, and
   recovery before enabling any dispatch;
9. run schema/unit/fault-injection GREEN fixtures over the same 52 scenarios and
   ordered 39 inputs on each
   claimed filesystem profile. The no-spawn dispatcher is the only passing
   platform behavior at this stage;
10. obtain the no-spawn implementation review; it must include the bootstrap
   source/review, runtime-builder source/review and build pair, and all three
   producer source/review identities;
11. through a separate accepted materialization amendment, seal the complete
    closed predecessor set into one immutable base-input synthetic repository.
    Authenticate its manifest, logical member digest, physical root, canonical
    source paths, and retained-handle epoch before any vector capture;
12. run the distinct non-authoritative vector-bundle capture only from that
    base snapshot and emit the exact `PFG3VBC1` framed private logical output
    containing exactly 12 candidate vector payloads. The trusted parent persists
    the closed candidate and parent-authored run receipt at their exact paths,
    then publishes the private vector-capture completion marker last.  The
    capture emits no tree, snapshot member, parity completion marker, accepted
    vector, review, or G2 promotion marker; the accepted materializer alone
    validates the completion/candidate/receipt/observation chain, binds its projection into the candidate-set
    manifest, and constructs the exact immutable candidate-payload tree;
13. materialize a new immutable derived G1 vector snapshot from the unchanged base
    plus that exact payload using the closed logical disjoint-union rule,
    preserving every canonical repository path while exclusively creating and
    freshly observing every derived physical member with `nlink:1` and no
    source file-ID reuse;
14. separately construct and host-validate one native backend, validate the
    already immutable runtime/system-loader manifest (never construct a second
    runtime), exact native entry-name enumeration, each role-specific
    readable-member/selected-plus-two-peer denial view, adversarial network/process/filesystem
    matrix, and host receipt, then run generator, evaluator, and cross-check
    only from that same derived snapshot. A different
    OS/build/architecture/filesystem is a different native review and envelope;
    and
15. after all three valid v2 completion chains exist, create and independently
    validate the exact section-6.1 pre-aggregate lineage mapping, including the
    GREEN crosscheck-v2 successor chain. Then, only through later separately
    accepted generation/promotion work, build one staged append-only G2
    `schema_contracts` root containing exactly the 12
    vector files, their 12 per-schema reviews, and a non-self-referential
    promotion marker; create-only atomically promote that whole root, making the
    already present marker effective at the rename linearization point; only
    afterward author the live aggregate manifest and its independent aggregate
    review. Every per-schema and aggregate review consumes the already completed
    lineage mapping and all three v2 evidence/completion pairs; it does not wait
    for G3-01. A later G3-01 adoption amendment consumes that lineage together
    with the effective promotion marker and live aggregate pair for downstream
    consumers. No review silently
    substitutes a v2 pair for a v1 single file identity, and neither snapshot is
    mutated.

An independent reproducer accepts the construction only if all of the following
are true:

- all section-1 pins and the amendment receipt validate from three retained-
  handle reads; the original red remains classified as zero-method invalid
  chronology and the 19-method red remains partial non-authority;
- the scenario manifest has exactly 52 ordered rows, the red receipt shows 52
  executed methods and zero setup errors before v2 launcher bytes, and the unchanged
  scenarios all pass after repair;
- all 25 section-4 schemas are closed, every canonical/duplicate/number/size negative
  fails, and all identities/IDs/body hashes recompute exactly;
- the runtime builder/build-plan/review and complete private bundle bind exact
  offline archive/toolchain/output identities; distribution/module/RECORD sets
  compare equal in both directions; producer-source path/alias/content
  intersections are empty; all imports resolve to exact allowed origins; and
  producer cross-import/shared-algorithm mutations fail;
- parent-bound interpreter/source/runtime identity precedes spawn, child
  observation matches; the strict CONTROL/source/STATUS/five-handle/gate
  protocol and EOFs validate; compile filename, every recursive `co_filename`,
  `__file__`, one-item argv, cwd, and snapshot root join exactly; and a
  child-only attestation fails;
- every security-relevant file passes the one-handle three-read/root/link/path-
  identity epoch; the ASCII entry roster/native spelling/directory-prefix sets
  and complete logical/physical base/payload/derived member bijections are
  exact; the vector candidate/receipt frame and base/source/run/payload joins are
  exact; the derived G1 logical tree is the disjoint G0-plus-12-payload union,
  while every derived physical member is newly created/observed, single-link,
  and file-ID-distinct from its sources; and every
  collision, extra/nonregular entry, mount/volume escape,
  unsupported profile, symlink/reparse/hardlink/replacement mutation fails;
- each host receipt proves the exact role-readable projection and OS-level
  canonical/raw/alias/inherited-handle denial for the selected and both peer
  producer sources, so the selected raw bytes enter the child only through the
  CONTROL_READ frame;
- every pre-marker fault leaves no completion marker, every valid ambiguous
  post-publication marker recovers as committed, no validation seam follows the
  marker, `CHILD_COMPLETE` precedes candidate staging, a candidate without a
  durable native-image receipt is never resumed, same-attempt raw and
  cross-attempt semantic retry comparisons are exact, transaction and
  coordination-lock quarantine are acyclic/separate, role-lock release crash
  seams reconcile, and exact fsync/durability-barrier seams behave as section 9;
  - the three `CJ(parity)` values are byte-identical and exactly preserve v1 while
  all three executions join one derived snapshot/candidate set and all outer
   host-specific execution/provenance bindings independently validate; the
   pre-aggregate lineage maps the accepted v1 role requirements to all three
   exact v2 completion/evidence pairs and explicitly binds the GREEN
   crosscheck-v2 source/review/launcher/runtime/implementation chain before any
   per-schema or aggregate review; and
- the implementation review passes only for no-spawn construction. Without a
  separate accepted native-host receipt and later adoption amendment, every
  public dispatch still fails before process creation and no completion marker
  can be created.

## 13. Adoption timing, non-authority, and unresolved host risks

This amendment is Part-0/generic: it fixes algorithms, artifact types, bounds,
orders, identities, and fail-closed choices without asserting a repository-
local absolute runtime path or portable OS proof. Exact absolute interpreter,
bundle, System32/system-library, OS build, architecture, filesystem, token or
namespace, and native receipt identities are necessarily future host-reviewed
values. Their absence is a blocker, not a placeholder or permission to choose
ambient state.

No current-host export observation is an authority input. The Windows baseline
is the documented classic `CreateProcessW` construction in section 8 and fails
closed unless the later exact host receipt proves every required API/semantic.
Microsoft's separately documented `CreateProcessInSandbox` API is experimental,
Windows-11-specific, exported by `processmodel.dll`, and has no public header;
it is therefore an optional future host capability, never this contract's
baseline, and this amendment makes no availability or absence claim about it.
The current ambient interpreter and installed packages are not the private runtime closure.
The current launcher maps three canonical producer paths that do not all exist;
no producer may be spawned until reviewed successor sources and identities do.
Linux relocatability, Windows system-image closure, macOS signing/sandboxing,
kernel/loader compromise, crash durability on an unsupported filesystem, and
the trusting-trust problem remain explicit risks outside this construction
contract.

Python's isolated/no-site/no-bytecode behavior and Windows path configuration
are design-grounded in the CPython 3.12 command-line and Windows documentation.
The conditional Windows boundary is design-grounded in Microsoft's
AppContainer isolation and classic AppContainer-launch documentation. Those
documents inform the contract; they are not local host execution evidence and
do not grant authority.

The primary design references are
`https://docs.python.org/3.12/using/cmdline.html`,
`https://docs.python.org/3.12/using/windows.html`,
`https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation`,
`https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer`,
`https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera`,
`https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/manage-the-component-store?view=windows-11`,
`https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info`,
and
`https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox`.

A passing amendment receipt permits only fixture and no-spawn implementation.
A passing closure or implementation review permits no process creation. A
future host receipt permits only that exact host isolation claim. None alone or
together authorizes schema/vector admission, runtime use, provider/audit launch,
package/release, production publication, active-head update, consumer use,
finding/severity/confidence/refutation/suppression, clean certification,
terminal-negative claims, install, commit, push, or cutover. Those authorities
remain false until a later independently reviewed adoption contract explicitly
consumes all completed predecessors.

A passing pre-aggregate lineage permits only the already accepted
clarification's parity requirement to be reviewed through the exact mapped v2
completion/evidence chains. It is not a vector or aggregate acceptance and does
not activate any authority bit.

That later promotion is a new append-only generation, not an update of either
capture snapshot. One staged G2 `schema_contracts` root must contain exactly 12
candidate vector files, exactly 12 corresponding per-schema reviews, and its
non-self-referential promotion marker. A create-only atomic root rename promotes
that whole tree; the already present marker becomes effective at that rename's
linearization point. Only after those live canonical vector/review/marker
triplets exist may the live aggregate manifest be authored and its independent
aggregate review follow. Before those per-schema/aggregate reviews, the exact
section-6.1 pre-aggregate lineage must already map the generator, evaluator,
and cross-check v2 completion/evidence chains to the accepted v1 requirement
projections and bind the GREEN crosscheck-v2 successor. G3-01 adoption is a
still later amendment that consumes, rather than creates, that mapping together
with the effective promotion marker and live aggregate manifest/review pair.
No base-snapshot, candidate-set, derived-snapshot, lineage instance,
staged-generation, aggregate, promotion-marker, or G3-01 adoption identity is
instantiated by this amendment, and every launcher
authority bit remains false.

## 14. Mechanical Draft-2020-12 schema construction

This section is normative. It closes every schema named in section 4 without
depending on an ambient schema store. The renderer takes one row from the root
registry below and emits this exact parsed value, replacing the two metanames
`ROOT_ID` and `ROOT_DEF` before serialization. They are renderer inputs, never
strings in a rendered schema. `DEFS` is the complete expansion of the
declaration registry in sections 14.1-14.3. Every rendered file contains its own
copy; there is no external `$ref`.

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"ROOT_ID","$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/format-annotation":true,"https://json-schema.org/draft/2020-12/vocab/meta-data":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},"$ref":"#/$defs/ROOT_DEF","$defs":"DEFS"}
```

The quoted `"DEFS"` token is replaced by the object, not retained as a string.
The renderer then applies `CF`. No annotation, default, unknown vocabulary,
remote reference, optional property, or unevaluated fallback may be added.

The following declaration notation is a deterministic abbreviation for JSON
Schema and is used only to keep the inlined registry reviewable:

- `S(a,b,p)` expands to `{"type":"string","minLength":a,"maxLength":b,
  "pattern":p}`; omit `p` only where displayed as `-`.
- `I(a,b)` expands to the analogous bounded integer schema; `B`, `N`, `C(x)`,
  and `E(x,...)` expand respectively to boolean, null, `{"const":x}`, and a
  string enum in displayed order.
- `R(n)` expands to `{"$ref":"#/$defs/n"}`. `Q(T)` expands to a two-branch
  `oneOf` containing `T` and `N`, in that order.
- `A(T,a,b,u)` expands to an array with `items:T`, exact `minItems:a`,
  `maxItems:b`, and `uniqueItems:u`.
- `T(T1,...,Tn)` expands to an array with `prefixItems:[T1,...,Tn]`,
  `items:false`, `minItems:n`, and `maxItems:n`.
- `O(k1:T1,...,kn:Tn)` expands to an object with `type:"object"`,
  `additionalProperties:false`, `properties` containing exactly the displayed
  members, and `required:[k1,...,kn]`. Thus every displayed field is required.
- `U(T1,...,Tn)` expands to `oneOf` in displayed order. `AND(T1,...,Tn)`
  expands to `allOf`. A displayed `if/then` is copied literally.

`S0=S(0,16384,-)`, `S1=S(1,16384,-)`, `PATH=S(1,4096,
"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$")`,
`ABS=S(1,4096,"^(?:[A-Za-z]:\\\\|/).+")`, `HEX=S(64,64,
"^[0-9a-f]{64}$")`, `ID=S(1,512,"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$")`,
`APATH=AND(PATH,S(1,4096,"^[A-Za-z0-9._/-]+$"))`, and
`SAFE=I(-9007199254740991,9007199254740991)`. Regexes are the parsed JSON
strings shown; the renderer performs no second escape pass. Unless another
bound is displayed, no string or array is permitted. Every `A` whose values
have a declared key is also rejected by the semantic validator if keys repeat
or the declared order is wrong; JSON Schema `uniqueItems` is necessary but not
sufficient.

### 14.1 Complete shared `$defs`

The following are the exact shared definitions. A colon introduces the schema
expression on the rest of that paragraph.

`file_identity`:
`O(path:PATH,size_bytes:I(0,9007199254740991),sha256:HEX)`.

`snapshot_file_identity`:
`O(path:APATH,size_bytes:I(0,9007199254740991),sha256:HEX)`.

`content_identity`:
`O(size_bytes:I(0,9007199254740991),sha256:HEX)`.

`inode_content_identity`:
`O(volume_id:S1,file_id:S1,nlink:I(1,9007199254740991),
size_bytes:I(0,9007199254740991),sha256:HEX)`. It deliberately excludes every
path/root spelling and is the only identity compared across a rename.

`handle_identity`:
`O(root_id:ID,path:S(1,4096,-),kind:C("REGULAR_FILE"),
volume_id:S1,file_id:S1,nlink:I(1,9007199254740991),
size_bytes:I(0,9007199254740991),sha256:HEX)`. It has the exact content
size/digest and `nlink:1`, except only a reviewed Windows `system_image` row may
use its recorded larger value. Its `inode_content_identity` projection is
verbatim `{volume_id,file_id,nlink,size_bytes,sha256}` and its
`content_identity` projection is verbatim `{size_bytes,sha256}`.

`snapshot_physical_member`:
`O(logical:R(snapshot_file_identity),physical:R(handle_identity))`. The
physical row's path equals `logical.path`, its size/hash equal the logical row,
and its root ID equals the root selected by the containing snapshot/payload.

`file_locator`:
`O(root_id:ID,path:S(1,4096,-),kind:C("REGULAR_FILE"),volume_id:S1,
file_id:S1,nlink:I(1,9007199254740991))`. It deliberately has no size or hash
and is used only when an object is stored inside the file it locates.

`directory_locator`:
`O(root_id:ID,path:S(1,4096,-),volume_id:S1,file_id:S1,owner:S1,
access_policy:HEX)`.

`directory_inode_identity`:
`O(volume_id:S1,file_id:S1,owner:S1,access_policy:HEX)`. It excludes path and
root spelling and is used only to join the same directory across a quarantine
rename.

`immutable_directory_identity`:
`O(locator:R(directory_locator),descendant_count:I(1,20000),
descendant_manifest_sha256:HEX)`. For a sealed tree, the descendant digest is
SHA-256 of `CJ(physical_member.physical)||0x0a` for the complete array sorted by
the path inside that path-bearing handle identity; `descendant_count` equals
the array length. It is never computed from logical rows alone.

`input_snapshot_policy`:
`O(kind:C("IMMUTABLE_SYNTHETIC_REPOSITORY_SNAPSHOT_V1"),
canonical_layout_required:C(true),live_repository_execution:C(false),
private_candidate_set_only:C(true),materialization_status:C(
"REQUIRES_SEPARATE_ACCEPTED_MATERIALIZATION_AMENDMENT"))`.

`base_snapshot_directory_locator`:
`O(root_id:C("BASE_INPUT_SNAPSHOT"),path:C("."),volume_id:S1,file_id:S1,
owner:S1,access_policy:HEX)`.

`base_input_snapshot_root`:
`O(locator:R(base_snapshot_directory_locator),descendant_count:I(1,20000),
descendant_manifest_sha256:HEX)`.

`base_input_snapshot_manifest`:
`O(schema_version:C("plamen.program_facts_parity_base_input_snapshot.v1"),
base_snapshot_id:S(39,39,"^pfg3bs-[0-9a-f]{32}$"),
kind:C("IMMUTABLE_SYNTHETIC_REPOSITORY_BASE_SNAPSHOT_V1"),
file_members:A(R(snapshot_file_identity),1,20000,true),
physical_members:A(R(snapshot_physical_member),1,20000,true),
target_vector_paths_absent:C(true),logical_content_sha256:HEX,
absolute_root:ABS,physical_root:R(base_input_snapshot_root),
vector_bundle_source:R(snapshot_file_identity),canonical_file_member_count:I(1,20000),
materialization_disposition:C("PRIVATE_NONAUTHORITY_BASE_SNAPSHOT_ONLY"),
accepted_scope:C(["IMMUTABLE_VECTOR_BUNDLE_INPUT_ONLY"]),
authority_ceiling:R(authority_v2),base_snapshot_body_sha256:HEX)`.

`base_input_snapshot_binding`:
`O(identity:R(file_identity),manifest:R(base_input_snapshot_manifest))`.

`base_input_snapshot_projection`:
`O(identity:R(file_identity),base_snapshot_id:S(39,39,
"^pfg3bs-[0-9a-f]{32}$"),base_snapshot_body_sha256:HEX,
logical_content_sha256:HEX,absolute_root:ABS,
physical_root:R(base_input_snapshot_root))`.

`vector_bundle_payload`:
`O(path:APATH,size_bytes:I(1,16777216),sha256:HEX,
encoding:C("UTF8_CF_INLINE_STRING_V1"),cf_utf8:S(1,16777216,-))`.

`vector_bundle_payload_projection`:
`O(path:APATH,size_bytes:I(1,16777216),sha256:HEX)`.

`vector_capture_source_binding`:
`O(logical:R(snapshot_file_identity),physical:R(handle_identity),
absolute_path:ABS,parent_resolved:C(true),child_lexical_path:ABS,
child_parent_depth:C(3),child_lexical_root:ABS,
content_reopen_count:C(0),metadata_reopen_count:C(0))`.

`vector_capture_run_binding`:
`O(backend_id:S1,interpreter:R(execution_interpreter),
argv:A(S1,1,16,false),cwd:ABS,environment:C({}),
protocol_magic:C("PFG3VBC1"),length_encoding:C("U64_BIG_ENDIAN"),
candidate_max_bytes:C(16777216),framed_stdout:R(content_identity),
frame_sha256:HEX,
stderr:C({"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size_bytes":0}),
exit_code:C(0),process_tree_zero:C(true))`.

`vector_bundle_output_projection`:
`O(identity:R(file_identity),vector_bundle_id:S(39,39,
"^pfg3vb-[0-9a-f]{32}$"),vector_bundle_body_sha256:HEX,
framed_stdout:R(content_identity),frame_sha256:HEX)`.

`vector_capture_projection`:
`O(candidate:R(file_identity),receipt:R(file_identity),
vector_bundle_id:S(39,39,"^pfg3vb-[0-9a-f]{32}$"),
vector_bundle_body_sha256:HEX,receipt_id:S(40,40,
"^pfg3vbr-[0-9a-f]{32}$"),capture_run_id:S(40,40,
"^pfg3vcr-[0-9a-f]{32}$"),payload_set_sha256:HEX)`.

`candidate_payload_directory_locator`:
`O(root_id:C("CANDIDATE_PAYLOAD"),path:C("."),volume_id:S1,file_id:S1,
owner:S1,access_policy:HEX)`.

`candidate_payload_root`:
`O(locator:R(candidate_payload_directory_locator),descendant_count:C(12),
descendant_manifest_sha256:HEX)`.

`candidate_set_manifest`:
`O(schema_version:C("plamen.program_facts_parity_private_candidate_set.v1"),
candidate_set_id:S(39,39,"^pfg3cs-[0-9a-f]{32}$"),
base_snapshot_id:S(39,39,"^pfg3bs-[0-9a-f]{32}$"),
vector_bundle_source:R(snapshot_file_identity),
vector_capture:R(vector_capture_projection),
payload_members:A(R(snapshot_file_identity),12,12,true),
payload_absolute_root:ABS,payload_physical_root:R(candidate_payload_root),
payload_physical_members:A(R(snapshot_physical_member),12,12,true),
payload_complete:C(true),logical_content_sha256:HEX,
disposition:C("PRIVATE_UNREVIEWED_VECTOR_BUNDLE_ONLY"),
accepted_scope:C(["DERIVED_PARITY_INPUT_MATERIALIZATION_ONLY"]),
authority_ceiling:R(authority_v2),candidate_set_body_sha256:HEX)`.

`candidate_set_projection`:
`O(manifest:R(file_identity),candidate_set_id:S(39,39,
"^pfg3cs-[0-9a-f]{32}$"),base_snapshot_id:S(39,39,
"^pfg3bs-[0-9a-f]{32}$"),candidate_set_body_sha256:HEX,
logical_content_sha256:HEX,
vector_capture:R(vector_capture_projection),
payload_absolute_root:ABS,payload_physical_root:R(candidate_payload_root),
disposition:C("PRIVATE_UNREVIEWED_VECTOR_BUNDLE_ONLY"))`.

`snapshot_directory_locator`:
`O(root_id:C("INPUT_SNAPSHOT"),path:C("."),volume_id:S1,file_id:S1,
owner:S1,access_policy:HEX)`.

`input_snapshot_root`:
`O(locator:R(snapshot_directory_locator),descendant_count:I(1,20000),
descendant_manifest_sha256:HEX)`.

`snapshot_role_source_paths`:
`T(C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v2.py"),
C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v2.py"),
C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py"))`.

`snapshot_subject_paths`:
`C(["rules/schemas/mechanical_program_facts.v3.schema.json",
"rules/schemas/mechanical_program_facts_debt.v3.schema.json",
"rules/schemas/mechanical_program_facts_receipt.v3.schema.json",
"rules/schemas/program_facts_active_selection.v1.schema.json",
"rules/schemas/program_facts_independent_review.v1.schema.json",
"rules/schemas/program_facts_phase_io_interface_vector.v1.schema.json",
"rules/schemas/program_facts_public_generation.v2.schema.json",
"rules/schemas/program_facts_publication_arm.v2.schema.json",
"rules/schemas/program_facts_r19_seed_acceptance.v1.schema.json",
"rules/schemas/program_facts_r19_seed_admission.v1.schema.json",
"rules/schemas/program_facts_source_identity_census.v1.schema.json",
"rules/schemas/program_facts_provider_registry.v2.schema.json"])`.

`snapshot_vector_paths`:
`C(["review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts.v3.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts_debt.v3.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/mechanical_program_facts_receipt.v3.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_active_selection.v1.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_independent_review.v1.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_phase_io_interface_vector.v1.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_public_generation.v2.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_publication_arm.v2.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_r19_seed_acceptance.v1.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_r19_seed_admission.v1.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_source_identity_census.v1.schema.json/conformance_vectors.v1.json",
"review_fixtures/program_facts_runtime_gate3/schema_contracts/program_facts_provider_registry.v2.schema.json/conformance_vectors.v1.json"])`.

`input_snapshot_manifest`:
`O(schema_version:C("plamen.program_facts_parity_input_snapshot.v1"),
snapshot_id:S(39,39,"^pfg3is-[0-9a-f]{32}$"),
kind:C("IMMUTABLE_SYNTHETIC_REPOSITORY_SNAPSHOT_V1"),
base_snapshot:R(base_input_snapshot_projection),
candidate_set:R(candidate_set_projection),
file_members:A(R(snapshot_file_identity),30,20000,true),
physical_members:A(R(snapshot_physical_member),30,20000,true),
logical_content_sha256:HEX,absolute_root:ABS,
physical_root:R(input_snapshot_root),role_source_paths:R(snapshot_role_source_paths),
subject_schema_paths:R(snapshot_subject_paths),vector_paths:R(snapshot_vector_paths),
registry_path:C("rules/program-facts-provider-registry.v2.json"),
canonical_file_member_count:I(30,20000),
materialization_disposition:C("PRIVATE_NONAUTHORITY_SNAPSHOT_ONLY"),
accepted_scope:C(["IMMUTABLE_PARITY_INPUT_ONLY"]),authority_ceiling:R(authority_v2),
snapshot_body_sha256:HEX)`.

`input_snapshot_binding`:
`O(identity:R(file_identity),manifest:R(input_snapshot_manifest))`.

`input_snapshot_projection`:
`O(identity:R(file_identity),snapshot_id:S(39,39,"^pfg3is-[0-9a-f]{32}$"),
snapshot_body_sha256:HEX,logical_content_sha256:HEX,
absolute_root:ABS,physical_root:R(input_snapshot_root),
base_snapshot:R(base_input_snapshot_projection),
candidate_set:R(candidate_set_projection))`.

For both snapshots, `logical_content_sha256` is SHA-256 of the complete
UTF-8-path-sorted stream `CJ({path,size_bytes,sha256}) || 0x0a` over every
regular-file member, using canonical repository-relative paths and no host
absolute path, volume ID, file ID, owner, ACL, or runtime observation. The base
snapshot ID is `"pfg3bs-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_PARITY_BASE_INPUT_SNAPSHOT_V1",
logical_content_sha256}))[0:32]`. The candidate-set ID is `"pfg3cs-" ||
SHA-256(CJ({domain:"PROGRAM_FACTS_G3_PARITY_PRIVATE_CANDIDATE_SET_V1",
base_snapshot_id,vector_bundle_id:vector_capture.vector_bundle_id,
logical_content_sha256}))[0:32]`; its logical digest covers the
complete ordered candidate-vector member stream and excludes host identity,
reviews, promotion, and adoption. The derived snapshot ID is `"pfg3is-" ||
SHA-256(CJ({domain:"PROGRAM_FACTS_G3_PARITY_INPUT_SNAPSHOT_V1",
base_snapshot_id,candidate_set_id,logical_content_sha256}))[0:32]`.
`base_snapshot_body_sha256`, `candidate_set_body_sha256`, and
`snapshot_body_sha256` each hash `CJ` of their respective full manifest after
removing only that body-digest field. Those body digests cover absolute roots,
physical roots, path-bearing member identities, and other host-bound envelope
values and therefore are never claimed equal across hosts. Only the three IDs,
their three `logical_content_sha256` values, the logical `vector_bundle_id`, and
the logical payload-set digest may be compared across operating systems when
their defined logical preimages match. Base/candidate/derived manifest body
digests and file bytes, vector-capture receipt/run IDs, absolute roots, physical
roots, host receipts, native-image receipts, transactions, candidates,
evidence, and completion markers remain host-bound.
For the base, candidate payload, and derived snapshot independently,
`physical_members` is a complete path-sorted array in bijection with the
logical member array: equal path/size/hash, exact containing root ID, and no
missing or extra row in either direction. Each physical root's descendant count
equals its physical-array count, and its descendant digest uses the
path-bearing-handle preimage fixed by `immutable_directory_identity`; native
handle-relative enumeration must reproduce the same array and reject aliases,
extra directories, nonregular entries, and mount/volume escapes. A logical
digest cannot stand in for any physical proof.

The base manifest's `target_vector_paths_absent:true` means every one of the 12
exact `snapshot_vector_paths` is absent from its logical and physical arrays
and native enumeration. The candidate payload arrays contain exactly those 12
paths. The derived logical array is exactly the disjoint union of every base
logical row and every payload logical row; paths, sizes, hashes, and bytes
remain equal. The physical array is not a rebound union of source physical
rows. The materializer reads each source through its retained base-or-payload
handle, exclusively creates a new regular file under a fresh `INPUT_SNAPSHOT`
tree, writes and three-read validates it, and only then observes the derived
member's new path-bearing identity. Every derived member has `nlink:1`; its file
ID is distinct from every base/payload source file ID and from every other
derived member on that volume. Hardlink/reflink identity reuse or copying a
source physical identity into a derived row rejects. The newly observed derived
rows match the logical union only in path/size/hash and form a complete
bijection under the newly observed derived root. Only the materialization
amendment creates/seals these trees and records the retained-handle completion
epoch.
This generic snapshot interface selects no operating system. The currently
specified native authority is Windows-only; any future Linux or macOS backend
must reuse these logical snapshot rules but supply its own reviewed physical
root and native envelope. This amendment supplies no concrete value for any
base snapshot, vector candidate/receipt, candidate set, derived snapshot,
materialization receipt, pre-aggregate lineage, or promotion generation.
The base manifest's `canonical_file_member_count` equals `file_members.length`,
which also equals `physical_members.length` and its root descendant count; its
logical/physical rows are complete, bijective, and UTF-8-path-sorted, and its
`vector_bundle_source` is one of those exact rows at the section-2
`capture_schema_contract_parity_evidence_v2.py` source path; the parent resolves it beneath
the retained base root and its supplied absolute spelling has exactly the
lexical depth needed for `parents[3]` to equal that root without a child reopen.
The candidate manifest's 12
`payload_members` and 12 physical rows are in exact `snapshot_vector_paths`
order, validate the payload tree in both directions, and contain no review
or accepted-vector identity. Its `vector_bundle_source` equals the base
manifest row; its `vector_capture` completion/candidate/receipt/run/bundle/body/payload
projection is parsed-value identical to the validated section-15 capture chain;
and the 12 payload rows equal the vector candidate's payload projection in
order and both directions. The candidate-set body therefore binds capture
provenance while its logical ID remains free of host paths and physical IDs.
The derived manifest's base/candidate projections
must match those parsed manifests; its `canonical_file_member_count` equals
both member-array lengths and root descendant count; its complete
UTF-8-path-sorted logical/physical arrays and both logical/physical digests
must equal the immutable derived tree. These are semantic
requirements in addition to the closed schemas.
Every `role_source_paths`, `subject_schema_paths`, `vector_paths`, and
`registry_path` value names exactly one same-spelled `file_members` row. The 12
vector-member identities equal the candidate manifest's 12 `payload_members` in
order, and `registry_path` is the provider-registry instance
`rules/program-facts-provider-registry.v2.json`, not its subject schema.

`principal`:
`O(principal_id:S(1,256,"^(?:author|reviewer|builder|validator|collector):[a-z0-9-]+/[a-z0-9-]+$"),organization:S(1,256,-),role:E("GENERATOR","EVALUATOR","CROSSCHECK","LAUNCHER","BOOTSTRAP_AUTHOR","SOURCE_REVIEWER","CLOSURE_REVIEWER","IMPLEMENTATION_REVIEWER","AMENDMENT_REVIEWER","RUNTIME_BUILDER","NATIVE_HOST_VALIDATOR","NATIVE_IMAGE_COLLECTOR"))`.

`source_binding`: `O(principal:R(principal),source:R(file_identity))`.

`native_image_collector_principal`:
`C({"organization":"OpenAI Codex","principal_id":"collector:openai-codex/g3-00-native-image-collector","role":"NATIVE_IMAGE_COLLECTOR"})`.

`native_image_collector_source`:
`O(path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/collect_windows_native_images_v1.cpp"),
size_bytes:I(1,16777216),sha256:HEX)`.

`native_image_collector_binding`:
`O(principal:R(native_image_collector_principal),
source:R(native_image_collector_source))`.

`producer_principal`:
`U(C({"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-contract-generator","role":"GENERATOR"}),
C({"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-semantic-evaluator","role":"EVALUATOR"}),
C({"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-stdlib-crosscheck","role":"CROSSCHECK"}))`.

`launcher_principal`:
`C({"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-parity-launcher","role":"LAUNCHER"})`.

`producer_binding`:
`O(principal:R(producer_principal),source:R(file_identity))`.

`launcher_binding`:
`O(principal:R(launcher_principal),source:R(file_identity))`.

`runtime_archive`:
`O(kind:C("CPYTHON_EMBED_AMD64"),
filename:C("python-3.12.10-embed-amd64.zip"),tag:C("cp312-win_amd64"),
input:R(file_identity))`.

`locked_wheel`:
`U(O(name:C("attrs"),version:C("26.1.0"),filename:C("attrs-26.1.0-py3-none-any.whl"),tag:C("py3-none-any"),input:R(file_identity)),
O(name:C("jsonschema"),version:C("4.26.0"),filename:C("jsonschema-4.26.0-py3-none-any.whl"),tag:C("py3-none-any"),input:R(file_identity)),
O(name:C("jsonschema-specifications"),version:C("2025.9.1"),filename:C("jsonschema_specifications-2025.9.1-py3-none-any.whl"),tag:C("py3-none-any"),input:R(file_identity)),
O(name:C("referencing"),version:C("0.37.0"),filename:C("referencing-0.37.0-py3-none-any.whl"),tag:C("py3-none-any"),input:R(file_identity)),
O(name:C("rpds-py"),version:C("0.30.0"),filename:C("rpds_py-0.30.0-cp312-cp312-win_amd64.whl"),tag:C("cp312-cp312-win_amd64"),input:R(file_identity)),
O(name:C("typing_extensions"),version:C("4.15.0"),filename:C("typing_extensions-4.15.0-py3-none-any.whl"),tag:C("py3-none-any"),input:R(file_identity)))`.

`runtime_build_tool`:
`O(kind:E("BUILDER_INTERPRETER","ARCHIVE_READER","HASH_VERIFIER"),
absolute_path:ABS,physical_identity:R(handle_identity),implementation:S1,
version:S1)`.

`runtime_build_rules`:
`O(offline_only:C(true),network_attempt_count:C(0),
archive_order:C("UTF8_FILENAME_ASCENDING"),member_order:C("UTF8_PATH_ASCENDING"),
normalize_before_extract:C(true),reject_absolute_parent_drive_device:C(true),
reject_symlink_reparse_hardlink:C(true),reject_duplicate_casefold_unicode:C(true),
regular_files_and_directories_only:C(true),directory_mode:C("0555"),
file_mode:C("0444_OR_0555_IF_EXECUTABLE"),normalized_timestamp_ns:C(0),
generated_text:C("UTF8_LF_NO_BOM"),bytecode_forbidden:C(true),
ambient_environment:C({}),package_index_forbidden:C(true),
fresh_staging_root:C(true),three_read_output_validation:C(true))`.

`runtime_build_binding`:
`O(plan:R(file_identity),review:R(file_identity),
build_id:S(39,39,"^pfg3rb-[0-9a-f]{32}$"))`.

`host_profile`:
`O(host_profile_id:S(39,39,"^pfg3hp-[0-9a-f]{32}$"),
os_family:C("WINDOWS"),os_version:S1,os_build:S1,
architecture:C("AMD64"),filesystem_profile:S1)`. This v2 schema closes only the
conditional Windows profile described here. Linux or macOS requires a new
successor schema and review; the generic no-spawn launcher still returns its
fixed unavailable error on those hosts.

`bundle_root`:
`O(root_id:C("PRIVATE_RUNTIME"),absolute_path:ABS,
physical_identity:R(immutable_directory_identity),owner:S1,access_policy:HEX)`.

`manifest_interpreter`:
`O(implementation:C("cpython"),version:C("3.12.10"),
cache_tag:C("cpython-312"),abi_tag:S1,platform_tag:S1,
executable_absolute_path:ABS,executable:R(handle_identity),
python_library_members:A(PATH,1,20000,true))`.

`resolved_sys_path` is `A(ABS,4,4,true)`. Its four values are, in order, the
canonical bundle-root resolutions of `.`, `Lib`, `DLLs`, and `vendor`.

`path_configuration`:
`O(kind:C("WINDOWS_PYTHON312_DOT_PTH_V1"),member:C("python312._pth"),
lines:C([".","Lib","DLLs","vendor"]),resolved_sys_path:R(resolved_sys_path),
import_site:C(false))`.

`bootstrap`:
`O(kind:C("FIXED_PARENT_BOOTSTRAP_V1"),source:R(file_identity),
source_review:R(file_identity),template_utf8_sha256:HEX,
instantiated_argv_sha256:HEX,
capabilities:C(["VERIFY_FLAGS","VERIFY_PATH","INSTALL_IMPORT_DENYLIST",
"READ_BOUND_SOURCE","EXPOSE_OUTER_CONTEXT","REPORT_PRE_GATE_STATUS",
"EXECUTE_BOUND_SOURCE","REPORT_IMPORTS"]))`.

`bundle_member`:
`O(path:PATH,size_bytes:I(0,67108864),sha256:HEX,
kind:E("EXECUTABLE","SHARED_LIBRARY","PYTHON_SOURCE","EXTENSION_MODULE",
"STDLIB_DATA","VENDOR_DATA","DISTRIBUTION_METADATA","BOOTSTRAP_POLICY",
"PATH_CONFIGURATION"),executable:B)`.

`producer_source_exclusion`:
`O(role:E("GENERATOR","EVALUATOR","CROSSCHECK"),source:R(file_identity),
canonical_path_intersection_count:C(0),alias_intersection_count:C(0),
content_identity_intersection_count:C(0),complete_bidirectional:C(true))`.

`distribution`:
`U(O(name:C("attrs"),version:C("26.1.0"),
metadata_members:A(PATH,1,20000,true),record_sha256:HEX),
O(name:C("jsonschema"),version:C("4.26.0"),
metadata_members:A(PATH,1,20000,true),record_sha256:HEX),
O(name:C("jsonschema-specifications"),version:C("2025.9.1"),
metadata_members:A(PATH,1,20000,true),record_sha256:HEX),
O(name:C("referencing"),version:C("0.37.0"),
metadata_members:A(PATH,1,20000,true),record_sha256:HEX),
O(name:C("rpds-py"),version:C("0.30.0"),
metadata_members:A(PATH,1,20000,true),record_sha256:HEX),
O(name:C("typing_extensions"),version:C("4.15.0"),
metadata_members:A(PATH,1,20000,true),record_sha256:HEX))`. This literal union
cannot accept a Cartesian-product mismatch.

`module_origin`:
`U(O(module_name:S1,origin_kind:C("BUILTIN"),origin_path:C(null),
file_identity:C(null),distribution:C(null)),
O(module_name:S1,origin_kind:C("FROZEN"),origin_path:C(null),
file_identity:C(null),distribution:C(null)),
O(module_name:S1,origin_kind:C("BUNDLE_SOURCE"),origin_path:PATH,
file_identity:R(file_identity),distribution:Q(E("attrs","jsonschema",
"jsonschema-specifications","referencing","rpds-py","typing_extensions"))),
O(module_name:S1,origin_kind:C("BUNDLE_EXTENSION"),origin_path:PATH,
file_identity:R(file_identity),distribution:Q(E("attrs","jsonschema",
"jsonschema-specifications","referencing","rpds-py","typing_extensions"))))`.
The four closed branches enforce every null/tag relationship; null distribution
on a bundle branch is allowed only for standard-library content.

`role_import_closure`:
`O(role:E("GENERATOR","EVALUATOR","CROSSCHECK"),entry_source:R(file_identity),
source_review:R(file_identity),
allowed_module_names:A(S1,1,20000,true),
allowed_distribution_names:A(E("attrs","jsonschema",
"jsonschema-specifications","referencing","rpds-py","typing_extensions"),
0,6,true),producer_module_names:A(S1,1,1,true))`.

`producer_exclusion`:
`O(module_name:S1,reason:E("PEER_PRODUCER","LAUNCHER","PRODUCTION_PLAMEN",
"TARGET_CODE","SECOND_IMPLEMENTATION"))`.

`import_inventory`:
`O(inventory_id:S(39,39,"^pfg3ii-[0-9a-f]{32}$"),
construction_method:C("STATIC_LITERAL_DYNAMIC_AND_BOUNDED_LAZY_FROM_EXISTING_BUNDLE_V1"),
source_reviews:A(R(file_identity),4,4,true),
role_import_closures:A(R(role_import_closure),3,3,true),
module_origins:A(R(module_origin),1,20000,true),
producer_exclusions:A(R(producer_exclusion),1,20000,true),
producer_exclusions_sha256:HEX,inventory_body_sha256:HEX)`.

`host_system_component`:
`O(kind:E("KERNEL","LOADER"),absolute_path:ABS,
physical_identity:R(handle_identity),owner_sid:S1,dacl_sha256:HEX,
signature:R(signature),os_build:S1)`.

`host_identity`:
`O(os_family:C("WINDOWS"),os_version:S1,os_build:S1,
architecture:C("AMD64"),kernel_identity:R(host_system_component),
loader_identity:R(host_system_component))`.

`signature`:
`O(status:C("VALID_MICROSOFT"),signer_thumbprint:S(40,128,
"^[0-9A-F]+$"),chain_sha256:HEX)`.

`winsxs_alias`:
`O(path:ABS,volume_id:S1,file_id:S1)`.

`system_image`:
`O(canonical_path:ABS,physical_identity:R(handle_identity),
content_identity:R(content_identity),owner_sid:S1,dacl_sha256:HEX,
signature:R(signature),os_build:S1,winsxs_aliases:A(R(winsxs_alias),0,20000,true))`.
Every alias has the same volume/file ID as `physical_identity`; the list is the
complete UTF-16-sorted WinSxS alias set. `canonical_path` is under the exact
System32 or WinSxS root. No other row may use `nlink>1`. Every displayed
`content_identity` is exactly the `{size_bytes,sha256}` projection of the same
row's path-bearing `physical_identity`; `canonical_path` equals its absolute
path under the host root. Kernel/loader components use the equally host-bound
`host_system_component`, never portable `file_identity`.

`system_loader_boundary`:
`O(trust_model:C("TRUSTED_KERNEL_AND_OS_LOADER_NOT_PYTHON_ATTESTED"),
host_identity:R(host_identity),allowed_system_images:A(R(system_image),1,20000,true))`.

`native_image_origin`:
`U(O(kind:C("BUNDLE"),bundle_member:PATH),
O(kind:C("SYSTEM"),system_image:R(system_image)))`.

`native_image_expectation`:
`O(load_ordinal:I(0,19999),event:E("CREATE_PROCESS_DEBUG_EVENT",
"LOAD_DLL_DEBUG_EVENT"),canonical_path:ABS,
debug_hfile_identity:R(handle_identity),content_identity:R(content_identity),
origin:R(native_image_origin))`.

`role_native_image_projection`:
`O(role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
expected_images:A(R(native_image_expectation),1,20000,true),
projection_sha256:HEX)`.

`limits`:
`O(stdout_max_bytes:C(33554432),stderr_max_bytes:C(1048576),
control_max_bytes:C(16777216),source_max_bytes:C(16777216),
status_frame_max_bytes:C(1048576),
runtime_member_max_bytes:C(67108864),runtime_bundle_max_bytes:C(268435456),
runtime_member_max_count:C(20000),module_max_count:C(20000),
import_event_max_count:C(100000),attempt_max_count:C(8),
timeout_seconds:C(3600))`.

`authority_v2` is `C(` followed by the literal
`V2_NONAUTHORITY_CAPABILITY_BITSET` object in section 3 and `)`. `authority_v1`
is the same construction using the separately named 17-field
`PARENT_V1_AUTHORITY_CEILING`; it occurs only inside the embedded v1 parity
definition and never as a v2 artifact's `authority_ceiling`.

`runtime_closure_binding`:
`O(manifest:R(file_identity),review:R(file_identity),closure_id:S(39,39,
"^pfg3rc-[0-9a-f]{32}$"))`.

`runtime_closure_observed`:
`O(manifest:R(file_identity),review:R(file_identity),closure_id:S(39,39,
"^pfg3rc-[0-9a-f]{32}$"),parent_pre_spawn_verified:C(true),
child_observation_matched:C(true))`.

`source_access_denial`:
`O(path:APATH,expected_identity:R(handle_identity),open_denied:C(true),
raw_read_denied:C(true),alias_read_denied:C(true),
inherited_handle_absent:C(true),denial_probe_sha256:HEX)`.

`native_snapshot_entry`:
`U(O(path:APATH,kind:C("REGULAR_FILE"),
physical_identity:R(handle_identity)),
O(path:APATH,kind:C("DIRECTORY"),
physical_identity:R(directory_locator)))`.

`snapshot_entry_validation`:
`O(snapshot_id:S(39,39,"^pfg3is-[0-9a-f]{32}$"),
logical_entry_roster_sha256:HEX,
physical_member_projection_sha256:HEX,physical_member_bijection_complete:C(true),
allowed_directory_prefixes:A(APATH,1,20000,true),
native_entries:A(R(native_snapshot_entry),1,20000,true),
ascii_logical_roster:C(true),exact_case_and_spelling:C(true),
casefold_collision_count:C(0),unicode_normalization_collision_count:C(0),
missing_entry_count:C(0),extra_entry_count:C(0),extra_directory_count:C(0),
nonregular_entry_count:C(0),
mount_or_volume_escape_count:C(0),hardlink_alias_count:C(0),
reparse_alias_count:C(0),alternate_name_alias_count:C(0),
filesystem_profile_supported:C(true),complete:C(true))`.

The logical entry roster is the exact ASCII, case-sensitive spelling of every
derived-snapshot `file_members.path` plus every nonempty proper directory prefix
of those paths; no other directory or entry exists. Paths and prefixes are
unique in exact bytes, under Unicode normalization, and under the host's case-
folding rule. `allowed_directory_prefixes` is the complete UTF-8-byte-sorted
proper-prefix set. `native_entries` is the complete UTF-8-path-sorted native
enumeration of that logical roster, directories before descendants, and
`logical_entry_roster_sha256` is SHA-256 of its ordered
`CJ({kind,path}) || 0x0a` stream. Each physical identity must remain under the
retained snapshot root and volume. An exact-spelling mismatch, case-fold or
Unicode-normalization collision, extra directory, nonregular entry, mount or
volume escape, multi-link/alias, reparse point, alternate/short-name alias,
incomplete enumeration, or unsupported filesystem profile rejects before
spawn. Host-native rename and
durability primitives are not inferred from this projection and still require
their later receipt.
`physical_member_projection_sha256` is SHA-256 of the ordered
`CJ(snapshot_physical_member)||0x0a` stream and must equal the derived
manifest's physical array; `physical_member_bijection_complete:true` requires
both differences between that array, the native regular-file entries, and the
logical roster to be empty.

`role_readable_member_view`:
`O(role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
snapshot_id:S(39,39,"^pfg3is-[0-9a-f]{32}$"),
selected_source:R(handle_identity),
selected_source_filesystem_denial:R(source_access_denial),
shared_contract_inputs:A(R(handle_identity),1,20000,true),
subject_schema_inputs:A(R(handle_identity),12,12,true),
registry_input:R(handle_identity),vector_inputs:A(R(handle_identity),12,12,true),
launcher_inputs:A(R(handle_identity),1,16,true),
denied_peer_sources:A(R(source_access_denial),2,2,true),
source_denial_projection_sha256:HEX,
readable_member_count:I(27,20000),readable_member_projection_sha256:HEX,
acl_policy_sha256:HEX,complete:C(true))`.

The view is host-specific evidence and is never a member of the common logical
snapshot or any snapshot-ID preimage. `selected_source.path` is respectively
the generator, evaluator, or cross-check row of `snapshot_role_source_paths`.
`selected_source_filesystem_denial.path` and `expected_identity` equal that
selected row and retained handle.
`denied_peer_sources` is exactly the other two rows in that same tuple order,
with each `expected_identity` copied from the parent-authenticated snapshot
member. Each categorized readable array is complete and ordered, and no path
repeats within or across categories:
only the shared contract, 12 subject-schema, registry-instance, 12 private-
vector, and launcher inputs are readable. No producer source occurs in any
readable category, and no uncategorized snapshot member is readable by the
child token. Every readable or denied handle has root ID
`INPUT_SNAPSHOT` and equals the same-path derived `file_members` row in size and
digest. `readable_member_count` equals the total rows in
those five readable categories. `readable_member_projection_sha256` is SHA-256
of the concatenated `CJ({category,ordinal,path,physical_identity}) || 0x0a`
stream in category order `SHARED_CONTRACT`,
`SUBJECT_SCHEMA`, `REGISTRY`, `PRIVATE_VECTOR`, `LAUNCHER`, with each array in
its declared order. `source_denial_projection_sha256` is SHA-256 of the
concatenated `CJ(source_access_denial)||0x0a` stream for all three producer
paths in `snapshot_role_source_paths` order, reconstructed from the one selected
row and two peer rows. All four denial results for all three rows must be proved
at the OS/filesystem boundary; source scanning or a child claim is insufficient.

`bootstrap_protocol_contract`:
`O(control_magic:C("PFG3CTL2"),status_magic:C("PFG3STS2"),
length_encoding:C("U64_BIG_ENDIAN"),control_payload:C("STRICT_CF_JSON"),
source_payload:C("RAW_SELECTED_SOURCE"),status_payload:C("STRICT_CF_JSON"),
control_max_bytes:C(16777216),source_max_bytes:C(16777216),
status_frame_max_bytes:C(1048576),exact_eof:C(true),
gate_bytes_hex:C("01"),gate_then_eof:C(true))`.

`host_receipt`:
`O(identity:R(file_identity),
schema_version:C("plamen.program_facts_parity_native_host_receipt.v1"),
disposition:C("PASS_EXACT_NATIVE_HOST_ISOLATION_ONLY"),
host_profile_id:S(39,39,"^pfg3hp-[0-9a-f]{32}$"),
role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
input_snapshot:R(input_snapshot_projection),
snapshot_entry_validation:R(snapshot_entry_validation),
readable_member_view:R(role_readable_member_view),
bootstrap_protocol:R(bootstrap_protocol_contract))`.
The identity must validate against the later native-host schema selected by its
literal `schema_version`; absence, another disposition, or a profile mismatch
rejects it. Its `input_snapshot` is the exact host-physical projection validated
by that native run. Its `role` and `readable_member_view` must match the
candidate/evidence role and isolation view; both nested `snapshot_id` values
equal `input_snapshot.snapshot_id`, and `snapshot_entry_validation` is
parsed-value identical across host receipt and isolation. Its protocol is the
literal five-handle CONTROL/STATUS/GATE contract above; the receipt proves the
host can enforce that framing, one-byte gate, pipe directions/EOF, and size
limits without reusing stdout or stderr. No placeholder
receipt is valid.

`sys_flags`:
`O(isolated:C(1),no_site:C(1),no_user_site:C(1),dont_write_bytecode:C(1),
safe_path:C(true),ignore_environment:C(1))`.

`startup_hooks`:
`O(site_imported:C(false),pth_executed:C(false),
sitecustomize_imported:C(false),usercustomize_imported:C(false),
pythonstartup_executed:C(false),registry_path_used:C(false),
environment_path_used:C(false))`.

`import_event`:
`O(ordinal:I(0,99999),module_name:S1,resolved_origin:R(module_origin))`.

`source_execution_binding`:
`O(source_absolute_path:ABS,source_physical_identity:R(handle_identity),
parent_resolved_source_absolute_path:ABS,child_lexical_source_path:ABS,
child_parent_depth:C(3),child_lexical_root:ABS,
source_content_reopen_count:C(0),source_metadata_reopen_count:C(0),
compile_filename:ABS,code_object_filenames:A(ABS,1,20000,false),
globals_name:C("__main__"),globals_file:ABS,sys_argv:T(ABS),
cwd:R(producer_cwd))`.

`runtime_observation`:
`O(sys_executable:ABS,sys_flags:R(sys_flags),sys_path:R(resolved_sys_path),
startup_hook_observations:R(startup_hooks),
source_execution_binding:R(source_execution_binding),
loaded_modules:A(R(module_origin),1,20000,true),
import_events:A(R(import_event),1,100000,true),bytecode_write_count:C(0))`.

`execution_interpreter`:
`O(absolute_path:ABS,physical_identity:R(handle_identity),
content_identity:R(content_identity),implementation:C("cpython"),
version:C("3.12.10"),abi_tag:S1,platform_tag:S1)`.

`bootstrap_control`:
`O(schema_version:C("plamen.program_facts_parity_bootstrap_control.v1"),
protocol:R(bootstrap_protocol_contract),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
role:E("GENERATOR","EVALUATOR","CROSSCHECK"),principal:R(producer_principal),
start_gate_child_handle_value:S(1,20,"^(?:0|[1-9][0-9]*)$"),
status_write_child_handle_value:S(1,20,"^(?:0|[1-9][0-9]*)$"),
source:R(file_identity),source_absolute_path:ABS,
source_physical_identity:R(handle_identity),launcher:R(launcher_binding),
runtime_closure:R(runtime_closure_binding),
input_snapshot:R(input_snapshot_projection),candidate_set:R(candidate_set_projection),
host_receipt:R(host_receipt),requested_output:PATH,candidate_path:PATH,
transaction_evidence_path:PATH,completion_path:PATH,
authority_ceiling:R(authority_v2))`.

`bootstrap_status`:
`O(schema_version:C("plamen.program_facts_parity_bootstrap_status.v1"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
role:E("GENERATOR","EVALUATOR","CROSSCHECK"),outer_context_sha256:HEX,
control_frame_sha256:HEX,source_frame_sha256:HEX,
startup_flags_verified:C(true),startup_paths_verified:C(true),
source_binding_verified:C(true),source_location_verified:C(true),
parent_resolved_source_binding_verified:C(true),
child_lexical_source_depth_verified:C(true),
source_denial_projection_sha256:HEX,source_denials_verified:C(true),
status_emitted_before_gate:C(true),ready_for_gate:C(true),
authority_ceiling:R(authority_v2))`.

`producer_cwd`:
`O(logical:C("IMMUTABLE_SYNTHETIC_REPOSITORY_ROOT"),absolute_path:ABS,
physical_identity:R(snapshot_directory_locator))`.

`fixture_cwd`:
`O(logical:C("REPOSITORY_ROOT"),absolute_path:ABS,
physical_identity:R(directory_locator))`.

`inherited_handle`:
`O(ordinal:I(0,4),purpose:E("CONTROL_READ","STDOUT_WRITE","STDERR_WRITE",
"START_GATE_READ","STATUS_WRITE"),parent_handle_id:S1,child_handle_value:S1,
access:E("READ_ONLY","WRITE_ONLY"),direction:E("PARENT_TO_CHILD",
"CHILD_TO_PARENT"),physical_identity:Q(R(handle_identity)))`.

`inherited_handles_fixed`:
`T(O(ordinal:C(0),purpose:C("CONTROL_READ"),parent_handle_id:S1,
child_handle_value:S1,access:C("READ_ONLY"),direction:C("PARENT_TO_CHILD"),
physical_identity:C(null)),
O(ordinal:C(1),purpose:C("STDOUT_WRITE"),parent_handle_id:S1,
child_handle_value:S1,access:C("WRITE_ONLY"),direction:C("CHILD_TO_PARENT"),
physical_identity:C(null)),
O(ordinal:C(2),purpose:C("STDERR_WRITE"),parent_handle_id:S1,
child_handle_value:S1,access:C("WRITE_ONLY"),direction:C("CHILD_TO_PARENT"),
physical_identity:C(null)),
O(ordinal:C(3),purpose:C("START_GATE_READ"),parent_handle_id:S1,
child_handle_value:S1,access:C("READ_ONLY"),direction:C("PARENT_TO_CHILD"),
physical_identity:C(null)),
O(ordinal:C(4),purpose:C("STATUS_WRITE"),parent_handle_id:S1,
child_handle_value:S1,access:C("WRITE_ONLY"),direction:C("CHILD_TO_PARENT"),
physical_identity:C(null)))`.

`handle_accounting`:
`O(inherited_allowlist_count:C(5),inherited_allowlist_complete:C(true),
os_created_handles_classified_separately:C(true))`.

`execution`:
`O(interpreter:R(execution_interpreter),
argv:T(ABS,C("-I"),C("-S"),C("-B"),C("-c"),S1),
producer_arguments:C([]),control:R(bootstrap_control),
bootstrap_status:R(bootstrap_status),cwd:R(producer_cwd),
input_snapshot:R(input_snapshot_projection),environment:C({}),
inherited_handles:R(inherited_handles_fixed),
handle_accounting:R(handle_accounting),shell:C(false),
stdout_max_bytes:C(33554432),stderr_max_bytes:C(1048576),
status_frame_max_bytes:C(1048576),
timeout_seconds:C(3600))`. `argv` is the exact interpreter path, `-I`, `-S`,
`-B`, `-c`, and instantiated bootstrap in that order. Handle ordinals are 0-4
in displayed purpose order and each purpose has its fixed access/direction.
For `source_execution_binding`, `source_absolute_path`, `compile_filename`,
`parent_resolved_source_absolute_path`, `child_lexical_source_path`,
`globals_file`, the sole `sys_argv` item, and every recursively enumerated
`code_object_filenames` item are parsed-string identical. That absolute path was
resolved by the parent component-by-component under retained handles and is the
canonical join of `execution.input_snapshot.absolute_root` and the selected
candidate source's repository-relative path; its handle identity equals the
role view's `selected_source`. `child_parent_depth` is exactly three,
`child_lexical_root` equals the snapshot absolute root, and both reopen counts
are zero. The lexical path/depth test performs no `resolve`, `stat`, or content
open in the child. The control role equals the evidence role;
control source path/size/digest and physical identity equal the selected source
and candidate source; its source absolute path equals the same canonical join.
Its transaction/attempt/principal, launcher, runtime closure, snapshot,
candidate-set, host-receipt, output/candidate/evidence/completion paths, and
authority equal the outer candidate/evidence and exact transaction mapping.
The binding's `cwd` is parsed-value identical to
`execution.cwd`, its absolute path equals the snapshot root, and its locator is
the snapshot projection's `physical_root.locator` with root ID
`INPUT_SNAPSHOT`. Control input-snapshot absolute/physical roots equal those
same values; its candidate set equals the snapshot's nested projection; and its
start-gate/status-write values equal inherited-handle ordinals 3 and 4.
Status transaction/attempt/role and authority equal control; its outer-context
digest is SHA-256 of `CJ(control)`, its control-frame digest is SHA-256 of the
complete CONTROL_READ magic/length/control bytes, and its source-frame digest
is SHA-256 of the exact raw source bytes. Its source-denial digest equals the
host view's exact three-source projection. The parent validates the complete
status frame and EOF before writing
`0x01` and closing the gate. The
parent/bootstrap records the complete recursive code-object traversal in
depth-first pre-order, beginning with the root and visiting code-valued
`co_consts` by increasing tuple index, before producer execution; a child-authored claim cannot
satisfy this join.

`isolation`:
`O(os_family:C("WINDOWS"),backend_id:S1,
host_receipt:R(host_receipt),token_or_namespace_identity:S1,
snapshot_entry_validation:R(snapshot_entry_validation),
readable_member_view:R(role_readable_member_view),
network_denied:C(true),filesystem_denied:C(true),
child_creation_denied:C(true),process_tree_zero:C(true))`.

`native_image_projection`:
`O(identity:R(file_identity),receipt_id:S(39,39,
"^pfg3ni-[0-9a-f]{32}$"),ordered_image_set_sha256:HEX)`.

`candidate_projection`:
`O(identity:R(file_identity),candidate_id:S(39,39,
"^pfg3pc-[0-9a-f]{32}$"),candidate_body_sha256:HEX)`.

`evidence_projection`:
`O(identity:R(file_identity),evidence_id:S(40,40,
"^pfg3pe2-[0-9a-f]{32}$"),evidence_body_sha256:HEX)`.

`completion_projection`:
`O(identity:R(file_identity),completion_id:S(40,40,
"^pfg3pcm-[0-9a-f]{32}$"),completion_body_sha256:HEX)`.

`lineage_parity_projection`:
`O(cj_content_identity:R(content_identity),parity_body_sha256:HEX)`.

`lineage_role_row` is the three-branch union below; each
`legacy_requirement` constant includes exactly `{schema_version,role,principal,
source_path,output_path}` and every branch then has the common fields
`successor_source_review:R(file_identity),evidence:R(evidence_projection),
completion:R(completion_projection),parity_projection:R(lineage_parity_projection),
outer_envelope_equal:C(false),outer_envelope_equality_required:C(false),
projection_result:C("EXACT_ACCEPTED_V1_PARITY_VALUE_AND_ROLE_PROVENANCE_WITH_V2_ENVELOPE")`:

```text
U(
 O(role:C("GENERATOR"),
   legacy_requirement:C({"output_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/generator.parity_evidence.v1.json","principal":{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-contract-generator","role":"GENERATOR"},"role":"GENERATOR","schema_version":"plamen.program_facts_gate3_schema_contract_parity_evidence.v1","source_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v1.py"}),
   successor_source:O(path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v2.py"),size_bytes:I(1,16777216),sha256:HEX),successor_source_review:R(file_identity),evidence:R(evidence_projection),completion:R(completion_projection),parity_projection:R(lineage_parity_projection),outer_envelope_equal:C(false),outer_envelope_equality_required:C(false),projection_result:C("EXACT_ACCEPTED_V1_PARITY_VALUE_AND_ROLE_PROVENANCE_WITH_V2_ENVELOPE")),
 O(role:C("EVALUATOR"),
   legacy_requirement:C({"output_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/evaluator.parity_evidence.v1.json","principal":{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-semantic-evaluator","role":"EVALUATOR"},"role":"EVALUATOR","schema_version":"plamen.program_facts_gate3_schema_contract_parity_evidence.v1","source_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v1.py"}),
   successor_source:O(path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v2.py"),size_bytes:I(1,16777216),sha256:HEX),successor_source_review:R(file_identity),evidence:R(evidence_projection),completion:R(completion_projection),parity_projection:R(lineage_parity_projection),outer_envelope_equal:C(false),outer_envelope_equality_required:C(false),projection_result:C("EXACT_ACCEPTED_V1_PARITY_VALUE_AND_ROLE_PROVENANCE_WITH_V2_ENVELOPE")),
 O(role:C("CROSSCHECK"),
   legacy_requirement:C({"output_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence/crosscheck.parity_evidence.v1.json","principal":{"organization":"OpenAI Codex","principal_id":"author:openai-codex/g3-00-schema-stdlib-crosscheck","role":"CROSSCHECK"},"role":"CROSSCHECK","schema_version":"plamen.program_facts_gate3_schema_contract_parity_evidence.v1","source_path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v1.py"}),
   successor_source:O(path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py"),size_bytes:I(1,16777216),sha256:HEX),successor_source_review:R(file_identity),evidence:R(evidence_projection),completion:R(completion_projection),parity_projection:R(lineage_parity_projection),outer_envelope_equal:C(false),outer_envelope_equality_required:C(false),projection_result:C("EXACT_ACCEPTED_V1_PARITY_VALUE_AND_ROLE_PROVENANCE_WITH_V2_ENVELOPE")))
```

`lineage_check`:
`O(check_id:E("LIN-01-LEGACY-REQUIREMENT-PROJECTIONS",
"LIN-02-V2-COMPLETION-CHAINS","LIN-03-EXACT-PARITY-PROJECTION",
"LIN-04-GREEN-CROSSCHECK-V2-SUCCESSOR","LIN-05-ACYCLIC-NONAUTHORITY"),
result:E("PASS","FAIL"),evidence:A(R(file_identity),1,10000000,true))`.

`completion_state`: `O(capture_complete:C(true))`.

`finding`:
`O(finding_id:ID,severity:E("BLOCKING","NONBLOCKING"),
status:E("OPEN","CLOSED"),description:S(1,8192,-),
evidence:A(R(file_identity),1,10000000,true))`.

`reviewer`:
`O(principal_id:S(12,256,"^reviewer:[a-z0-9-]+/[a-z0-9-]+$"),
organization:S(1,256,-),role:S(1,256,-))`.

`review_check`:
`O(check_id:ID,result:E("PASS","FAIL"),
evidence:A(R(file_identity),1,10000000,true))`.

`amendment_check`:
`O(check_id:E("G3LRC-R01-PREDECESSOR-PINS-AND-HISTORY",
"G3LRC-R02-IMMUTABLE-V1-ACYCLIC-V2",
"G3LRC-R03-STARTUP-INTERPRETER-RUNTIME-CLOSURE",
"G3LRC-R04-DEPENDENCY-ORIGIN-AND-PRODUCER-INDEPENDENCE",
"G3LRC-R05-PARITY-AND-EVIDENCE-BINDING",
"G3LRC-R06-DESCRIPTOR-HANDLE-STABLE-IO",
"G3LRC-R07-MARKER-LAST-TRANSACTION-RECOVERY",
"G3LRC-R08-EXACT-FIXTURE-FIRST-DENOMINATOR",
"G3LRC-R09-CLOSED-SCHEMAS-CANONICALIZATION-LIMITS",
"G3LRC-R10-NATIVE-NO-SPAWN-BOUNDARY",
"G3LRC-R11-REVIEW-INDEPENDENCE-AND-ADOPTION-DAG",
"G3LRC-R12-TRUST-AND-AUTHORITY-CEILING",
"G3LRC-R13-RUNTIME-BUILD-AND-SNAPSHOT-PAYLOAD-CLOSURE",
"G3LRC-R14-QUARANTINE-LOCATOR-AND-NATIVE-TRANSPORT",
"G3LRC-R15-AUTHENTICATED-FOURTH-CAPTURE-LIFECYCLE",
"G3LRC-R16-EXACT-NATIVE-METADATA-STREAMS",
"G3LRC-R17-CLOSED-CONTROL-STATUS-SOURCE-AND-PATH-BINDING",
"G3LRC-R18-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION",
"G3LRC-R19-NO-RETRY-STATE-ARTIFACT-TOTALITY",
"G3LRC-R20-PLATFORM-AUTHORITY-BOUNDARY"),result:E("PASS","FAIL"),
evidence:A(R(file_identity),1,10000000,true))`.

`closure_check`:
`O(check_id:E("RCV-01-MANIFEST-IDENTITY",
"RCV-02-BUNDLE-TREE-BIDIRECTIONAL",
"RCV-03-DISTRIBUTION-RECORD-BIDIRECTIONAL","RCV-04-MODULE-ORIGINS",
"RCV-05-ROLE-IMPORT-CLOSURES","RCV-06-SYSTEM-LOADER-AND-NATIVE-PROJECTIONS",
"RCV-07-PATH-AND-LIMITS","RCV-08-NONAUTHORITY",
"RCV-09-BUILD-PLAN-AND-PRODUCER-SOURCE-EXCLUSION"),
result:E("PASS","FAIL"),evidence:A(R(file_identity),1,10000000,true))`.

`runtime_build_check`:
`O(check_id:E("RBV-01-LOCKED-ARCHIVE-IDENTITIES",
"RBV-02-BUILDER-SOURCE-AND-TOOLCHAIN","RBV-03-OFFLINE-SAFE-EXTRACTION",
"RBV-04-LAYOUT-MODE-TIME-NORMALIZATION","RBV-05-EXPECTED-MEMBER-BIDIRECTIONAL",
"RBV-06-PRODUCER-SOURCE-EXCLUSION","RBV-07-REPRODUCIBLE-OUTPUT-AND-ID",
"RBV-08-NONAUTHORITY"),result:E("PASS","FAIL"),
evidence:A(R(file_identity),1,10000000,true))`.

`source_check`:
`O(check_id:E("SRV-01-SOURCE-IDENTITY","SRV-02-NO-PEER-IMPORT",
"SRV-03-NO-SHARED-ALGORITHM","SRV-04-SEMANTIC-IMPORT-DECLARATIONS",
"SRV-05-TRANSPORT-OR-BUILDER-BOUNDARY","SRV-06-NONAUTHORITY",
"SRV-07-VECTOR-CAPTURE-BOOTSTRAP-MODE",
"SRV-08-CONTAINMENT-SUPERVISOR-SOURCE"),
result:E("PASS","FAIL"),evidence:A(R(file_identity),1,10000000,true))`.

`implementation_check`:
`O(check_id:E("V2I-01-RED-CHRONOLOGY","V2I-02-SCHEMAS",
"V2I-03-RUNTIME-CLOSURE","V2I-04-IMPORT-INDEPENDENCE",
"V2I-05-HANDLE-IO","V2I-06-TRANSACTION-RECOVERY","V2I-07-PARITY",
"V2I-08-NATIVE-NO-SPAWN","V2I-09-NONAUTHORITY",
"V2I-10-RUNTIME-BUILD-CHAIN",
"V2I-11-QUARANTINE-LOCATOR-AND-NATIVE-TRANSPORT",
"V2I-12-AUTHENTICATED-FOURTH-CAPTURE-LIFECYCLE",
"V2I-13-EXACT-NATIVE-METADATA-STREAMS",
"V2I-14-CONTROL-STATUS-SOURCE-AND-PATH-BINDING",
"V2I-15-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION",
"V2I-16-NO-RETRY-STATE-ARTIFACT-TOTALITY",
"V2I-17-PLATFORM-AUTHORITY-BOUNDARY"),
result:E("PASS","FAIL"),evidence:A(R(file_identity),1,10000000,true))`.

`review_common` is not itself a root; review roots below repeat and close all
members so that their check enums, exact counts, dispositions, scopes, and
independence constants cannot be widened.

`mutation_single`:
`O(kind:C("SINGLE"),value:S1)`.

`mutation_subcases`:
`O(kind:C("SUBCASES"),values:A(S1,1,256,true))`.

`mixed_subcase`:
`O(expected_error_precedence:Q(I(1,51)),expected_first_error:Q(S1),
expected_outcome:E("ACCEPT","REJECT","ABORT_ATTEMPT",
"QUARANTINE_TRANSACTION","ADOPT_COMMITTED","RECOVERY_TRANSITION",
"QUARANTINE_VECTOR_CAPTURE","ADOPT_VECTOR_CAPTURE"),label:S1)`,
wrapped in `AND` with this exact constraint:

```json
{"allOf":[{"if":{"properties":{"expected_outcome":{"enum":["ACCEPT","ADOPT_COMMITTED","RECOVERY_TRANSITION","ADOPT_VECTOR_CAPTURE"]}},"required":["expected_outcome"]},"then":{"properties":{"expected_error_precedence":{"const":null},"expected_first_error":{"const":null}}}},{"if":{"properties":{"expected_outcome":{"enum":["REJECT","ABORT_ATTEMPT","QUARANTINE_TRANSACTION","QUARANTINE_VECTOR_CAPTURE"]}},"required":["expected_outcome"]},"then":{"properties":{"expected_error_precedence":{"type":"integer"},"expected_first_error":{"type":"string","minLength":1}}}}]}
```

`mutation_mixed_subcases`:
`O(kind:C("MIXED_SUBCASES"),values:A(R(mixed_subcase),2,256,true))`.

`scenario`:
`O(category:E("BASELINE","STARTUP","RUNTIME_CLOSURE",
"IMPORT_INDEPENDENCE","HANDLE_IO","TRANSPORT_SCHEMA","PARITY",
"TRANSACTION","RECOVERY","NATIVE_NO_SPAWN","HISTORY"),
expected_error_precedence:Q(I(1,51)),expected_first_error:Q(S1),
green_expectation:E("PASS_EXPECTED_ACCEPTANCE","PASS_EXPECTED_REJECTION",
"PASS_EXPECTED_RECOVERY","PASS_CLOSED_SUBCASES"),
mutation:U(R(mutation_single),R(mutation_subcases),
R(mutation_mixed_subcases)),ordinal:I(0,51),
red_expectation:E("PASS_BASELINE_PIN","FAIL_FIRST_CANDIDATE"),
scenario_id:S(7,7,"^LRC2-(?:0[0-9]|[1-4][0-9]|5[01])$"))`, wrapped in
`AND` with this exact constraint:

```json
{"allOf":[{"if":{"properties":{"ordinal":{"const":0}},"required":["ordinal"]},"then":{"properties":{"category":{"const":"BASELINE"},"expected_error_precedence":{"const":null},"expected_first_error":{"const":null},"green_expectation":{"const":"PASS_EXPECTED_ACCEPTANCE"},"red_expectation":{"const":"PASS_BASELINE_PIN"},"scenario_id":{"const":"LRC2-00"}}}},{"if":{"properties":{"ordinal":{"minimum":1}},"required":["ordinal"]},"then":{"properties":{"red_expectation":{"const":"FAIL_FIRST_CANDIDATE"}}}},{"if":{"properties":{"mutation":{"properties":{"kind":{"const":"MIXED_SUBCASES"}},"required":["kind"]}},"required":["mutation"]},"then":{"properties":{"expected_error_precedence":{"const":null},"expected_first_error":{"const":null},"green_expectation":{"const":"PASS_CLOSED_SUBCASES"}}}},{"if":{"properties":{"green_expectation":{"const":"PASS_CLOSED_SUBCASES"}},"required":["green_expectation"]},"then":{"properties":{"mutation":{"properties":{"kind":{"const":"MIXED_SUBCASES"}},"required":["kind"]}}}},{"if":{"properties":{"green_expectation":{"const":"PASS_EXPECTED_RECOVERY"}},"required":["green_expectation"]},"then":{"properties":{"expected_error_precedence":{"const":null},"expected_first_error":{"const":null},"ordinal":{"enum":[28,29,30]}}}},{"if":{"properties":{"ordinal":{"enum":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,24,25,26,27,31,36,37,39,40,41,43,44,45]}},"required":["ordinal"]},"then":{"properties":{"expected_error_precedence":{"type":"integer"},"expected_first_error":{"type":"string"},"green_expectation":{"const":"PASS_EXPECTED_REJECTION"}}}}]}
```

`scenario_subcase_result`:
`O(subcase_ordinal:I(0,255),label:S1,
expected_outcome:E("ACCEPT","REJECT","ABORT_ATTEMPT",
"QUARANTINE_TRANSACTION","ADOPT_COMMITTED","RECOVERY_TRANSITION",
"QUARANTINE_VECTOR_CAPTURE","ADOPT_VECTOR_CAPTURE"),
expected_error_precedence:Q(I(1,51)),expected_first_error:Q(S1),
observed_outcome:E("ACCEPT","REJECT","ABORT_ATTEMPT",
"QUARANTINE_TRANSACTION","ADOPT_COMMITTED","RECOVERY_TRANSITION",
"QUARANTINE_VECTOR_CAPTURE","ADOPT_VECTOR_CAPTURE"),
observed_error_precedence:Q(I(1,51)),observed_first_error:Q(S1),
status:E("PASS","FAIL"))`.

`scenario_result`:
`O(scenario_id:S(7,7,"^LRC2-(?:0[0-9]|[1-4][0-9]|5[01])$"),
ordinal:I(0,51),scenario_definition:R(scenario),method_name:S1,
status:E("PASS","FAIL"),observed_error_precedence:Q(I(1,51)),
observed_first_error:Q(S1),
subcase_results:A(R(scenario_subcase_result),1,256,true))`. Each result's
`scenario_definition` is byte-identical as a parsed value to the manifest row
at its ordinal and its outer ID/ordinal. A `SINGLE` row has exactly one result
whose label is `value`; a `SUBCASES` row has one result per string in order.
Their expected outcome is `ACCEPT` for `PASS_EXPECTED_ACCEPTANCE`, `REJECT` for
`PASS_EXPECTED_REJECTION`, `RECOVERY_TRANSITION` for LRC2-28, and
`ADOPT_COMMITTED` for LRC2-29/LRC2-30; their expected error pair is copied from
the row. No non-mixed row uses another `green_expectation`/outcome pairing.
A `MIXED_SUBCASES` row has one
result per definition in order and copies all four expected fields exactly.
Observed outcome, precedence, and error must equal their three expected values
for subcase `status:"PASS"`. The outer result is `PASS` exactly when every
subcase is `PASS`; its outer observed precedence/error pair is `(null,null)` when
no active subcase has an error and otherwise equals the first pair under the
section-10 total order.

`fixture_subject`:
`O(harness:R(file_identity),launcher_under_test:R(file_identity))`.

`fixture_interpreter`:
`O(absolute_path:ABS,physical_identity:R(handle_identity),
content_identity:R(content_identity),implementation:S1,version:S1)`.

`profile_writable_root`:
`O(kind:E("PROFILE_ROOT","LOCALAPPDATA","TEMP","TMP"),absolute_path:ABS,
physical_identity:R(directory_locator),owner_sid:S1,dacl_sha256:HEX,
deny_execute:C(true),importable:C(false))`.

`created_descendant_identity`:
`U(R(handle_identity),R(directory_locator),
O(absolute_path:ABS,physical_identity:R(quarantine_nonregular_identity)))`.

`attempt_paths`:
`O(lock:PATH,head:PATH,head_stage:PATH,head_history:PATH,head_backup:PATH,
journal:PATH,attempt:PATH,candidate:PATH,native_images:PATH,
staged_evidence:PATH,staged_marker:PATH,quarantine_root:PATH,completion:PATH)`.

`attempt_inputs`:
`O(amendment:R(file_identity),amendment_review:R(file_identity),
scenario_manifest:R(file_identity),schema_files:A(R(file_identity),25,25,true),
source_files:A(R(file_identity),6,6,true),source_reviews:A(R(file_identity),5,5,true),
runtime_build_plan:R(file_identity),runtime_build_review:R(file_identity),
runtime_manifest:R(file_identity),runtime_review:R(file_identity),
input_snapshot:R(input_snapshot_projection),
candidate_set:R(candidate_set_projection),
host_receipt:R(host_receipt))`.

`artifact_ref`:
`O(kind:E("JOURNAL","ATTEMPT","CANDIDATE","NATIVE_IMAGES",
"STAGED_EVIDENCE","STAGED_MARKER","COMPLETION","HEAD","LOCK",
"HEAD_STAGE","HEAD_HISTORY","HEAD_BACKUP","QUARANTINE_INTENT",
"QUARANTINE_PROGRESS","QUARANTINE"),path:PATH,
inode_content_identity:R(inode_content_identity))`.

`artifact_slot`:
`U(O(status:C("ABSENT")),
O(status:C("CURRENT"),artifact:R(artifact_ref)),
O(status:C("PREDECESSOR"),artifact:R(artifact_ref)))`.

`attempt_artifacts`:
`O(lock:R(artifact_slot),head:R(artifact_slot),journal:R(artifact_slot),
attempt:R(artifact_slot),candidate:R(artifact_slot),
native_images:R(artifact_slot),staged_evidence:R(artifact_slot),
staged_marker:R(artifact_slot),quarantine:R(artifact_slot),
completion:R(artifact_slot))`.

`transaction_error`:
`O(error_code:S1,precedence:I(0,9007199254740991),detail:S(0,8192,-))`.

`quarantine_nonregular_identity`:
`O(volume_id:S1,file_id:S1,nlink:I(1,9007199254740991),
native_kind:E("SYMLINK","JUNCTION","REPARSE_POINT","DEVICE","SOCKET",
"FIFO","OTHER_NONREGULAR"),native_metadata_sha256:HEX)`.

`quarantine_tree_identity`:
`O(root:R(directory_inode_identity),descendant_count:I(0,20000),
descendant_manifest_sha256:HEX)`. Its manifest is the ordered
`CJ({path,kind,identity})||0x0a` stream from a complete no-follow native
enumeration of every descendant, including directories, regular files, and any
nonregular conflict. It is valid only after process-tree zero has stopped writes.

`quarantine_source_path`: `U(PATH,ABS)`.

`quarantine_entry_ref`:
`U(O(entry_kind:C("REGULAR_ARTIFACT"),artifact:R(artifact_ref)),
O(entry_kind:C("WRITABLE_PROFILE_TREE"),writable_kind:E("PROFILE_ROOT",
"LOCALAPPDATA","TEMP","TMP"),path:R(quarantine_source_path),tree_identity:R(quarantine_tree_identity)),
O(entry_kind:C("NONREGULAR_CONFLICT"),path:R(quarantine_source_path),
path_identity:R(quarantine_nonregular_identity)))`.

`coordination_lock_entry_ref`:
`U(O(entry_kind:C("REGULAR_ARTIFACT"),artifact:R(artifact_ref)),
O(entry_kind:C("NONREGULAR_CONFLICT"),path:R(quarantine_source_path),
path_identity:R(quarantine_nonregular_identity)))`.

`quarantine_move`:
`O(move_ordinal:I(0,19999),source:R(quarantine_entry_ref),destination:PATH)`.

`quarantine_intent_projection`:
`O(identity:R(artifact_ref),quarantine_id:S(39,39,
"^pfg3pq-[0-9a-f]{32}$"),quarantine_body_sha256:HEX)`.

`quarantine_progress_projection`:
`O(identity:R(artifact_ref),progress_id:S(40,40,
"^pfg3qmp-[0-9a-f]{32}$"),move_ordinal:I(0,19999),
progress_body_sha256:HEX)`.

`coordination_quarantine_intent_projection`:
`O(identity:R(artifact_ref),lock_quarantine_id:S(39,39,
"^pfg3lq-[0-9a-f]{32}$"),quarantine_body_sha256:HEX)`.

`coordination_quarantine_progress_projection`:
`O(identity:R(artifact_ref),progress_id:S(40,40,
"^pfg3lmp-[0-9a-f]{32}$"),move_ordinal:C(0),
progress_body_sha256:HEX)`.

`child_capture`:
`O(control_frame_sha256:HEX,status_frame:R(content_identity),
source_frame:R(content_identity),stdout:R(content_identity),
stderr:C({"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size_bytes":0}),
exit_code:C(0),process_tree_zero:C(true),status_validated_before_gate:C(true),
gate_exact_one_byte_then_eof:C(true))`.

`native_image_event`:
`O(load_ordinal:I(0,19999),event:E("CREATE_PROCESS_DEBUG_EVENT",
"LOAD_DLL_DEBUG_EVENT"),process_id:S1,image_base:S1,
requested_path:Q(S1),debug_hfile_identity:R(handle_identity),
canonical_path:ABS,content_identity:R(content_identity),origin:R(native_image_origin),
evidence_reference:S1)`.

<!-- PARITY_V1_LOCAL_FRAGMENT_BEGIN -->

`json_value` is the locally recursive JSON-domain union
`U(N,B,SAFE,S0,A(R(json_value),0,10000000,false),R(json_object))` and
`json_object` is `{"type":"object","propertyNames":{"maxLength":16384,
"type":"string"},"additionalProperties":{"$ref":"#/$defs/json_value"},
"maxProperties":4096}`. This branch is used only for parsed JSON Schema/proof
values whose property vocabulary is itself data; it is not an artifact envelope
and does not waive any artifact object's closed member set.

`parity_contracts`:
`O(schema_closure_amendment:R(file_identity),
schema_closure_review:R(file_identity),
vector_clarification_amendment:R(file_identity),
vector_clarification_review:R(file_identity))`.

`parity_subject_row`:
`O(subject_ordinal:I(0,11),schema:R(file_identity),schema_id:S1,
vectors:R(file_identity),vector_body_sha256:HEX,
keyword_occurrence_count:I(0,10000000),coverage_atom_count:I(0,10000000),
vector_count:I(0,10000000),impossible_positive_count:I(0,10000000),
impossible_negative_count:I(0,10000000),witness_decision_count:I(0,10000000),
pattern_occurrence_count:I(0,10000000))`.

`parity_occurrence_row`:
`O(subject_ordinal:I(0,11),schema_path:PATH,schema_pointer:S0,
target_schema_pointer:S0,keyword:S1)`.

`parity_atom_row`:
`O(schema_path:PATH,schema_pointer:S0,keyword:S1,atom_id:ID,
expected:E("VALID","INVALID"))`.

`parity_disposition_vector`:
`O(atom_ordinal:I(0,21577),disposition:C("VECTOR"),
vector_ids:A(ID,1,10000000,true))`.

`parity_disposition_impossible`:
`O(atom_ordinal:I(0,21577),disposition:C("IMPOSSIBLE"),predicate_id:E(
"NEG-01-MAXITEMS-10000000","NEG-02-MINITEMS-0",
"NEG-03-MAXPROPERTIES-4096","NEG-04-MINPROPERTIES-0",
"NEG-05-MAXLENGTH-16384","NEG-06-MINLENGTH-0",
"NEG-07-MAXIMUM-SAFE-MAX","NEG-08-MINIMUM-SAFE-MIN",
"NEG-09-MULTIPLEOF-1-INTEGER","NEG-10-TYPE-ALL-SIX",
"NEG-11-IF-DIRECT","NEG-12-ONEOF-MUTUALLY-EXCLUSIVE-CONSTS",
"NEG-13-DELEGATED-EMPTY-SCHEMA","NEG-14-ENUM-NULL-CLOSED-DOMAIN",
"NEG-15-ENUM-BOOLEAN-CLOSED-DOMAIN",
"NEG-16-TAGGED-UNION-NO-EXCLUSIVE-FIELD",
"POS-01-MAXITEMS-CONTROL-CEILING","POS-02-LOCAL-SCHEMA-ID-MINLENGTH",
"POS-03-ITEMS-FALSE-CHILD-VALID"),proof:R(json_value),vector_ids:C([]))`.

`parity_atom_disposition`:
`U(R(parity_disposition_vector),R(parity_disposition_impossible))`.

`parity_proof_row`:
`O(subject_schema_id:S1,schema_pointer:S0,atom_id:ID,
direction:E("POSITIVE","NEGATIVE"),predicate_id:E(
"NEG-01-MAXITEMS-10000000","NEG-02-MINITEMS-0",
"NEG-03-MAXPROPERTIES-4096","NEG-04-MINPROPERTIES-0",
"NEG-05-MAXLENGTH-16384","NEG-06-MINLENGTH-0",
"NEG-07-MAXIMUM-SAFE-MAX","NEG-08-MINIMUM-SAFE-MIN",
"NEG-09-MULTIPLEOF-1-INTEGER","NEG-10-TYPE-ALL-SIX",
"NEG-11-IF-DIRECT","NEG-12-ONEOF-MUTUALLY-EXCLUSIVE-CONSTS",
"NEG-13-DELEGATED-EMPTY-SCHEMA","NEG-14-ENUM-NULL-CLOSED-DOMAIN",
"NEG-15-ENUM-BOOLEAN-CLOSED-DOMAIN",
"NEG-16-TAGGED-UNION-NO-EXCLUSIVE-FIELD",
"POS-01-MAXITEMS-CONTROL-CEILING","POS-02-LOCAL-SCHEMA-ID-MINLENGTH",
"POS-03-ITEMS-FALSE-CHILD-VALID"),proof:R(json_value))`.

`parity_vector_identity_row`:
`O(subject_ordinal:I(0,11),vector_id:ID,target_schema_pointer:S0,
expected:E("VALID","INVALID"),covers:A(S0,1,1,true),
instance_cj_size_bytes:I(0,16777216),instance_cj_sha256:HEX)`.

`parity_witness_decision_row`:
`O(subject_schema_id:S1,schema_pointer:S0,atom_id:ID,
predicate_id:C("WIT-01-DIRECT-HEX64-CONST"),proof:R(json_value),vector_id:ID)`.

`parity_member_state`:
`U(O(state:C("ABSENT")),O(state:C("PRESENT"),value:R(json_value)))`.

`parity_direct_other`:
`O(type:R(parity_member_state),enum:R(parity_member_state),
format:R(parity_member_state),$ref:R(parity_member_state),
allOf:R(parity_member_state),anyOf:R(parity_member_state),
oneOf:R(parity_member_state),not:R(parity_member_state),
if:R(parity_member_state),then:R(parity_member_state),
else:R(parity_member_state))`.

`parity_pattern_occurrence_row`:
`O(subject_ordinal:I(0,11),subject_path:PATH,subject_schema_id:S1,
occurrence_ordinal:I(0,10000000),containing_node_pointer:S0,
keyword_pointer:S0,literal_pattern:S0,direct_minLength:R(parity_member_state),
direct_maxLength:R(parity_member_state),direct_const:R(parity_member_state),
direct_other:R(parity_direct_other),direct_sibling_keyword_names:A(S1,0,4096,true),
direct_sibling_schema:R(json_object))`.

`parity_pattern_literal_row`: `O(literal_pattern:S0)`.

`parity_pattern_sibling_row`:
`O(literal_pattern:S0,direct_sibling_schema:R(json_object))`.

`parity_pattern_conflict_row`:
`O(subject_path:PATH,subject_schema_id:S1,keyword_pointer:S0,
literal_pattern:S0,positive_witness:R(json_value),
reasons:A(U(E("DIRECT_TYPE","DIRECT_MINLENGTH","DIRECT_MAXLENGTH",
"DIRECT_CONST","DIRECT_ENUM"),S(18,16384,"^UNMODELED_DIRECT_.+$")),1,6,true),
direct_sibling_schema:R(json_object))`.

`parity_totals`:
`O(subject_count:C(12),keyword_occurrence_count:C(7517),
coverage_atom_count:C(21578),vector_count:I(0,10000000),
impossible_positive_count:I(0,10000000),
impossible_negative_count:I(0,10000000),witness_decision_count:I(0,10000000),
pattern_occurrence_count:C(521),pattern_literal_count:C(39),
pattern_sibling_context_count:C(41),pattern_positive_conflict_count:C(1))`.

`parity_stream_identity`:
`O(encoding:C("CJ_ROW_LF_V1"),row_count:I(0,10000000),
preimage_size_bytes:I(0,9007199254740991),sha256:HEX)`.

`parity_atom_set_identity`:
`O(encoding:C("SCHEMA_ROSTER_ORDER_THEN_OCCURRENCE_ORDER_THEN_SECTION_4_4_ATOM_ORDER;EACH_EXACT_ROW_SCHEMA_PATH_SCHEMA_POINTER_KEYWORD_ATOM_ID_EXPECTED_AS_UTF16_JCS_PLUS_LF;CONCATENATE_WITH_NO_HEADER_OR_TRAILER"),
row_count:C(21578),occurrence_count:C(7517),coverage_atom_count:C(21578),
coverage_atom_counts_by_subject:A(I(0,10000000),12,12,false),
preimage_size_bytes:C(5102113),
sha256:C("286aa2a4477aa46f632c590020d3a49e1e147cef0194471d9893f8898a903915"))`.

`parity_v1`:
`O(schema_version:C("plamen.program_facts_gate3_schema_contract_parity.v1"),
contracts:R(parity_contracts),subject_rows:A(R(parity_subject_row),12,12,true),
occurrence_rows:A(R(parity_occurrence_row),1,10000000,true),
atom_rows:A(R(parity_atom_row),21578,21578,true),
atom_disposition_rows:A(R(parity_atom_disposition),21578,21578,true),
proof_rows:A(R(parity_proof_row),1,10000000,true),
vector_identity_rows:A(R(parity_vector_identity_row),1,10000000,true),
witness_decision_rows:A(R(parity_witness_decision_row),1,10000000,true),
pattern_occurrence_context_rows:A(R(parity_pattern_occurrence_row),521,521,true),
pattern_literal_rows:A(R(parity_pattern_literal_row),39,39,true),
pattern_sibling_context_rows:A(R(parity_pattern_sibling_row),41,41,true),
pattern_positive_conflict_rows:A(R(parity_pattern_conflict_row),1,1,true),
totals:R(parity_totals),subject_set_identity:R(parity_stream_identity),
occurrence_set_identity:R(parity_stream_identity),
atom_set_identity:R(parity_atom_set_identity),
atom_disposition_set_identity:R(parity_stream_identity),
proof_set_identity:R(parity_stream_identity),vector_set_identity:R(parity_stream_identity),
witness_set_identity:R(parity_stream_identity),
pattern_occurrence_context_set_identity:R(parity_stream_identity),
pattern_literal_set_identity:R(parity_stream_identity),
pattern_sibling_context_set_identity:R(parity_stream_identity),
pattern_positive_conflict_set_identity:R(parity_stream_identity),
parity_body_sha256:HEX)`.

The following rules are the complete local semantic closure for `parity_v1`.
They require no predecessor prose or schema store. `contracts` is the exact
parsed object formed from these four path/size/SHA-256 identities:

```text
schema_closure_amendment:
  architecture/program-facts-g3-00-schema-closure-amendment.md
  88187 / 85534326385e04c73d74f92c3dfa13b0b8702131bd3e97ce97bbd998e685b280
schema_closure_review:
  review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_CLOSURE_AMENDMENT_INDEPENDENT_REVIEW.v1.json
  9002 / c3dd6f630b9bd6c2ff73aacd386c35b3201659d2eead45be90bb6835e71edd4f
vector_clarification_amendment:
  architecture/program-facts-g3-00-schema-vector-clarification-amendment.md
  80218 / f03b07bea209dde4cf2cf8dcebd3e4c618a5fd56196c4448594a9d744136f7fa
vector_clarification_review:
  review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_VECTOR_CLARIFICATION_AMENDMENT_INDEPENDENT_REVIEW.v1.json
  15568 / 3db4b56a2132bbd5d8dd7cb59bb68cdb4e32aa5f109da55420b05b786fee5e92
```

`subject_rows` is in the exact order below. Each `schema.path` is the displayed
path, `schema_id` is `https://plamen.local/schemas/` plus its basename,
`vectors.path` is `review_fixtures/program_facts_runtime_gate3/schema_contracts/`
plus the basename plus `/conformance_vectors.v1.json`, and the remaining two
file-identity members are recomputed from those exact files. The three numeric
columns are respectively keyword occurrences, atoms, and pattern occurrences:

```text
0  rules/schemas/mechanical_program_facts.v3.schema.json                         652 1879 48
1  rules/schemas/mechanical_program_facts_debt.v3.schema.json                    626 1812 48
2  rules/schemas/mechanical_program_facts_receipt.v3.schema.json                 988 2950 67
3  rules/schemas/program_facts_active_selection.v1.schema.json                   769 2283 58
4  rules/schemas/program_facts_independent_review.v1.schema.json                 993 2881 41
5  rules/schemas/program_facts_phase_io_interface_vector.v1.schema.json          528 1445 32
6  rules/schemas/program_facts_public_generation.v2.schema.json                  678 1959 54
7  rules/schemas/program_facts_publication_arm.v2.schema.json                    693 2018 56
8  rules/schemas/program_facts_r19_seed_acceptance.v1.schema.json                521 1436 33
9  rules/schemas/program_facts_r19_seed_admission.v1.schema.json                 422 1160 31
10 rules/schemas/program_facts_source_identity_census.v1.schema.json             366  992 29
11 rules/schemas/program_facts_provider_registry.v2.schema.json                  281  763 24
```

The exact coverage-keyword order is `$ref`, `type`, `const`, `enum`, `required`,
`additionalProperties`, `propertyNames`, `properties`, `dependentRequired`,
`prefixItems`, `items`, `contains`, `minContains`, `maxContains`,
`minProperties`, `maxProperties`, `minItems`, `maxItems`, `uniqueItems`,
`minLength`, `maxLength`, `pattern`, `minimum`, `maximum`, `multipleOf`,
`allOf`, `anyOf`, `oneOf`, `not`, `if`, `then`, `else`, with ordinals
`000,010,020,030,040,050,060,070,080,090,100,110,111,112,120,121,130,
131,140,150,151,160,170,171,180,190,200,210,220,230,231,232`.
Traversal starts at each schema root and descends only through `$defs/<name>`,
`properties/<name>`, `propertyNames`, schema-valued `additionalProperties`,
`prefixItems/<canonical-index>`, schema-valued `items`, `contains`,
`allOf|anyOf|oneOf/<canonical-index>`, `not`, `if`, `then`, and `else`.
Object names use decoded UTF-16/JCS order, arrays use increasing canonical index,
RFC-6901 decode/re-encode must be byte-identical, and boolean schemas and
`const`/`enum` instances are not traversed. Occurrences sort by containing-node
pointer, the displayed keyword ordinal, then full keyword pointer; duplicate
pointers reject. `occurrence_rows` is exactly this complete 7,517-row traversal.

For each occurrence, atom rows use exactly the following order and expected
direction: `$ref` `ACCEPT_RESOLVED`/`REJECT_RESOLVED`; `type` one
`ACCEPT_<type>` in source member order then `REJECT_DISALLOWED_TYPE`; `const`
`ACCEPT_CONST`/`REJECT_UNEQUAL_SAME_TYPE`; `enum` one
`ACCEPT_MEMBER_<index>` in source order then `REJECT_UNKNOWN_SAME_TYPE`;
`required` `ACCEPT_COMPLETE` then one `REJECT_MISSING_<escaped-property>` in
source order; `additionalProperties:false` `ACCEPT_NO_EXTRA`/
`REJECT_UNKNOWN_FIELD`, or schema-valued `ACCEPT_EXTRA_VALUE`/
`REJECT_EXTRA_VALUE`; `propertyNames` `ACCEPT_NAME`/`REJECT_NAME`;
`properties` paired `ACCEPT_PROPERTY_<escaped-name>`/
`REJECT_PROPERTY_<escaped-name>` in UTF-16 name order; `dependentRequired`
`ACCEPT_TRIGGER_ABSENT`, `ACCEPT_TRIGGER_COMPLETE`, then each
`REJECT_<trigger>_MISSING_<dependent>` in source-list order; `prefixItems`
paired `ACCEPT_INDEX_<index>`/`REJECT_INDEX_<index>`; `items`
`ACCEPT_ITEM`/`REJECT_ITEM`; `contains` `ACCEPT_EXACT_LOWER` then
`ACCEPT_EXACT_UPPER` when `maxContains` exists, followed by applicable `REJECT_TOO_FEW` and
`REJECT_TOO_MANY`; each of `minContains`, `maxContains`, `minProperties`,
`maxProperties`, `minItems`, `maxItems`, `minLength`, `maxLength`, `minimum`,
and `maximum` `ACCEPT_BOUNDARY` then `REJECT_ONE_STEP_OUTSIDE`;
`uniqueItems` `ACCEPT_DISTINCT_PAIR`/
`REJECT_DUPLICATE_PAIR`; `pattern` `ACCEPT_PATTERN`/`REJECT_PATTERN`;
`multipleOf` `ACCEPT_MULTIPLE`/`REJECT_NONMULTIPLE`; `allOf` `ACCEPT_ALL`
then `REJECT_BRANCH_<index>`; `anyOf` `ACCEPT_BRANCH_<index>` then
`REJECT_ZERO_MATCH`; `oneOf` `ACCEPT_EXACT_BRANCH_<index>` then
`REJECT_ZERO_MATCH` and `REJECT_MULTIPLE_MATCH`; `not`
`ACCEPT_CHILD_INVALID`/`REJECT_CHILD_VALID`; `if` `ACCEPT_CONDITION_TRUE`/
`ACCEPT_CONDITION_FALSE`; `then` `ACCEPT_SELECTED_THEN`/
`REJECT_SELECTED_THEN`; and `else` `ACCEPT_SELECTED_ELSE`/
`REJECT_SELECTED_ELSE`. Every `ACCEPT` atom has expected `VALID`; every
`REJECT` atom has expected `INVALID`. A tagged closed-object `oneOf` appends,
for each branch index, exactly `TAGGED_BRANCH_<i>_ACCEPT`,
`TAGGED_BRANCH_<i>_REJECT_ZERO_BRANCH`,
`TAGGED_BRANCH_<i>_REJECT_UNKNOWN_TAG`,
`TAGGED_BRANCH_<i>_REJECT_MISSING_TAG_BRANCH_PAYLOAD`,
`TAGGED_BRANCH_<i>_REJECT_VALID_BRANCH_UNKNOWN_FIELD`, and
`TAGGED_BRANCH_<i>_REJECT_CROSS_BRANCH_FIELD`. This produces exactly 21,578
`atom_rows` in roster/occurrence/display order and per-subject counts
`[1879,1812,2950,2283,2881,1445,1959,2018,1436,1160,992,763]`.

Every atom has exactly one same-ordinal disposition. `VECTOR` has a nonempty
UTF-8-sorted duplicate-free vector-ID array; `IMPOSSIBLE` has `vector_ids:[]`
and exactly one matching proof. No solver, timeout, allocation failure, absent
vector, candidate exhaustion, or inferred finite domain is a proof. Proof keys
sort by UTF-16 over `(subject_schema_id,schema_pointer,atom_id,direction,
predicate_id)`. NEG-01 through NEG-13 have respectively these exact proof
values, with metavariables replaced by the source-derived values described here:

```text
NEG-01 {"keyword":"maxItems","value":10000000}
NEG-02 {"keyword":"minItems","value":0}
NEG-03 {"keyword":"maxProperties","value":4096}
NEG-04 {"keyword":"minProperties","value":0}
NEG-05 {"global_string_ceiling_bytes":16384,"keyword":"maxLength","value":16384}
NEG-06 {"keyword":"minLength","value":0}
NEG-07 {"keyword":"maximum","value":9007199254740991}
NEG-08 {"keyword":"minimum","value":-9007199254740991}
NEG-09 {"integer_only_domain":true,"keyword":"multipleOf","value":1}
NEG-10 {"keyword":"type","permitted_types":["null","boolean","integer","string","array","object"]}
NEG-11 {"keyword":"if"}
NEG-12 {"branch_const_cj":[CJ of each direct required discriminator const in branch order],"discriminator":first valid UTF-16 property name}
NEG-13 {"delegated_child_pointer":selected pointer,"resolution_chain":[origin then each same-document sole-$ref target through terminal {}],"terminal":{}}
```

NEG-12 requires all branch discriminator consts pairwise unequal. NEG-13 applies
only to `$ref/REJECT_RESOLVED`, `properties/REJECT_PROPERTY_*`,
`propertyNames/REJECT_NAME`, schema-valued
`additionalProperties/REJECT_EXTRA_VALUE`, `prefixItems/REJECT_INDEX_*`,
schema-valued `items/REJECT_ITEM`, or `allOf/REJECT_BRANCH_*`; its chain permits
only same-document sole-`$ref` objects and terminal `{}`. The exact 12 current
NEG-13 atoms are `REJECT_PROPERTY_instance` at
`/$defs/gate3_schema_conformance_vectors_v1/properties/vectors/items/properties`
with selected child ending `/instance`, one per subject.

NEG-14 proof is exactly `{"enum_jset":["null"],"type":"null"}` and matches
only `enum/REJECT_UNKNOWN_SAME_TYPE` with direct scalar `type:"null"` and the
exact member-CJ set. NEG-15 is exactly
`{"enum_jset":["false","true"],"type":"boolean"}` under the analogous
direct boolean rule. NEG-16 matches only
`TAGGED_BRANCH_<i>_REJECT_CROSS_BRANCH_FIELD`; every branch must be a direct
closed object (possibly through an acyclic same-document sole-`$ref` chain), the
first UTF-16 candidate property is required with pairwise-distinct direct consts,
and `(union other branch property names) - selected branch property names` must
be empty. Its proof has exactly `{branch_index,discriminator,
discriminator_const_cj,other_minus_selected:[],property_sets,union_pointer}`;
each property-set row is UTF-16 sorted and branch order is preserved. Exactly
six current atoms match: branches 0/1/2 at
`/properties/nonsemantic_transport/oneOf` with property set
`["invocation_label","wrapper_file_identity"]`, and branches 0/1/2 at
`/properties/replay/oneOf` with property set `["outcome","semantic_source"]`,
all in `mechanical_program_facts_receipt.v3.schema.json`.

POS-01 matches only `maxItems:10000000/ACCEPT_BOUNDARY` with exact proof
`{"ceiling_bytes":16777216,"comma_bytes":9999999,"element_count":10000000,
"minimum_array_cj_bytes":20000001,"minimum_element_bytes":1,
"structural_bytes":2}`; there are exactly 221 matches. POS-02 matches only
`minLength:1/ACCEPT_BOUNDARY` with direct `type:"string"` and pattern
`^https://plamen\.local/schemas/[A-Za-z0-9._-]+\.schema\.json$`; its proof is
exactly `{"declared_min_length":1,"literal_prefix":"https://plamen.local/schemas/",
"literal_prefix_code_points":29,"literal_suffix":".schema.json",
"literal_suffix_code_points":12,"minimum_basename_code_points":1,
"minimum_match_code_points":42}` and there are exactly 13 matches. POS-03
matches only direct `items:false/ACCEPT_ITEM`, has exact proof
`{"child":false,"keyword":"items"}`, and has exactly 11 matches. These positive
proofs have direction `POSITIVE`; NEG-01 through NEG-16 use `NEGATIVE`.
Impossible atoms remain in the atom denominator and have no vector ID.

`witness_decision_rows` has exactly one row. It is the WIT-01 decision for
subject ID `https://plamen.local/schemas/program_facts_provider_registry.v2.schema.json`,
pointer `/properties/registry_body_sha256/pattern`, atom `ACCEPT_PATTERN`, and
predicate `WIT-01-DIRECT-HEX64-CONST`; its proof is exactly
`{"const":"56962c461653c11e76201987e2bc98c7f9d50e4e0db7128e1b7525c70f878d89",
"length":64,"pattern":"^[0-9a-f]{64}$"}` and its vector ID joins the sole vector
that uses that const as the positive instance. No other witness override exists.

The pattern occurrence traversal is the traversal above, emitting a containing
object before descendants and resetting `occurrence_ordinal` per subject. Each
member-state, `direct_other`, sibling-name list, and sibling schema is an exact
physical direct-member projection. Occurrence rows number 521 with per-subject
counts `[48,48,67,58,41,32,54,56,33,31,29,24]`; literal rows are the UTF-16-
sorted 39-row deduplication; sibling rows are the lexicographically CJ-sorted
41-row deduplication. Conflict rows preserve occurrence order and are produced
by checking the chosen positive against direct `type,minLength,maxLength,const,
enum` in that order, followed by one `UNMODELED_DIRECT_` reason for any other
sorted direct names. There is exactly one conflict, with this exact parsed row:

```json
{"direct_sibling_schema":{"const":"56962c461653c11e76201987e2bc98c7f9d50e4e0db7128e1b7525c70f878d89","maxLength":64,"minLength":64,"type":"string"},"keyword_pointer":"/properties/registry_body_sha256/pattern","literal_pattern":"^[0-9a-f]{64}$","positive_witness":"0000000000000000000000000000000000000000000000000000000000000000","reasons":["DIRECT_CONST"],"subject_path":"rules/schemas/program_facts_provider_registry.v2.schema.json","subject_schema_id":"https://plamen.local/schemas/program_facts_provider_registry.v2.schema.json"}
```

The four stream identities are:

```text
pattern_occurrence_context 521 / 553621 / fd49a3e86c7f44f0ccbd8d7ac373d9c5938401816aebe3caf48d80575fb1162c
pattern_literal             39 /   1837 / a999487cb7040fe4c250c568016dd4eaf14342699013edce1e8a20fbe85d20cd
pattern_sibling_context     41 /   5015 / 560a11e14db188e537e5b517a1068590edc375aa213c0bc37d8a31f6fde16229
pattern_positive_conflict    1 /    534 / d88fec0b4309965311a2405ce1c56639f0ba42bf9ddb5e09f210bf18b43eddb3
```

Each triple is `row_count/preimage_size_bytes/sha256` under `CJ_ROW_LF_V1`.
Every non-atom stream identity is recomputed as the concatenation of
`CJ(row)||LF` in its normative array order, with no header/trailer. Mappings are
subject/subject rows; occurrence/occurrence rows; disposition/atom ordinal;
proof/proof-key order; vector/`(subject_ordinal,UTF8(vector_id))`; witness/
witness-key order; and each pattern identity/its displayed stream. Logical row
keys are duplicate-free. `atom_set_identity.coverage_atom_counts_by_subject` is
the exact 12-number atom array above and its remaining constants are those in
the schema definition. Every stream's `row_count`, byte count, and digest must
recompute; count-only or digest-only agreement is insufficient.

For each subject and globally, vector/impossible-positive/impossible-negative/
witness counts equal their exact joined row projections. All additive top
totals are the sums of the 12 subject values; the fixed totals are 12 subjects,
7,517 occurrences, 21,578 atoms, 521 pattern occurrences, 39 literals, 41
sibling contexts, and one conflict. Every vector disposition joins at least one
vector row, every vector row joins its exact singleton `covers` atom pointer and
subject vector identity/body digest, every impossible disposition joins exactly
one byte-identical proof row in both directions, and the WIT/conflict join is
one-to-one. Orphans, duplicate keys, ambiguous joins, extras, omissions, or an
order mismatch reject.

Finally, `parity_body_sha256 = SHA-256(CJ(parity_v1 without only
parity_body_sha256))`. Generator, evaluator, and cross-check must independently
emit parsed-value-identical parity objects and identical `CJ` bytes, with every
row array and all 11 identities compared in order and in both difference
directions. No majority, shared result, count-only comparison, digest-only
comparison, source review, runtime manifest, generated output, or later artifact
participates in selecting or completing this fragment.

<!-- PARITY_V1_LOCAL_FRAGMENT_END -->

`parity_v1_fragment_source_sha256` is the lowercase SHA-256 of the exact 22,213
UTF-8 bytes beginning immediately after the BEGIN marker's LF and ending
immediately before the END marker's `<`, including the displayed blank-line LFs:
`97844a817f292066ae73dc554f7f747148e4569648dd783da7fdf0eb72f6ad3d`.
Every renderer must recompute that value before expansion. It is an amendment
construction pin, not a later-review agreement.

### 14.2 Complete root definitions

`runtime_build_plan_root`:
`O(schema_version:C("plamen.program_facts_parity_runtime_build_plan_lock.v1"),
build_id:S(39,39,"^pfg3rb-[0-9a-f]{32}$"),builder_source:R(file_identity),
builder_source_review:R(file_identity),amendment:R(file_identity),
amendment_review:R(file_identity),runtime_archive:R(runtime_archive),
bootstrap_source:R(file_identity),bootstrap_source_review:R(file_identity),
producer_sources:T(R(file_identity),R(file_identity),R(file_identity)),
producer_source_reviews:T(R(file_identity),R(file_identity),R(file_identity)),
wheels:T(R(locked_wheel),R(locked_wheel),R(locked_wheel),R(locked_wheel),R(locked_wheel),R(locked_wheel)),
toolchain:A(R(runtime_build_tool),1,16,true),rules:R(runtime_build_rules),
expected_output_members:A(R(bundle_member),1,20000,true),
disposition:C("LOCKED_PRIVATE_RUNTIME_BUILD_INPUT_ONLY"),
accepted_scope:C(["DETERMINISTIC_PRIVATE_RUNTIME_BUILD_ONLY"]),
authority_ceiling:R(authority_v2),build_body_sha256:HEX)`.
The six `wheels` tuple items must select the six distinct `locked_wheel` union
branches in the exact section-4.0 order. `build_id` is
`"pfg3rb-" || SHA-256(CJ({domain:"PROGRAM_FACTS_G3_PARITY_RUNTIME_BUILD_V1",
builder_source,builder_source_review,bootstrap_source,bootstrap_source_review,
producer_sources,producer_source_reviews,
runtime_archive,wheels,rules,
expected_output_members}))[0:32]`; the host-bound
toolchain is excluded only from that logical ID and remains covered by
`build_body_sha256`.

`runtime_build_review_root`:
`O(schema_version:C("plamen.program_facts_parity_runtime_build_plan_lock_review.v1"),
review_id:S(40,40,"^pfg3rbr-[0-9a-f]{32}$"),subject:R(file_identity),
build_id:S(39,39,"^pfg3rb-[0-9a-f]{32}$"),amendment:R(file_identity),
amendment_review:R(file_identity),reviewer:R(reviewer),
independence:O(builder_author_separate:C(true),plan_author_separate:C(true),
all_input_source_authors_separate:C(true),
runtime_closure_reviewer_separate:C(true),no_self_generated_evidence:C(true),
workspace_clean:C(true)),checks:A(R(runtime_build_check),8,8,true),
findings:A(R(finding),0,10000000,true),open_findings:A(ID,0,10000000,true),
disposition:E("PASS_LOCKED_PRIVATE_RUNTIME_BUILD_ONLY","REJECTED"),
accepted_scope:C(["DETERMINISTIC_PRIVATE_RUNTIME_BUILD_REVIEW_ONLY"]),
authority_ceiling:R(authority_v2),review_body_sha256:HEX)`.

`runtime_closure_root`:
`O(schema_version:C("plamen.program_facts_parity_runtime_closure.v2"),
closure_id:S(39,39,"^pfg3rc-[0-9a-f]{32}$"),
disposition:C("DECLARED_EXACT_PRIVATE_RUNTIME_CLOSURE_ONLY"),
accepted_scope:C(["RUNTIME_CLOSURE_INPUT_NO_SPAWN_AUTHORITY"]),
host_profile:R(host_profile),
bundle_root:R(bundle_root),interpreter:R(manifest_interpreter),
runtime_build:R(runtime_build_binding),
path_configuration:R(path_configuration),bootstrap:R(bootstrap),
bundle_members:A(R(bundle_member),1,20000,true),
producer_source_exclusions:A(R(producer_source_exclusion),3,3,true),
allowed_distributions:A(R(distribution),6,6,true),
allowed_modules:A(R(module_origin),1,20000,true),
import_inventory:R(import_inventory),
input_snapshot_policy:R(input_snapshot_policy),
system_loader_boundary:R(system_loader_boundary),
role_native_image_projections:A(R(role_native_image_projection),3,3,true),limits:R(limits),
authority_ceiling:R(authority_v2),closure_body_sha256:HEX)`.

`candidate_root`:
`O(schema_version:C("plamen.program_facts_gate3_schema_contract_parity_candidate.v2"),
candidate_id:S(39,39,"^pfg3pc-[0-9a-f]{32}$"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),
attempt_ordinal:I(0,7),role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
principal:R(producer_principal),source:R(file_identity),launcher:R(launcher_binding),
runtime_closure:R(runtime_closure_binding),
input_snapshot:R(input_snapshot_projection),host_receipt:R(host_receipt),
requested_output:PATH,candidate_path:PATH,parity:R(parity_v1),
runtime_observation:R(runtime_observation),authority_ceiling:R(authority_v2),
candidate_body_sha256:HEX)`.

`evidence_root`:
`O(schema_version:C("plamen.program_facts_gate3_schema_contract_parity_evidence.v2"),
evidence_id:S(40,40,"^pfg3pe2-[0-9a-f]{32}$"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),
attempt_ordinal:I(0,7),role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
producer:R(producer_binding),launcher:R(launcher_binding),execution:R(execution),
runtime_closure:R(runtime_closure_observed),
input_snapshot:R(input_snapshot_projection),isolation:R(isolation),
native_image_receipt:R(native_image_projection),candidate:R(candidate_projection),
parity:R(parity_v1),transaction_evidence_path:PATH,completion_path:PATH,
authority_ceiling:R(authority_v2),evidence_body_sha256:HEX)`.

`completion_root`:
`O(schema_version:C("plamen.program_facts_gate3_schema_contract_parity_completion.v2"),
completion_id:S(40,40,"^pfg3pcm-[0-9a-f]{32}$"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
state:C("COMMITTED"),role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
principal:R(producer_principal),producer:R(producer_binding),launcher:R(launcher_binding),
runtime_closure:R(runtime_closure_observed),host_receipt:R(host_receipt),
input_snapshot:R(input_snapshot_projection),
native_image_receipt:R(native_image_projection),candidate:R(candidate_projection),
evidence:R(evidence_projection),completion_path:PATH,
commit_primitive:E("LINUX_RENAMEAT2_NOREPLACE_DIRFD_FSYNC_V1",
"WINDOWS_SETFILEINFORMATIONBYHANDLE_RENAME_NO_REPLACE_V1"),
commit_linearization:C("FINAL_MARKER_CREATE_ONLY_PUBLICATION"),
completion_state:R(completion_state),disposition:C("CAPTURE_COMPLETE_ONLY"),
accepted_scope:C(["G3_00_PARITY_CAPTURE_COMPLETION_ONLY"]),
authority_ceiling:R(authority_v2),
completion_body_sha256:HEX)`.

`scenario_manifest_root`:
`O(schema_version:C("plamen.program_facts_g3_00_parity_launcher_scenario_manifest.v1"),
manifest_id:S(39,39,"^pfg3sm-[0-9a-f]{32}$"),
subject:O(amendment:R(file_identity),amendment_review:R(file_identity)),
scope:C("G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_FIXTURE_ONLY"),
disposition:C("DENOMINATOR_ONLY"),scenarios:A(R(scenario),52,52,true),
authority_ceiling:R(authority_v2),manifest_body_sha256:HEX)`.
For the rendered manifest schema, `scenarios:A(...)` is narrowed to
`scenarios:C(<the parsed 52-object JSON array printed in section 10>)`; angle
brackets are metanotation and are not emitted. The standalone `scenario`
definition remains present for negative-fixture localization, but cannot widen
the root constant.
Before the red run, the fixture bootstrap renders this one schema in memory
without writing any schema or v2 implementation file and runs
`Draft202012Validator.check_schema`; later schema construction repeats the
identical operation before writing `CF`. Both parse the section-10 array,
recompute both fixed digests,
and validate one complete manifest instance whose ID/body digest have been
computed by section 14.3. It then validates each of the 52 rows against the
local `scenario` definition and requires the root constant comparison to pass.
Deleting, reordering, or mutating any row must fail the root even if the
standalone row shape still passes. These 54 validations are recorded in the
red evidence; zero setup errors includes all of them.

`scenario_execution_root`:
`O(schema_version:C("plamen.program_facts_g3_00_parity_launcher_scenario_execution_evidence.v1"),
evidence_id:S(39,39,"^pfg3se-[0-9a-f]{32}$"),phase:E("RED","GREEN"),
disposition:E("EXPECTED_FAILURE_CHRONOLOGY_ONLY",
"PASS_FIXTURE_AND_NO_SPAWN_IMPLEMENTATION_ONLY"),
accepted_scope:C(["G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_FIXTURE_ONLY"]),
subject:R(fixture_subject),amendment:R(file_identity),
amendment_review:R(file_identity),scenario_manifest:R(file_identity),
harness:R(file_identity),launcher_candidate:R(file_identity),
successor_inputs:A(R(file_identity),39,39,true),interpreter:R(fixture_interpreter),
command:T(ABS,C("-I"),C("-S"),C("-B"),ABS,E("--phase=RED","--phase=GREEN")),
instantiated_argv_sha256:HEX,cwd:R(fixture_cwd),environment:C({}),method_count:C(52),
setup_error_count:C(0),scenario_results:A(R(scenario_result),52,52,true),
authority_ceiling:R(authority_v2),evidence_body_sha256:HEX)`. `RED` pairs only
with `EXPECTED_FAILURE_CHRONOLOGY_ONLY`; `GREEN` pairs only with the passing
disposition. Both use the same exact ordered 39 successor identities. The schema renders these as two exclusive
`allOf` `if/then` branches by wrapping the displayed `O` expression in
`AND` with this exact parsed constraint:

```json
{"allOf":[{"if":{"properties":{"phase":{"const":"RED"}},"required":["phase"]},"then":{"properties":{"disposition":{"const":"EXPECTED_FAILURE_CHRONOLOGY_ONLY"}}}},{"if":{"properties":{"phase":{"const":"GREEN"}},"required":["phase"]},"then":{"properties":{"disposition":{"const":"PASS_FIXTURE_AND_NO_SPAWN_IMPLEMENTATION_ONLY"}}}}]}
```

The exact `successor_inputs` path order, with each row instantiated as its
stable `file_identity`, is:

```text
rules/schemas/program_facts_g3_00_parity_launcher_runtime_closure_amendment_review.v1.schema.json
rules/schemas/program_facts_parity_runtime_build_plan_lock.v1.schema.json
rules/schemas/program_facts_parity_runtime_build_plan_lock_review.v1.schema.json
rules/schemas/program_facts_parity_runtime_closure.v2.schema.json
rules/schemas/program_facts_parity_runtime_closure_review.v1.schema.json
rules/schemas/program_facts_parity_source_review.v1.schema.json
rules/schemas/program_facts_parity_candidate.v2.schema.json
rules/schemas/program_facts_parity_evidence.v2.schema.json
rules/schemas/program_facts_parity_completion.v2.schema.json
rules/schemas/program_facts_parity_scenario_manifest.v1.schema.json
rules/schemas/program_facts_parity_scenario_execution_evidence.v1.schema.json
rules/schemas/program_facts_parity_launcher_implementation_review.v1.schema.json
rules/schemas/program_facts_parity_transaction_journal.v2.schema.json
rules/schemas/program_facts_parity_staged_marker.v2.schema.json
rules/schemas/program_facts_parity_transaction_lock.v2.schema.json
rules/schemas/program_facts_parity_coordination_lock_quarantine.v1.schema.json
rules/schemas/program_facts_parity_quarantine.v2.schema.json
rules/schemas/program_facts_parity_quarantine_locator.v1.schema.json
rules/schemas/program_facts_parity_transaction_head.v2.schema.json
rules/schemas/program_facts_parity_attempt.v2.schema.json
rules/schemas/program_facts_parity_native_image_receipt.v2.schema.json
rules/schemas/program_facts_parity_vector_bundle_candidate.v1.schema.json
rules/schemas/program_facts_parity_vector_bundle_capture_receipt.v1.schema.json
rules/schemas/program_facts_parity_vector_capture_transaction.v2.schema.json
rules/schemas/program_facts_parity_pre_aggregate_lineage.v1.schema.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/parity_bootstrap_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/build_private_runtime_v1.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_BOOTSTRAP_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/RUNTIME_BUILDER_V1_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/GENERATOR_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/EVALUATOR_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/CROSSCHECK_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_RUNTIME_BUILD_PLAN_LOCK.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_RUNTIME_BUILD_PLAN_LOCK_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_LAUNCHER_RUNTIME_CLOSURE.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_LAUNCHER_RUNTIME_CLOSURE_REVIEW.v1.json
```

`subject.harness == harness`, `subject.launcher_under_test ==
launcher_candidate`, and both equalities are parsed-value equality. RED's
launcher is the exact pinned section-1 first candidate; GREEN's launcher path
is the exact section-2 v2 launcher. `command[0]` equals
`interpreter.absolute_path`; `command[4]` is the canonical absolute path formed
by resolving `harness.path` beneath `cwd.absolute_path`; and `command[5]` is
exactly `"--phase=" || phase`. The digest is:

```text
instantiated_argv_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_SCENARIO_FIXTURE_ARGV_V1",
  argv:command
}))
```

The RED ambient interpreter is never a portable `file_identity`: its absolute
path, retained-handle locator, size/hash, implementation, and version are all
recorded by `fixture_interpreter` before invocation.

`amendment_review_root`:
`O(schema_version:C("plamen.program_facts_g3_00_parity_launcher_runtime_closure_amendment_review.v1"),
review_id:S(41,41,"^pfg3lrcr-[0-9a-f]{32}$"),subject:R(file_identity),
normative_parents:A(R(file_identity),2,2,true),
candidate_inputs:A(R(file_identity),5,5,true),reviewer:R(reviewer),
independence:C(` followed by the exact section-3 independence object and `),
checks:A(R(amendment_check),25,25,true),findings:A(R(finding),0,10000000,true),
open_findings:A(ID,0,10000000,true),
disposition:E("PASS_G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_FOR_FIXTURE_AND_IMPLEMENTATION_ONLY","REJECTED"),
accepted_scope:C(["G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_CONTRACT"]),
authority_ceiling:R(authority_v2),review_body_sha256:HEX)`. Its check IDs are
exactly the ordered 20-ID roster in section 11. The two parent and five input arrays are the
literal section-1 identities, in table order.

`closure_review_root`:
`O(schema_version:C("plamen.program_facts_g3_00_parity_runtime_closure_review.v1"),
review_id:S(40,40,"^pfg3rcr-[0-9a-f]{32}$"),subject:R(file_identity),
amendment:R(file_identity),amendment_review:R(file_identity),reviewer:R(reviewer),
independence:O(runtime_bundle_builder_separate:C(true),
runtime_closure_reviewer_separate:C(true),source_authors_separate:C(true),
launcher_implementer_separate:C(true),no_self_generated_evidence:C(true),
workspace_clean:C(true)),checks:A(R(closure_check),9,9,true),
findings:A(R(finding),0,10000000,true),open_findings:A(ID,0,10000000,true),
disposition:E("PASS_EXACT_PRIVATE_RUNTIME_CLOSURE_ONLY","REJECTED"),
accepted_scope:C(["EXACT_PRIVATE_RUNTIME_CLOSURE_NO_SPAWN_AUTHORITY"]),
authority_ceiling:R(authority_v2),review_body_sha256:HEX)`. The ordered check
enum is `RCV-01-MANIFEST-IDENTITY`, `RCV-02-BUNDLE-TREE-BIDIRECTIONAL`,
`RCV-03-DISTRIBUTION-RECORD-BIDIRECTIONAL`, `RCV-04-MODULE-ORIGINS`,
`RCV-05-ROLE-IMPORT-CLOSURES`, `RCV-06-SYSTEM-LOADER-AND-NATIVE-PROJECTIONS`,
`RCV-07-PATH-AND-LIMITS`, `RCV-08-NONAUTHORITY`,
`RCV-09-BUILD-PLAN-AND-PRODUCER-SOURCE-EXCLUSION`.

`source_review_root`:
`O(schema_version:C("plamen.program_facts_g3_00_parity_source_review.v1"),
review_id:S(39,39,"^pfg3sr-[0-9a-f]{32}$"),
source_kind:E("BOOTSTRAP","RUNTIME_BUILDER","GENERATOR","EVALUATOR","CROSSCHECK"),
subject:R(file_identity),reviewed_modes:A(E("PARITY_V2","VECTOR_CAPTURE_V1"),1,2,true),
amendment:R(file_identity),
amendment_review:R(file_identity),schema_files:A(R(file_identity),25,25,true),
reviewer:R(reviewer),independence:O(subject_author_separate:C(true),
peer_source_authors_separate:C(true),launcher_implementer_separate:C(true),
runtime_builder_separate:C(true),no_self_generated_evidence:C(true),
workspace_clean:C(true)),checks:A(R(source_check),8,8,true),
findings:A(R(finding),0,10000000,true),open_findings:A(ID,0,10000000,true),
disposition:E("PASS_BOOTSTRAP_SOURCE_FOR_RUNTIME_CLOSURE_ONLY",
"PASS_RUNTIME_BUILDER_SOURCE_FOR_RUNTIME_BUILD_ONLY",
"PASS_GENERATOR_SOURCE_FOR_RUNTIME_CLOSURE_ONLY",
"PASS_EVALUATOR_SOURCE_FOR_RUNTIME_CLOSURE_ONLY",
"PASS_CROSSCHECK_SOURCE_FOR_RUNTIME_CLOSURE_ONLY","REJECTED"),
accepted_scope:C(["PRE_MANIFEST_SOURCE_SEMANTICS_ONLY"]),
authority_ceiling:R(authority_v2),
review_body_sha256:HEX)`. The ordered check enum is
`SRV-01-SOURCE-IDENTITY`, `SRV-02-NO-PEER-IMPORT`,
`SRV-03-NO-SHARED-ALGORITHM`, `SRV-04-SEMANTIC-IMPORT-DECLARATIONS`,
`SRV-05-TRANSPORT-OR-BUILDER-BOUNDARY`, `SRV-06-NONAUTHORITY`,
`SRV-07-VECTOR-CAPTURE-BOOTSTRAP-MODE`. An exclusive
`if/then` branch maps each `source_kind` to its same-named passing disposition;
`REJECTED` is valid for every kind. The exact added constraint is:

```json
{"allOf":[{"if":{"properties":{"source_kind":{"const":"BOOTSTRAP"}},"required":["source_kind"]},"then":{"properties":{"disposition":{"enum":["PASS_BOOTSTRAP_SOURCE_FOR_RUNTIME_CLOSURE_ONLY","REJECTED"]}}}},{"if":{"properties":{"source_kind":{"const":"RUNTIME_BUILDER"}},"required":["source_kind"]},"then":{"properties":{"disposition":{"enum":["PASS_RUNTIME_BUILDER_SOURCE_FOR_RUNTIME_BUILD_ONLY","REJECTED"]}}}},{"if":{"properties":{"source_kind":{"const":"GENERATOR"}},"required":["source_kind"]},"then":{"properties":{"disposition":{"enum":["PASS_GENERATOR_SOURCE_FOR_RUNTIME_CLOSURE_ONLY","REJECTED"]}}}},{"if":{"properties":{"source_kind":{"const":"EVALUATOR"}},"required":["source_kind"]},"then":{"properties":{"disposition":{"enum":["PASS_EVALUATOR_SOURCE_FOR_RUNTIME_CLOSURE_ONLY","REJECTED"]}}}},{"if":{"properties":{"source_kind":{"const":"CROSSCHECK"}},"required":["source_kind"]},"then":{"properties":{"disposition":{"enum":["PASS_CROSSCHECK_SOURCE_FOR_RUNTIME_CLOSURE_ONLY","REJECTED"]}}}}]}
```

The renderer wraps `source_review_root` in `AND(the displayed O expression,
the displayed parsed constraint)`; it does not merge or reinterpret members.

`implementation_review_root`:
`O(schema_version:C("plamen.program_facts_g3_00_parity_launcher_v2_implementation_review.v1"),
review_id:S(39,39,"^pfg3ir-[0-9a-f]{32}$"),subjects:O(
schema_files:A(R(file_identity),25,25,true),bootstrap:R(file_identity),
runtime_builder:R(file_identity),runtime_build_plan:R(file_identity),
runtime_build_review:R(file_identity),
fixture_harness:R(file_identity),
producer_sources:A(R(file_identity),3,3,true),
source_reviews:A(R(file_identity),5,5,true),runtime_manifest:R(file_identity),
runtime_review:R(file_identity),scenario_manifest:R(file_identity),
red_evidence:R(file_identity),green_evidence:R(file_identity),
vector_capture_source:R(file_identity),launcher:R(file_identity)),
amendment:R(file_identity),
amendment_review:R(file_identity),reviewer:R(reviewer),
independence:O(all_subject_authors_separate:C(true),
all_source_reviewers_separate:C(true),runtime_closure_reviewer_separate:C(true),
native_host_validator_separate:C(true),no_self_generated_evidence:C(true),
workspace_clean:C(true)),checks:A(R(implementation_check),22,22,true),
findings:A(R(finding),0,10000000,true),open_findings:A(ID,0,10000000,true),
disposition:E("PASS_G3_00_PARITY_LAUNCHER_V2_CONSTRUCTION_NO_SPAWN_ONLY","REJECTED"),
accepted_scope:C(["G3_00_PARITY_LAUNCHER_V2_NO_SPAWN_CONSTRUCTION_ONLY"]),
authority_ceiling:R(authority_v2),review_body_sha256:HEX)`. Its ordered check
enum is the exact 17-ID roster in sections 11 and 16.6.

`pre_aggregate_lineage_root`:
`O(schema_version:C("plamen.program_facts_g3_00_parity_pre_aggregate_lineage.v1"),
lineage_id:S(40,40,"^pfg3lin-[0-9a-f]{32}$"),
clarification:R(file_identity),clarification_review:R(file_identity),
amendment:R(file_identity),amendment_review:R(file_identity),
scenario_manifest:R(file_identity),harness:R(file_identity),
green_evidence:R(file_identity),implementation_review:R(file_identity),
launcher:R(file_identity),runtime_closure:R(runtime_closure_binding),
role_lineages:T(R(lineage_role_row),R(lineage_role_row),R(lineage_role_row)),
common_parity_projection:R(lineage_parity_projection),reviewer:R(reviewer),
independence:O(all_producer_authors_separate:C(true),
launcher_author_separate:C(true),fixture_author_separate:C(true),
implementation_reviewer_separate:C(true),materializer_author_separate:C(true),
all_per_schema_reviewers_separate:C(true),aggregate_reviewer_separate:C(true),
no_self_generated_evidence:C(true),workspace_clean:C(true)),
checks:A(R(lineage_check),5,5,true),
disposition:E("PASS_PRE_AGGREGATE_V2_EVIDENCE_LINEAGE_MAPPING_ONLY","REJECTED"),
accepted_scope:C(["G3_00_PRE_AGGREGATE_EVIDENCE_LINEAGE_ONLY"]),
authority_ceiling:R(authority_v2),lineage_body_sha256:HEX)`. The tuple branches
must be generator, evaluator, and cross-check in that order; the two accepted
clarification identities are the exact section-1 normative parents; and the
amendment/review, GREEN chain, implementation review, launcher, runtime, source
reviews, and all three completed role chains are opened and joined. The five
check IDs occur exactly once in displayed order. Passing requires every result
`PASS`, exact common parity projections, and the exact crosscheck-v2 source and
GREEN-successor chain required by section 6.1.

`attempt_root`:
`O(schema_version:C("plamen.program_facts_parity_attempt.v2"),
attempt_id:S(39,39,"^pfg3pa-[0-9a-f]{32}$"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
state:C("PREPARED"),
paths:R(attempt_paths),inputs:R(attempt_inputs),
profile_writable_roots:A(R(profile_writable_root),4,4,true),
created_descendants:C([]),
artifacts:R(attempt_artifacts),last_error:Q(R(transaction_error)),
disposition:C("NONAUTHORITY_ATTEMPT_RECORD_ONLY"),
accepted_scope:C(["TRANSACTION_PRIVATE_NONAUTHORITY"]),
authority_ceiling:R(authority_v2),attempt_body_sha256:HEX)`.

`journal_root`:
`O(schema_version:C("plamen.program_facts_parity_transaction_journal.v2"),
journal_id:S(39,39,"^pfg3pj-[0-9a-f]{32}$"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),
journal_ordinal:I(0,9007199254740991),previous_journal:Q(R(artifact_ref)),
attempt_ordinal:I(0,7),attempt_id:S(39,39,"^pfg3pa-[0-9a-f]{32}$"),
role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
state:E("PREPARED","CHILD_COMPLETE","CANDIDATE_STAGED","NATIVE_IMAGES_VALIDATED","EVIDENCE_STAGED",
"EVIDENCE_VALIDATED","MARKER_STAGED","COMMITTED","ABORTED",
"QUARANTINED","EXHAUSTED"),
paths:R(attempt_paths),inputs:R(attempt_inputs),artifacts:R(attempt_artifacts),
child_capture:Q(R(child_capture)),last_error:Q(R(transaction_error)),
created_descendants:A(R(created_descendant_identity),0,20000,true),
disposition:C("NONAUTHORITY_TRANSACTION_JOURNAL_ONLY"),
accepted_scope:C(["TRANSACTION_PRIVATE_NONAUTHORITY"]),
authority_ceiling:R(authority_v2),
journal_body_sha256:HEX)`.

`head_root`:
`O(schema_version:C("plamen.program_facts_parity_transaction_head.v2"),
head_id:S(39,39,"^pfg3ph-[0-9a-f]{32}$"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),
head_revision:I(0,9007199254740991),predecessor_head_body_sha256:Q(HEX),
journal:R(artifact_ref),transaction_state:E("PREPARED","CHILD_COMPLETE",
"CANDIDATE_STAGED","NATIVE_IMAGES_VALIDATED","EVIDENCE_STAGED","EVIDENCE_VALIDATED","MARKER_STAGED",
"COMMITTED","ABORTED","QUARANTINED","EXHAUSTED"),attempt_ordinal:I(0,7),
disposition:C("NONAUTHORITY_TRANSACTION_HEAD_ONLY"),
accepted_scope:C(["TRANSACTION_PRIVATE_NONAUTHORITY"]),
authority_ceiling:R(authority_v2),head_body_sha256:HEX)`.

`lock_root`:
`O(schema_version:C("plamen.program_facts_parity_transaction_lock.v2"),
lock_id:S(39,39,"^pfg3pl-[0-9a-f]{32}$"),role:E("GENERATOR",
"EVALUATOR","CROSSCHECK"),transaction_id:S(40,40,
"^pfg3ptx-[0-9a-f]{32}$"),owner_process:O(pid:I(1,9007199254740991),
process_start_identity:S1,launcher_identity:R(file_identity)),
created_host_monotonic_ns:I(0,9007199254740991),lock_path:PATH,
lock_locator:R(file_locator),
disposition:C("NONAUTHORITY_COORDINATION_ONLY"),
accepted_scope:C(["TRANSACTION_PRIVATE_NONAUTHORITY"]),
authority_ceiling:R(authority_v2),
lock_body_sha256:HEX)`.

`quarantine_root`:
`U(R(quarantine_prepared_root),R(quarantine_move_progress_root),
R(quarantine_complete_root))`.

`quarantine_prepared_root`:
`O(schema_version:C("plamen.program_facts_parity_quarantine.v2"),
record_kind:C("PREPARED"),
quarantine_id:S(39,39,"^pfg3pq-[0-9a-f]{32}$"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),role:E("GENERATOR",
"EVALUATOR","CROSSCHECK"),error_code:S1,source_head:Q(R(artifact_ref)),
source_journal:Q(R(artifact_ref)),
conflicting_entries:A(R(quarantine_entry_ref),1,20000,true),
intent_path:PATH,planned_moves:A(R(quarantine_move),1,20000,true),
state:C("PREPARED"),
disposition:C("QUARANTINE_INTENT_NONAUTHORITY"),
accepted_scope:C(["TRANSACTION_QUARANTINE_ONLY"]),
authority_ceiling:R(authority_v2),quarantine_body_sha256:HEX)`.

`quarantine_move_progress_root`:
`O(schema_version:C("plamen.program_facts_parity_quarantine.v2"),
record_kind:C("MOVE_PROGRESS"),quarantine_id:S(39,39,
"^pfg3pq-[0-9a-f]{32}$"),progress_id:S(40,40,
"^pfg3qmp-[0-9a-f]{32}$"),transaction_id:S(40,40,
"^pfg3ptx-[0-9a-f]{32}$"),role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
intent:R(artifact_ref),move_ordinal:I(0,19999),
planned_move:R(quarantine_move),
reconciled_from:E("SOURCE_IDENTITY","DESTINATION_IDENTITY"),
destination_entry:R(quarantine_entry_ref),
destination_metadata_observation:R(native_metadata_capture_observation),
source_absent:C(true),
destination_current:C(true),durability_barriers_complete:C(true),
state:C("MOVE_DURABLE"),
disposition:C("QUARANTINE_MOVE_PROGRESS_NONAUTHORITY"),
accepted_scope:C(["TRANSACTION_QUARANTINE_ONLY"]),
authority_ceiling:R(authority_v2),progress_body_sha256:HEX)`.

`quarantine_complete_root`:
`O(schema_version:C("plamen.program_facts_parity_quarantine.v2"),
record_kind:C("COMPLETE"),quarantine_id:S(39,39,
"^pfg3pq-[0-9a-f]{32}$"),transaction_id:S(40,40,
"^pfg3ptx-[0-9a-f]{32}$"),role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
error_code:S1,intent:R(artifact_ref),record_path:PATH,
move_progress:A(R(quarantine_progress_projection),1,20000,true),
cleanup_disposition:C("MOVED_COMPLETE"),
disposition:C("QUARANTINED_TRANSACTION_TERMINAL_ONLY"),
accepted_scope:C(["TRANSACTION_QUARANTINE_ONLY"]),
authority_ceiling:R(authority_v2),quarantine_body_sha256:HEX)`.

`coordination_lock_quarantine_root`:
`U(R(coordination_quarantine_prepared_root),
R(coordination_quarantine_move_progress_root),
R(coordination_quarantine_complete_root))`.

`coordination_quarantine_prepared_root`:
`O(schema_version:C("plamen.program_facts_parity_coordination_lock_quarantine.v1"),
record_kind:C("PREPARED"),
lock_quarantine_id:S(39,39,"^pfg3lq-[0-9a-f]{32}$"),
role:E("GENERATOR","EVALUATOR","CROSSCHECK"),error_code:S1,
lock_path:PATH,observed_lock:R(coordination_lock_entry_ref),intent_path:PATH,
planned_move:T(R(quarantine_move)),
owner_absence_basis:E("RECORDED_PROCESS_START_ABSENT",
"UNPARSEABLE_OWNER_AND_STALE_REGULAR_LOCK_ACQUIRED",
"NONREGULAR_PATH_HAS_NO_LOCK_OWNER"),native_lock_status:E("ACQUIRED_STALE_REGULAR",
"NOT_APPLICABLE_NONREGULAR"),
state:C("PREPARED"),
disposition:C("COORDINATION_LOCK_QUARANTINE_INTENT_ONLY"),
accepted_scope:C(["COORDINATION_RECOVERY_NONAUTHORITY"]),
authority_ceiling:R(authority_v2),quarantine_body_sha256:HEX)`.

`coordination_quarantine_move_progress_root`:
`O(schema_version:C("plamen.program_facts_parity_coordination_lock_quarantine.v1"),
record_kind:C("MOVE_PROGRESS"),lock_quarantine_id:S(39,39,
"^pfg3lq-[0-9a-f]{32}$"),progress_id:S(40,40,
"^pfg3lmp-[0-9a-f]{32}$"),role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
intent:R(artifact_ref),move_ordinal:C(0),
planned_move:R(quarantine_move),
reconciled_from:E("SOURCE_IDENTITY","DESTINATION_IDENTITY"),
destination_entry:R(quarantine_entry_ref),
destination_metadata_observation:R(native_metadata_capture_observation),
source_absent:C(true),
destination_current:C(true),durability_barriers_complete:C(true),
state:C("MOVE_DURABLE"),
disposition:C("COORDINATION_LOCK_QUARANTINE_MOVE_PROGRESS_ONLY"),
accepted_scope:C(["COORDINATION_RECOVERY_NONAUTHORITY"]),
authority_ceiling:R(authority_v2),progress_body_sha256:HEX)`.

`coordination_quarantine_complete_root`:
`O(schema_version:C("plamen.program_facts_parity_coordination_lock_quarantine.v1"),
record_kind:C("COMPLETE"),lock_quarantine_id:S(39,39,
"^pfg3lq-[0-9a-f]{32}$"),role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
error_code:S1,lock_path:PATH,
intent:R(artifact_ref),record_path:PATH,
payload_path:PATH,
move_progress:T(R(coordination_quarantine_progress_projection)),
cleanup_disposition:C("MOVED_EXACT_COORDINATION_LOCK"),
disposition:C("COORDINATION_LOCK_QUARANTINE_ONLY"),
accepted_scope:C(["COORDINATION_RECOVERY_NONAUTHORITY"]),
authority_ceiling:R(authority_v2),quarantine_body_sha256:HEX)`.
Its ID is the specialized transaction-independent formula in section 9;
intent, progress, record, and payload paths are derived only afterward and none
occurs in that ID preimage. The prepared `observed_lock` path equals
`lock_path`. A regular observed lock requires
`native_lock_status:"ACQUIRED_STALE_REGULAR"` and either recorded-owner-absent
or unparseable-owner/stale-lock-acquired basis; a nonregular observed lock
requires the nonregular basis and `NOT_APPLICABLE_NONREGULAR`. Planned move
ordinal is zero; and the progress destination has the
same regular-or-nonregular pathless identity after the move. The complete
record binds the exact intent and sole progress identity. No family member
references itself or any transaction.

`native_image_receipt_root`:
`O(schema_version:C("plamen.program_facts_parity_native_image_receipt.v2"),
receipt_id:S(39,39,"^pfg3ni-[0-9a-f]{32}$"),
transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
collector:R(native_image_collector_binding),collector_binary:R(handle_identity),
host_receipt:R(host_receipt),expected_projection:R(role_native_image_projection),
images:A(R(native_image_event),1,20000,true),
ordered_image_set_sha256:HEX,completeness:E("COMPLETE_PROCESS_TREE_ZERO",
"INCOMPLETE_REJECTED"),disposition:C("NATIVE_IMAGE_OBSERVATION_ONLY"),
accepted_scope:C(["EXACT_RUN_NATIVE_IMAGE_CLOSURE_ONLY"]),
authority_ceiling:R(authority_v2),
receipt_body_sha256:HEX)`. Only `COMPLETE_PROCESS_TREE_ZERO` is consumable.
Images are ordered by load ordinal and contain the complete initial executable,
loader, Python library, extension, and later image-load stream through
process-tree zero. `collector` has the exact constant principal/source path in
section 14.1; `collector_binary` is the retained-handle identity of the exact
host-reviewed build of that source. `expected_projection` equals the runtime
manifest's same-role row, and section 8 defines its exact observed equality,
allowed-universe subset, required-image coverage, and digest preimage.
`host_receipt.role`, its readable view role, and the receipt `role` are equal;
the host receipt's snapshot-entry and readable-view projections are the same
objects already joined by candidate and evidence.
`transaction_id` deliberately does not depend on this receipt or its ID.

`vector_bundle_candidate_root`:
`O(schema_version:C("plamen.program_facts_parity_vector_bundle_candidate.v1"),
vector_bundle_id:S(39,39,"^pfg3vb-[0-9a-f]{32}$"),
capture_run_id:S(40,40,"^pfg3vcr-[0-9a-f]{32}$"),
base_snapshot_id:S(39,39,"^pfg3bs-[0-9a-f]{32}$"),
base_logical_content_sha256:HEX,capture_source:R(snapshot_file_identity),
payloads:A(R(vector_bundle_payload),12,12,true),payload_set_sha256:HEX,
disposition:C("PRIVATE_VECTOR_BUNDLE_CANDIDATE_ONLY"),
accepted_scope:C(["DERIVED_PARITY_INPUT_MATERIALIZATION_ONLY"]),
authority_ceiling:R(authority_v2),vector_bundle_body_sha256:HEX)`. Payload paths
are exactly `snapshot_vector_paths` in order; each decoded string re-encodes to
the exact strict `CF` bytes measured by its row. The payload-set digest and
logical vector-bundle ID use section 4.4's exact preimages.

`vector_bundle_capture_receipt_root`:
`O(schema_version:C("plamen.program_facts_parity_vector_bundle_capture_receipt.v1"),
receipt_id:S(40,40,"^pfg3vbr-[0-9a-f]{32}$"),
capture_run_id:S(40,40,"^pfg3vcr-[0-9a-f]{32}$"),
base_snapshot:R(base_input_snapshot_projection),
source_binding:R(vector_capture_source_binding),
run_binding:R(vector_capture_run_binding),output:R(vector_bundle_output_projection),
payload_projection:A(R(vector_bundle_payload_projection),12,12,true),
payload_set_sha256:HEX,
disposition:C("VECTOR_BUNDLE_CAPTURE_RUN_PROVENANCE_ONLY"),
accepted_scope:C(["DERIVED_PARITY_INPUT_MATERIALIZATION_ONLY"]),
authority_ceiling:R(authority_v2),receipt_body_sha256:HEX)`. Source logical and
physical rows join the base manifest; all absolute source strings are equal;
the lexical root/cwd equal the base absolute root; and both reopen counts are
zero. The candidate's run/base/source/payload fields, persisted file identity,
complete framed stdout, frame digest, and receipt projections join exactly as
section 4.4 requires. Concrete values remain unavailable until the accepted
base/materialization predecessor supplies them.

`staged_marker_root`:
`R(completion_root)`, with no staging-only
property. Its path is the only staging classification.

### 14.3 Root schema registry, identity formulas, and order

The 25 rows below are exhaustive after applying the two R3 insertion rows in
section 15.5. `$id` is `https://plamen.local/schemas/`
followed by the schema filename. The path is relative to repository root.

| Schema file suffix | `ROOT_DEF` | Root `schema_version` |
|---|---|---|
| `program_facts_g3_00_parity_launcher_runtime_closure_amendment_review.v1.schema.json` | `amendment_review_root` | `plamen.program_facts_g3_00_parity_launcher_runtime_closure_amendment_review.v1` |
| `program_facts_parity_runtime_build_plan_lock.v1.schema.json` | `runtime_build_plan_root` | `plamen.program_facts_parity_runtime_build_plan_lock.v1` |
| `program_facts_parity_runtime_build_plan_lock_review.v1.schema.json` | `runtime_build_review_root` | `plamen.program_facts_parity_runtime_build_plan_lock_review.v1` |
| `program_facts_parity_runtime_closure.v2.schema.json` | `runtime_closure_root` | `plamen.program_facts_parity_runtime_closure.v2` |
| `program_facts_parity_runtime_closure_review.v1.schema.json` | `closure_review_root` | `plamen.program_facts_g3_00_parity_runtime_closure_review.v1` |
| `program_facts_parity_source_review.v1.schema.json` | `source_review_root` | `plamen.program_facts_g3_00_parity_source_review.v1` |
| `program_facts_parity_candidate.v2.schema.json` | `candidate_root` | `plamen.program_facts_gate3_schema_contract_parity_candidate.v2` |
| `program_facts_parity_evidence.v2.schema.json` | `evidence_root` | `plamen.program_facts_gate3_schema_contract_parity_evidence.v2` |
| `program_facts_parity_completion.v2.schema.json` | `completion_root` | `plamen.program_facts_gate3_schema_contract_parity_completion.v2` |
| `program_facts_parity_scenario_manifest.v1.schema.json` | `scenario_manifest_root` | `plamen.program_facts_g3_00_parity_launcher_scenario_manifest.v1` |
| `program_facts_parity_scenario_execution_evidence.v1.schema.json` | `scenario_execution_root` | `plamen.program_facts_g3_00_parity_launcher_scenario_execution_evidence.v1` |
| `program_facts_parity_launcher_implementation_review.v1.schema.json` | `implementation_review_root` | `plamen.program_facts_g3_00_parity_launcher_v2_implementation_review.v1` |
| `program_facts_parity_transaction_journal.v2.schema.json` | `journal_root` | `plamen.program_facts_parity_transaction_journal.v2` |
| `program_facts_parity_staged_marker.v2.schema.json` | `staged_marker_root` | `plamen.program_facts_gate3_schema_contract_parity_completion.v2` |
| `program_facts_parity_transaction_lock.v2.schema.json` | `lock_root` | `plamen.program_facts_parity_transaction_lock.v2` |
| `program_facts_parity_coordination_lock_quarantine.v1.schema.json` | `coordination_lock_quarantine_root` | `plamen.program_facts_parity_coordination_lock_quarantine.v1` |
| `program_facts_parity_quarantine.v2.schema.json` | `quarantine_root` | `plamen.program_facts_parity_quarantine.v2` |
| `program_facts_parity_quarantine_locator.v1.schema.json` | `quarantine_locator_root` | `plamen.program_facts_parity_quarantine_locator.v1` |
| `program_facts_parity_transaction_head.v2.schema.json` | `head_root` | `plamen.program_facts_parity_transaction_head.v2` |
| `program_facts_parity_attempt.v2.schema.json` | `attempt_root` | `plamen.program_facts_parity_attempt.v2` |
| `program_facts_parity_native_image_receipt.v2.schema.json` | `native_image_receipt_root` | `plamen.program_facts_parity_native_image_receipt.v2` |
| `program_facts_parity_vector_bundle_candidate.v1.schema.json` | `vector_bundle_candidate_root` | `plamen.program_facts_parity_vector_bundle_candidate.v1` |
| `program_facts_parity_vector_bundle_capture_receipt.v1.schema.json` | `vector_bundle_capture_receipt_root` | `plamen.program_facts_parity_vector_bundle_capture_receipt.v1` |
| `program_facts_parity_vector_capture_transaction.v2.schema.json` | `vector_capture_transaction_root` | `plamen.program_facts_parity_vector_capture_transaction.v2` |
| `program_facts_parity_pre_aggregate_lineage.v1.schema.json` | `pre_aggregate_lineage_root` | `plamen.program_facts_g3_00_parity_pre_aggregate_lineage.v1` |

Except for the explicitly specialized identity families below,
instance identity uses this algorithm. `body` removes exactly the ID field and
the body-digest field. `digest_body` removes only the body-digest field. The ID
is `prefix || SHA-256(CJ({domain:<domain>,<label>:body}))[0:32]`; the body
digest is `SHA-256(CJ(digest_body))`; the file is `CF(full)`. Every row still
uses the exact prefix, domain, and digest field in this table:

| Artifact | ID field / prefix | Domain / label | Body digest field |
|---|---|---|---|
| amendment review | `review_id` / `pfg3lrcr-` | `PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_RUNTIME_CLOSURE_REVIEW_V1` / `review` | `review_body_sha256` |
| runtime build plan/lock | `build_id` / `pfg3rb-` | `PROGRAM_FACTS_G3_PARITY_RUNTIME_BUILD_V1` / specialized section-4.0 preimage | `build_body_sha256` |
| runtime build review | `review_id` / `pfg3rbr-` | `PROGRAM_FACTS_G3_PARITY_RUNTIME_BUILD_REVIEW_V1` / `review` | `review_body_sha256` |
| runtime manifest | `closure_id` / `pfg3rc-` | `PROGRAM_FACTS_G3_PARITY_RUNTIME_CLOSURE_V2` / `closure` | `closure_body_sha256` |
| runtime closure review | `review_id` / `pfg3rcr-` | `PROGRAM_FACTS_G3_PARITY_RUNTIME_CLOSURE_REVIEW_V1` / `review` | `review_body_sha256` |
| source review | `review_id` / `pfg3sr-` | `PROGRAM_FACTS_G3_PARITY_SOURCE_REVIEW_V1` / `review` | `review_body_sha256` |
| candidate | `candidate_id` / `pfg3pc-` | `PROGRAM_FACTS_G3_SCHEMA_PARITY_CANDIDATE_V2` / `candidate` | `candidate_body_sha256` |
| evidence | `evidence_id` / `pfg3pe2-` | `PROGRAM_FACTS_GATE3_SCHEMA_CONTRACT_PARITY_EVIDENCE_V2` / `evidence` | `evidence_body_sha256` |
| completion/staged marker | `completion_id` / `pfg3pcm-` | `PROGRAM_FACTS_GATE3_SCHEMA_PARITY_COMPLETION_V2` / `completion` | `completion_body_sha256` |
| scenario manifest | `manifest_id` / `pfg3sm-` | `PROGRAM_FACTS_G3_PARITY_SCENARIO_MANIFEST_V1` / `manifest` | `manifest_body_sha256` |
| red/green scenario execution | `evidence_id` / `pfg3se-` | `PROGRAM_FACTS_G3_PARITY_SCENARIO_EXECUTION_V1` / `evidence` | `evidence_body_sha256` |
| implementation review | `review_id` / `pfg3ir-` | `PROGRAM_FACTS_G3_PARITY_IMPLEMENTATION_REVIEW_V1` / `review` | `review_body_sha256` |
| pre-aggregate lineage | `lineage_id` / `pfg3lin-` | `PROGRAM_FACTS_G3_PARITY_PRE_AGGREGATE_LINEAGE_V1` / `lineage` | `lineage_body_sha256` |
| journal | `journal_id` / `pfg3pj-` | `PROGRAM_FACTS_G3_PARITY_JOURNAL_V2` / `journal` | `journal_body_sha256` |
| lock | `lock_id` / `pfg3pl-` | `PROGRAM_FACTS_G3_PARITY_LOCK_V2` / specialized section-9 preimage | `lock_body_sha256` |
| coordination-lock quarantine PREPARED/COMPLETE | `lock_quarantine_id` / `pfg3lq-` | `PROGRAM_FACTS_G3_PARITY_COORDINATION_LOCK_QUARANTINE_V1` / specialized section-9 family preimage | `quarantine_body_sha256` |
| coordination-lock quarantine move progress | `progress_id` / `pfg3lmp-` | `PROGRAM_FACTS_G3_PARITY_LOCK_QUARANTINE_MOVE_PROGRESS_V1` / specialized section-9 move preimage | `progress_body_sha256` |
| quarantine PREPARED/COMPLETE | `quarantine_id` / `pfg3pq-` | `PROGRAM_FACTS_G3_PARITY_QUARANTINE_V2` / specialized section-9 family preimage | `quarantine_body_sha256` |
| quarantine move progress | `progress_id` / `pfg3qmp-` | `PROGRAM_FACTS_G3_PARITY_QUARANTINE_MOVE_PROGRESS_V2` / specialized section-9 move preimage | `progress_body_sha256` |
| head | `head_id` / `pfg3ph-` | `PROGRAM_FACTS_G3_PARITY_TRANSACTION_HEAD_V2` / `head` | `head_body_sha256` |
| attempt | `attempt_id` / `pfg3pa-` | `PROGRAM_FACTS_G3_PARITY_ATTEMPT_V2` / specialized section-9 preimage | `attempt_body_sha256` |
| native-image receipt | `receipt_id` / `pfg3ni-` | `PROGRAM_FACTS_G3_PARITY_NATIVE_IMAGE_RECEIPT_V2` / `receipt` | `receipt_body_sha256` |
| vector-bundle candidate | `vector_bundle_id` / `pfg3vb-` | `PROGRAM_FACTS_G3_PARITY_VECTOR_BUNDLE_V1` / specialized section-4.4 logical preimage | `vector_bundle_body_sha256` |
| vector-bundle capture receipt | `receipt_id` / `pfg3vbr-` | `PROGRAM_FACTS_G3_PARITY_VECTOR_BUNDLE_CAPTURE_RECEIPT_V1` / `receipt` | `receipt_body_sha256` |

The transaction ID is separately fixed before native execution and is
byte-for-byte the section-9 formula:

```text
transaction_id = "pfg3ptx-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_SCHEMA_PARITY_TRANSACTION_V2",
  role,launcher,producer,interpreter,runtime_closure,
  runtime_closure_review,input_snapshot,candidate_set,
  host_receipt,completion_path
}))[0:32]
```

The values have the exact types displayed in section 9: `role` is the role
string; `launcher`, `producer`, `runtime_closure`,
`runtime_closure_review`, and `host_receipt` are complete `file_identity`
objects; `interpreter` is the exact closed `execution_interpreter` already
joined to the runtime manifest, with canonical absolute path, path-bearing
handle/content projection, implementation, version, ABI, and platform tags;
`input_snapshot` and `candidate_set` are their exact closed
projections; and `completion_path` is portable. The nested candidate-set
projection is parsed-value identical to `input_snapshot.candidate_set`. No
native-image receipt, PID, time, random value, attempt ordinal, candidate, or
evidence occurs in this preimage. The generic
body-derived identity algorithm applies to all table rows except runtime build
plan, attempt, lock, both quarantine families and their move-progress records,
and the vector-bundle candidate. Those use only their exact specialized
section-4.0/4.4/9 preimages. `capture_run_id` is separately specialized by
section 4.4 but is not an artifact ID. Journal and head use their full
body-derived section-9 formulas.

Canonical array order is exact: section-1 pins and review inputs use table
order; schema identities use the 25-row registry order; sources use bootstrap,
runtime builder, generator, evaluator, cross-check, launcher; source reviews
use bootstrap, runtime builder, generator, evaluator, cross-check; roles use
generator, evaluator, cross-check;
scenario rows/results use ordinal 0-51; subcases use displayed mutation order;
checks use their displayed roster; findings/open IDs and generic evidence
identities use UTF-8 key order; bundle members use UTF-8 path order;
distributions use normalized name order; modules use module-name order; import
events and native images use ordinal order; system aliases use UTF-16 path
order; journals use journal ordinal; attempts use attempt ordinal; descendants
and quarantine entries/planned moves use UTF-8 canonical source-path order;
quarantine progress uses contiguous move ordinal; vector payload/projection rows
use `snapshot_vector_paths` order; lineage rows use generator, evaluator,
cross-check and lineage checks use their displayed order; inherited handles use
ordinal 0-4. An unordered, duplicate, missing, or extra row is invalid even
where ordinary JSON Schema cannot express sorting.

Scope and disposition are deliberately narrow. A manifest is a declaration,
a source/closure review accepts only the named source or closure, a red record
is chronology only, a green record is fixture/no-spawn evidence only, and an
implementation review is no-spawn construction only. Candidate, evidence,
attempt, journal, lock, head, quarantine intent/progress/complete records,
native-image receipt, vector candidate/receipt, pre-aggregate lineage, and
staged marker are private non-authority artifacts. Only a valid final marker has
`completion_state.capture_complete:true`, and that proves only capture. Every
one of these v2 roots contains the exact 28-field `authority_v2`; the embedded
v1 parity alone retains its exact 17-field parent ceiling. A later native host
receipt and separately reviewed adoption are still mandatory for any wider use.

## 15. R3 locator, native-move, and fourth-capture repair closure

This section closes the five independent R3 repair findings.  It is part of the
same Part-0 contract, creates no artifact, grants no host/process/capture/vector/
review/admission authority, and leaves every v1 byte and identity immutable.
All definitions named `R3 replacement` replace the same-named section-14
definition rather than adding a permissive alternative.  A renderer that keeps
both old and new branches, accepts either count, or resolves an old `$ref` is
invalid.

The R3 closed denominator is exactly:

```text
schema registry rows                         25
ordered successor inputs                     39
scenario rows / harness methods              52
scenario ordinals                            0..51
scenario IDs                                 LRC2-00..LRC2-51
```

The unchanged `PARITY_V1_LOCAL_FRAGMENT` remains exactly 22,213 bytes with
SHA-256
`97844a817f292066ae73dc554f7f747148e4569648dd783da7fdf0eb72f6ad3d`.
None of the R3 changes enters `parity_v1`, its 12-subject census, its 7,517
occurrences, its 21,578 atoms, or any of its 11 stream identities.  A renderer
must recompute this fragment pin after reading the amended file and reject any
change; it must not copy the value without checking the exact marker-bounded
bytes.

### 15.1 Exact added paths and acyclic construction order

The following paths are added to the section-2 successor roster.  Every path is
repository-relative and fixed; angle-bracket tokens have only the exact
substitution meanings below.

```text
rules/schemas/program_facts_parity_quarantine_locator.v1.schema.json
rules/schemas/program_facts_parity_vector_capture_transaction.v2.schema.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/<transaction_id>/quarantine.intent.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/<transaction_id>/quarantine.retired.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/active-intent.head.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/locator.serialization.lock.v1
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/locator-head-staging/<locator-revision>/head.next.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/locator-head-history/<locator-revision>/head.previous.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/quarantine/coordination-locks/<role-lower>/locator-head-backups/<locator-revision>/head.displaced.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/capture.intent.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/capture.serialization.lock.v1
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/capture.head.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/head-staging/<capture-revision>/head.next.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/head-history/<capture-revision>/head.previous.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/head-backups/<capture-revision>/head.displaced.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/events/<capture-revision>.event.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/attempt.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/control.binding.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/status.binding.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/run.authorization.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/stdout.frame.v1.bin
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/stderr.frame.v1.bin
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/observation.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/candidate.staged.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/receipt.staged.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/attempts/<capture-attempt>/completion.staged.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/capture.complete.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/capture.terminal.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/quarantine/<capture-quarantine-id>/quarantine.intent.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/quarantine/<capture-quarantine-id>/move-progress/<move-ordinal>.moved.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/process_evidence_v2/vector-capture-transactions/<capture_operation_id>/quarantine/<capture-quarantine-id>/quarantine.v1.json
```

`<locator-revision>`, `<capture-revision>`, and `<move-ordinal>` are exactly 16
lowercase decimal digits, left-zero-padded.  `<capture-attempt>` is the exact
single ASCII digit `0`.  `<capture_operation_id>` matches
`^pfg3vop-[0-9a-f]{32}$`; `<capture-quarantine-id>` matches
`^pfg3vcq-[0-9a-f]{32}$`.  No other spelling, suffix, temporary path, or
directory selection is allowed.

The R3.1 total DAG is: amendment -> independent amendment receipt -> render and
independently check all 25 schemas -> review the existing transport bootstrap
for both its unchanged parity mode and the closed vector mode below -> build
and review the runtime as already ordered -> create the 52-row immutable
scenario manifest and harness -> execute the complete RED denominator against
the pinned v1 launcher -> implement the no-spawn v2 launcher and the R3 state
machines -> execute the complete GREEN denominator -> independent
implementation review -> separate materializer/base snapshot -> fourth capture
transaction -> candidate-set and derived snapshot -> separately governed native
host receipt -> three parity transactions -> pre-aggregate lineage -> later G2
promotion/review -> later G3-01 adoption.  The bootstrap review, source frame,
host profile, capture intent, or run observation never depends on a vector
candidate, receipt, completion marker, accepted vector, or later review.  The
family IDs below never depend on locator paths or locator bytes.  These two
properties close every new identity cycle.

### 15.2 Fixed-address quarantine intent discovery

Directory enumeration, globbing, newest-file selection, suffix probing, and
reconstruction of a family ID from moved source paths remain forbidden.  A
move is legal only after one of the following fixed-address records is file-
durable, descriptor-read three times, path/identity validated, and its parent
directory durability barrier has completed.

#### 15.2.1 Transaction locator

Transaction quarantine is terminal, so each deterministic transaction has one
create-only active locator and one create-only retirement record.  The active
locator path is the section-15.1
`quarantine/<transaction_id>/quarantine.intent.v2.json`, known from the
transaction ID even before genesis.  It contains the *complete* parsed
`quarantine_prepared_root` value, including its already-derived family ID,
source references, ordered entries, and complete move plan; it does not merely
point to the ID-root intent.  It is written before the ID-root intent and before
any move.  Its exact root is:

```text
transaction_quarantine_active_locator_root =
O(schema_version:C("plamen.program_facts_parity_quarantine_locator.v1"),
  locator_kind:C("TRANSACTION_ACTIVE_INTENT"),locator_revision:C(0),
  transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
  locator_path:PATH,intent:R(quarantine_prepared_root),
  permanent_intent:R(file_identity),
  family_id:S(39,39,"^pfg3pq-[0-9a-f]{32}$"),
  state:C("ACTIVE"),predecessor_locator_body_sha256:C(null),
  disposition:C("FIXED_TRANSACTION_QUARANTINE_DISCOVERY_ONLY"),
  accepted_scope:C(["TRANSACTION_QUARANTINE_RECOVERY_ONLY"]),
  authority_ceiling:R(authority_v2),locator_body_sha256:HEX)
```

`locator_path` is the exact fixed path, `intent.transaction_id`/`role`/
`quarantine_id` equal the three outer values, and the family ID is recomputed
from the section-9 family preimage using the section-15.3 R3 entry identities,
which contains neither locator path,
locator digest, nor locator identity.  After locator durability, the launcher
exclusively creates and validates the permanent ID-root intent as exact `CF`
bytes of `intent`.  `permanent_intent.path` is exactly `intent.intent_path` and
its size/digest are those precomputable `CF(intent)` bytes.  This first anchor is
only protected-root path plus canonical content; it does not claim an inode that
could not have been observed before creation.  The first later progress/event
records the observed `artifact_ref`, and every successor requires that physical
identity.  The retired locator repeats that later-bound artifact.  A differing
existing ID-root intent is terminal tampering; content equality alone cannot
replace a physical identity after the first successor has bound it.

After ID-root `COMPLETE`, and only after all exact destination identities and
progress records validate, the launcher creates the fixed
`quarantine/<transaction_id>/quarantine.retired.v2.json` path with:

```text
transaction_quarantine_retired_locator_root =
O(schema_version:C("plamen.program_facts_parity_quarantine_locator.v1"),
  locator_kind:C("TRANSACTION_RETIRED"),locator_revision:C(1),
  transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),locator_path:PATH,
  family_id:S(39,39,"^pfg3pq-[0-9a-f]{32}$"),
  active_locator:R(file_identity),permanent_intent:R(file_identity),
  complete_record:R(file_identity),
  state:C("RETIRED"),predecessor_locator_body_sha256:HEX,
  disposition:C("FIXED_TRANSACTION_QUARANTINE_RETIREMENT_ONLY"),
  accepted_scope:C(["TRANSACTION_QUARANTINE_RECOVERY_ONLY"]),
  authority_ceiling:R(authority_v2),locator_body_sha256:HEX)
```

The predecessor digest is the active locator body digest.  Both fixed records
are retained forever; retirement means fenced and complete, not deleted.  An
active locator without retirement resumes its exact intent.  Retirement
without the active locator, a family mismatch, a second active locator, any
overwrite, or any transaction operation after retirement rejects.  Repeated
quarantines are supported across deterministic transaction roots; within one
transaction the first valid quarantine is terminal and cannot be bypassed by a
new family ID.

#### 15.2.2 Repeatable coordination-lock locator

The reusable role lock path needs an independent revisioned locator.  Its
fixed current path is section 15.1's
`coordination-locks/<role-lower>/active-intent.head.v2.json`; its staging,
history, and backup paths are derived solely from the next revision.  A head is
one of the exact roots:

```text
coordination_locator_active_head_root =
O(schema_version:C("plamen.program_facts_parity_quarantine_locator.v1"),
  locator_kind:C("COORDINATION_ACTIVE_HEAD"),
  locator_id:S(40,40,"^pfg3qlh-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
  locator_revision:I(0,9007199254740991),
  predecessor_locator_body_sha256:Q(HEX),
  current_path:PATH,stage_path:PATH,history_path:PATH,backup_path:PATH,
  family_id:S(39,39,"^pfg3lq-[0-9a-f]{32}$"),
  intent:R(coordination_quarantine_prepared_root),
  permanent_intent:R(file_identity),state:C("ACTIVE"),
  disposition:C("REVISIONED_COORDINATION_QUARANTINE_DISCOVERY_ONLY"),
  accepted_scope:C(["COORDINATION_RECOVERY_NONAUTHORITY"]),
  authority_ceiling:R(authority_v2),locator_body_sha256:HEX)

coordination_locator_retired_head_root =
O(schema_version:C("plamen.program_facts_parity_quarantine_locator.v1"),
  locator_kind:C("COORDINATION_RETIRED_HEAD"),
  locator_id:S(40,40,"^pfg3qlh-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
  locator_revision:I(1,9007199254740991),
  predecessor_locator_body_sha256:HEX,
  current_path:PATH,stage_path:PATH,history_path:PATH,backup_path:PATH,
  family_id:S(39,39,"^pfg3lq-[0-9a-f]{32}$"),
  intent:R(coordination_quarantine_prepared_root),
  permanent_intent:R(file_identity),complete_record:R(file_identity),
  state:C("RETIRED"),
  disposition:C("REVISIONED_COORDINATION_QUARANTINE_RETIREMENT_ONLY"),
  accepted_scope:C(["COORDINATION_RECOVERY_NONAUTHORITY"]),
  authority_ceiling:R(authority_v2),locator_body_sha256:HEX)
```

`quarantine_locator_root` is exactly the four-branch `U` of the two transaction
and two coordination roots in displayed order.  Each locator ID is
`"pfg3qlh-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_PARITY_COORDINATION_QUARANTINE_LOCATOR_HEAD_V1",
head:(full head without locator_id and locator_body_sha256)}))[0:32]`; its body
digest removes only `locator_body_sha256`.  The fixed path and exact
revision-derived scratch paths are semantically constant.  Genesis is revision
zero with null predecessor; every successor is exactly prior revision plus one
and names the exact prior body digest.  Revision, predecessor digest, family,
role, intent bytes, current/stage/history/backup paths, and the applicable file
IDs are all in the CAS comparison.  Reset to zero, deletion, reuse, wrap,
skipping, same-revision replacement, or ABA is invalid.

An ACTIVE head contains the complete prepared intent before the permanent
ID-root intent is created.  Once the ACTIVE head is durable, the ID-root intent
is exclusively created and must be byte-identical to `CF(head.intent)`.
`permanent_intent.path` equals `head.intent.intent_path`, and its size/digest
equal those bytes.  This is a protected-root path/content anchor, not a claim of
unobservable first-inode continuity.  The first progress successor binds the
observed physical `artifact_ref`; only then may physical continuity be required
through completion.  Only then may the sole lock move occur.  After its
`COMPLETE` record is durable, the next revision is a RETIRED head repeating the
identical intent and `permanent_intent` and binding that record.  A later corrupt
lock uses the next ACTIVE revision and cannot overwrite or omit any predecessor.
Head
CAS uses the exact transaction-head Linux/Windows staging/exchange/backup/
history algorithms and barriers, narrowed to these role-scoped paths.  A host
without that primitive returns `COORDINATION_LOCATOR_CAS_UNAVAILABLE` before
moving the lock.

Every new role-lock acquisition opens and validates the fixed locator head
before exclusive lock creation, records its revision/body digest, creates the
lock, and reopens the head afterward.  An ACTIVE head, or any revision/body
change, fences the new lock: the launcher closes/removes only the newly owned
lock by its retained handle and completes the selected quarantine family before
retry.  A stable RETIRED head permits acquisition.  This double read prevents a
new lock from racing an old corrupt-lock move.

Coordination progress replaces `source_absent:true` with the exact tagged
state `source_identity_state:E("ABSENT","DISTINCT_OBJECT_PRESENT")` and
`distinct_source_entry:Q(R(coordination_lock_entry_ref))`.  `ABSENT` requires
null.  `DISTINCT_OBJECT_PRESENT` requires the new source object to differ in
volume/file ID and complete branch identity from the quarantined object, while
the destination still names the exact old object.  The latter is a resumable
concurrent-new-lock state.  The same old identity at both source and
destination, neither location, or an unbound third identity is ambiguous.
Transaction progress retains strict `source_absent:true`.

For either family recovery begins from its fixed locator path, not from an ID
directory.  The exact order is locator -> permanent intent -> ordinal progress
paths -> COMPLETE -> locator retirement.  Crash seams exist immediately before
and after locator publication, permanent-intent publication, every move, each
source/destination barrier, each progress publication, COMPLETE publication,
retirement staging/CAS/history/barrier, and role-lock reacquisition.  At each
seam recovery accepts only the exact predecessor/successor inode identity
allowed above.  Traversal, role/path substitution, mutated intent bytes,
wrong family ID, a different locator inode with equal content, or an unexpected
CAS scratch object is terminal `QUARANTINE_LOCATOR_TAMPERED`; no scan repairs it.

### 15.3 Reproducible quarantine identity and native move profile

The section-14 statement that `inode_content_identity` is the only identity
compared across a rename is narrowed to **regular files only**.  A directory
uses its closed root plus descendant-tree identity; a nonregular entry uses its
OS-tagged no-follow native identity.  Cross-branch comparison is always false,
even when file IDs or digests happen to match.

The R3 replacement definitions are:

```text
quarantine_native_component =
U(O(encoding:C("POSIX_RAW_BYTES_BASE64URL_NOPAD"),
    value:S(1,4096,"^[A-Za-z0-9_-]+$")),
  O(encoding:C("WINDOWS_UTF16LE_BASE64URL_NOPAD"),
    value:S(2,8192,"^[A-Za-z0-9_-]+$")))

quarantine_relative_path =
O(os_family:E("LINUX","MACOS","WINDOWS"),
  components:A(R(quarantine_native_component),1,256,false))

quarantine_native_payload =
O(payload_kind:E("EMPTY","POSIX_SYMLINK_TARGET_RAW",
  "WINDOWS_REPARSE_BUFFER_RAW"),bytes_hex:S(0,131072,
  "^(?:[0-9a-f]{2})*$"),size_bytes:I(0,65536),sha256:HEX)

quarantine_posix_metadata =
O(os_family:E("LINUX","MACOS"),mode_octal:S(6,6,"^[0-7]{6}$"),
  uid:I(0,9007199254740991),gid:I(0,9007199254740991),
  rdev_major:I(0,9007199254740991),rdev_minor:I(0,9007199254740991),
  native_flags_hex:S(1,32,"^[0-9a-f]+$"),xattr_stream_sha256:HEX,
  acl_sha256:HEX)

quarantine_windows_metadata =
O(os_family:C("WINDOWS"),file_attributes_hex:S(8,8,"^[0-9a-f]{8}$"),
  reparse_tag_hex:S(8,8,"^[0-9a-f]{8}$"),
  allocation_size_bytes:I(0,9007199254740991),
  security_descriptor_sha256:HEX,ea_stream_sha256:HEX,
  alternate_stream_roster_sha256:HEX)

quarantine_nonregular_identity =
O(os_family:E("LINUX","MACOS","WINDOWS"),volume_id:S1,file_id:S1,
  nlink:I(1,9007199254740991),
  native_kind:E("SYMLINK","JUNCTION","REPARSE_POINT","DEVICE",
  "SOCKET","FIFO","OTHER_NONREGULAR"),
  metadata:U(R(quarantine_posix_metadata),R(quarantine_windows_metadata)),
  payload:R(quarantine_native_payload),native_metadata_sha256:HEX)

quarantine_descendant_row =
U(O(relative_path:R(quarantine_relative_path),entry_kind:C("REGULAR_FILE"),
    identity:R(inode_content_identity)),
  O(relative_path:R(quarantine_relative_path),entry_kind:C("DIRECTORY"),
    identity:R(directory_inode_identity)),
  O(relative_path:R(quarantine_relative_path),entry_kind:C("NONREGULAR"),
    identity:R(quarantine_nonregular_identity)))

quarantine_tree_identity =
O(root:R(directory_inode_identity),root_os_family:E("LINUX","MACOS","WINDOWS"),
  descendants:A(R(quarantine_descendant_row),0,20000,true),
  descendant_count:I(0,20000),descendant_stream_size_bytes:I(0,16777216),
  descendant_manifest_sha256:HEX)
```

`bytes_hex` is the complete raw payload: on Linux/macOS it is the exact
no-follow symlink target byte string returned by `readlinkat`; on Windows it is
the complete byte buffer returned by `FSCTL_GET_REPARSE_POINT`; for a
non-payload device/socket/FIFO/other entry it is empty and has the SHA-256 of
zero bytes.  Its decoded length equals `size_bytes` and its SHA-256 equals
`sha256`.  A Windows junction or reparse point requires
`WINDOWS_REPARSE_BUFFER_RAW`; a POSIX symlink requires
`POSIX_SYMLINK_TARGET_RAW`; all other kinds require `EMPTY`.  The metadata
branch's `os_family` equals the outer tag.  No timestamp whose value may change
on rename participates.

For a nonregular entry, let `metadata_preimage` be exactly:

```text
CJ({domain:"PROGRAM_FACTS_G3_PARITY_QUARANTINE_NATIVE_METADATA_V1",
    os_family,volume_id,file_id,nlink,native_kind,metadata,
    payload:{payload_kind,bytes_hex,size_bytes,sha256}})
```

and `native_metadata_sha256 = SHA-256(metadata_preimage)`.  Thus the digest
binds the OS branch, every included metadata field, and the payload bytes—not
merely a reported target string or a digest supplied without its preimage.

Tree descendant paths are relative to the quarantined root and losslessly
encode the native component sequence.  POSIX components decode as exact raw
pathname bytes; Windows components decode as an even-length exact UTF-16LE
code-unit sequence.  Encoding is canonical unpadded base64url: decode then
re-encode must reproduce `value`.  A decoded component may not be empty, `.`,
`..`, a separator, NUL, a drive/device prefix, or (on Windows) an unpaired
surrogate or Win32-reserved trailing dot/space spelling.  Every component in a
path uses the branch selected by `os_family`.  The root itself is not a
descendant.  POSIX row order is lexicographic by the unsigned decoded byte
sequence component-by-component; Windows row order is lexicographic by
unsigned decoded UTF-16 code units component-by-component; a strict ancestor
sorts before its descendant.  Duplicate decoded paths and case/normalization
aliases on a profile that would resolve them to one entry are forbidden.  The
list is the complete no-follow enumeration in that exact order.  Let:

```text
tree_header = CF({domain:"PROGRAM_FACTS_G3_PARITY_QUARANTINE_TREE_V1",
                  root,root_os_family,row_count:descendants.length,
                  order:"OS_NATIVE_COMPONENT_SEQUENCE_ASCENDING_V1"})
tree_rows = CONCAT CJ(descendants[i]) || 0x0a in array order
descendant_stream_size_bytes = len(tree_header || tree_rows)
descendant_manifest_sha256 = SHA-256(tree_header || tree_rows)
```

`descendant_count` equals the array length.  Completeness is proved from
retained directory handles after process-tree zero.  A row/tag mismatch,
alternate spelling, omitted directory, unlisted descendant, wrong order,
logical-only roster, wrong payload encoding, metadata omission, foreign OS
branch, or use of `inode_content_identity` for a directory/nonregular object
rejects before a move.

The R3 `quarantine_entry_ref` remains the same three-way tag but the tree and
nonregular branches use the replacements above.  The R3 move is exactly:

```text
quarantine_move =
O(move_ordinal:I(0,19999),source:R(quarantine_entry_ref),
  source_metadata_observation:R(native_metadata_capture_observation),
  source_parent:R(directory_locator),source_relative_path:R(quarantine_relative_path),
  destination_parent:R(directory_locator),
  destination_relative_path:R(quarantine_relative_path),
  identity_branch:E("REGULAR_FILE","DIRECTORY_TREE","NONREGULAR"),
  source_mount_id:S1,destination_mount_id:S1,
  source_st_dev:S1,destination_st_dev:S1,
  primitive:C("LINUX_RENAMEAT2_NOREPLACE_DIRFD_V1"))
```

The branch equals the source tag and selects exactly one cross-rename equality:
regular `inode_content_identity`, directory `quarantine_tree_identity`, or
nonregular `quarantine_nonregular_identity`.  Source/destination `statx`
`STATX_MNT_ID` values and `st_dev` values each equal their counterpart and the
retained parent handles; equal `st_dev` without equal mount ID is insufficient.
Destination relative paths
are the fixed family-ID/ordinal mapping and cannot contain a source spelling or
an implementer-selected suffix.

Before *any* child spawn the parent derives the complete finite set of every
possible quarantine pair for transaction artifacts, completion conflicts, the
role lock, AppContainer profile root, `LOCALAPPDATA`, `TEMP`, and `TMP`.  It
opens every source and destination root without following links and proves each
pair has the same filesystem/volume identity.  A profile root on another
volume than its fixed quarantine root, an unavailable stable volume identity,
or a mount transition returns exactly
`UNSUPPORTED_HOST_LAYOUT_CROSS_VOLUME_QUARANTINE` before child creation and
before any move.  This revision has no cross-volume copy/delete fallback and
does not silently relocate the quarantine root.  A future per-volume quarantine layout
requires its own reviewed contract.

The exact native move profiles are:

- Linux retains source/destination directory FDs and the no-follow source FD,
  verifies the same `st_dev`, then calls
  `renameat2(source_dirfd,source_name,destination_dirfd,destination_name,
  RENAME_NOREPLACE)`.  `EXDEV`, `EEXIST`, unsupported `renameat2`, another
  flag, bare `renameat`, path-based rename, or fallback copy/delete is a safe
  unsupported/error result.  Plain `renameat` has replacement semantics and is
  not an allowed no-replace primitive in this revision.
- macOS is unconditionally `MACOS_NAMESPACE_DURABILITY_UNAVAILABLE_R3_1`.
  `renameatx_np(...,RENAME_EXCL)` supplies no accepted current-head exchange or
  directory-entry power-loss barrier; regular-file `F_FULLFSYNC`, an API probe,
  or an empirical fixture cannot substitute.  R3.1 defines no accepting macOS
  move, head, marker, or host-receipt branch.
- Windows may record only the non-authoritative capability
  `WINDOWS_ORDINARY_USER_PROTECTED_ROOT_PROCESS_CRASH_V1`.  The documented
  `FileRenameInfoEx` information class uses a `FILE_RENAME_INFO` buffer with
  `Flags == 0`; a staged regular file may use `FILE_FLAG_WRITE_THROUGH` plus
  `FlushFileBuffers`.  Those facts do not provide a documented ordinary-user
  parent-directory or volume power-loss barrier.  `MoveFileExW`, including
  `MOVEFILE_WRITE_THROUGH`, `ReplaceFileW`, a nonzero rename flag, an assumed
  directory/volume `FlushFileBuffers`, or a receipt boolean cannot close the
  gap.  Power-loss-durable Windows construction is therefore unavailable before
  spawn and cannot publish `MOVE_DURABLE` or `COMMITTED`.

After a successful call the retained source handle is compared to the exact
destination no-follow observation, the source path is classified under the
transaction/coordination rule, both source and destination directories receive
their required durability barrier, and only then may progress be published.
Accepted Linux uses `fsync` on every staged regular file, every staged tree
directory bottom-up, and both retained source and destination parent directory
FDs after mutation; one directory `fsync` may satisfy both roles only when the
two retained FDs identify the same directory.  No receipt boolean substitutes
for a documented primitive.  Recovery reacquires only the
fixed root handles component-by-component, checks their recorded root and
volume/file identities, then opens the two exact relative names.  Wrong flag,
missing primitive, cross-volume result, incomplete barrier, root drift, or
handle reacquisition mismatch is terminal and never triggers a copy/delete.

The future native-host receipt is an R3 replacement that adds required member
`quarantine_move_profile`:

```text
quarantine_move_profile =
O(profile_id:S(40,40,"^pfg3qmpf-[0-9a-f]{32}$"),
  os_family:C("LINUX"),filesystem_profile:S1,
  source_destination_pairs:A(O(source_root:R(directory_locator),
    destination_root:R(directory_locator),source_mount_id:S1,
    destination_mount_id:S1,mount_id_equal:C(true),source_st_dev:S1,
    destination_st_dev:S1,st_dev_equal:C(true)),1,64,true),
  pair_set_complete:C(true),pre_spawn_verified:C(true),
  regular_primitive:C("LINUX_RENAMEAT2_NOREPLACE_DIRFD_V1"),
  directory_primitive:C("LINUX_RENAMEAT2_NOREPLACE_DIRFD_V1"),
  nonregular_primitive:C("LINUX_RENAMEAT2_NOREPLACE_DIRFD_V1"),
  serialization_primitive:C("LINUX_OFD_EXCLUSIVE_WRITE_LOCK_V1"),
  genesis_primitive:C("LINUX_CREATE_EXCLUSIVE_WRITE_FSYNC_PARENT_FSYNC_V1"),
  head_transition_primitive:C("LINUX_RENAMEAT2_EXCHANGE_DIRFD_V1"),
  durability_class:C("POWER_LOSS_DURABLE"),
  payload_write_policy:C("LINUX_FSYNC_BEFORE_RENAME"),
  namespace_barrier:C("LINUX_FSYNC_BOTH_PARENT_DIRFDS"),
  no_follow:C(true),no_replace:C(true),cross_volume_copy_delete:C(false),
  power_loss_capability:C(true),accepting_authority:C(false),
  recovery_handle_reacquisition:C(true))
```

All six primitive fields select the branch for `os_family`, the pair roster
is exact UTF-8 `(source root ID,path,destination root ID,path)` order, and
`profile_id = "pfg3qmpf-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_PARITY_QUARANTINE_MOVE_PROFILE_V1",profile:(full value
without profile_id)}))[0:32]`.  `host_receipt` now contains this value and the
launcher compares every `quarantine_move` against it before spawn and again
before move.  A host receipt without it grants no spawn authority.

### 15.4 Authenticated marker-last fourth capture

Section 4.4's two bare durable outputs are replaced by this transaction.  The
existing reviewed `parity_bootstrap_v2.py` is reused only if its independent
source review is extended to cover the closed `VECTOR_CAPTURE_V1` transport
mode below without changing the parity mode.  A second bootstrap, an unreviewed
inline `-c` program, direct execution of the capture source, or a bootstrap
whose source/review identity differs from the runtime manifest is rejected.

#### 15.4.1 Pre-spawn operation and exact source delivery

The fixed operation ID is selected before any process exists:

```text
capture_operation_id = "pfg3vop-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_VECTOR_CAPTURE_OPERATION_V1",
  base_snapshot,source_binding,bootstrap_binding,interpreter,
  host_receipt,execution_plan
}))[0:32]
```

`base_snapshot` is the full host-bound base projection.  `source_binding` is
the base member's logical identity, retained `handle_identity`, canonical
absolute path, lexical depth/root projection, and the passing launcher
implementation review whose subjects include that exact source.  `bootstrap_binding` is
exactly `{source,source_review,template_utf8_sha256,
instantiated_argv_sha256,mode:"VECTOR_CAPTURE_V1"}`.  `interpreter` is the
closed `execution_interpreter`; `host_receipt` includes the R3 quarantine move
profile; `execution_plan` is exactly `{backend_id,argv,cwd,environment,
control_protocol,status_protocol,gate_protocol,stdout_protocol,
stderr_max_bytes,timeout_seconds,attempt_max_count}`.  Only after the operation
ID exists is `completion_path` fixed by substituting it into the section-15.1
operation-root marker path; it is not in the ID preimage.  None contains a PID, process-start token,
status/output observation, candidate, receipt, run ID, or later path identity.

Before spawn, the parent writes the exact fixed `capture.intent.v2.json`:

```text
vector_capture_intent_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("INTENT"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),base_snapshot:R(base_input_snapshot_projection),
  source_binding:R(vector_capture_source_binding),
  bootstrap_binding:R(vector_capture_bootstrap_binding),
  interpreter:R(execution_interpreter),host_receipt:R(vector_capture_host_receipt),
  execution_plan:R(vector_capture_execution_plan),paths:R(vector_capture_paths),
  attempt_limit:C(8),state:C("INTENT_DURABLE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_INTENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

It is exclusive-create, file-durable, three-read validated, and parent-
directory durable before attempt zero or process creation.  Before the first
event exists, recovery authority is only the fixed protected-root path plus the
exact canonical intent content; no pre-creation inode is claimed.  The
`INTENT_DURABLE` event is the first successor that binds the observed physical
artifact reference.  Thereafter content equality at a different inode is not
adoption.  A conflicting intent makes the operation terminal.

The vector mode uses the exact six-item argv
`[interpreter.absolute_path,"-I","-S","-B","-c",
<exact reviewed bootstrap UTF-8 text>]`; the bootstrap text is the argument,
not a path or template.  `instantiated_argv_sha256` uses the unchanged section-
4.1 domain and exact array.  Cwd is the retained base-snapshot root and the
environment is exactly `{}`.

CONTROL_READ is exactly: eight ASCII bytes `PFG3VCT1`, one u64 big-endian
control length, strict `CF(vector_capture_control)`, one u64 big-endian source
length, the exact raw source bytes, and EOF.  The parent obtains those raw
bytes from the already retained base-member handle; it never reopens a path.
The control names the operation/attempt, complete base/source/bootstrap/
interpreter/host/execution-plan bindings, child gate/status handle values, and
the exact output protocol.  `source_frame_identity` is
`{size_bytes,sha256}` over the raw source bytes and equals the logical/physical
source projections.  Any source substitution, short/trailing frame, wrong
magic/length/EOF, or path/content disagreement rejects before status.

The bootstrap compiles the delivered bytes exactly once with
`compile(bound_source_bytes,source_absolute_path,"exec",flags=0,
dont_inherit=True,optimize=0)` before the gate.  It retains that exact code
object.  `compiled_code_identity` is `{marshal_version:4,size_bytes,sha256}`
over exact `marshal.dumps(code,4)` bytes under the bound CPython 3.12.10
runtime.  It walks root then code-valued `co_consts` depth-first in tuple-index
order and records each closed row `{ordinal,parent_ordinal_or_null,
const_index_or_null,co_name,co_qualname,co_firstlineno,co_flags,
co_code_sha256,co_filename}`.  Every `co_filename` equals the one canonical
source absolute path.  `code_object_projection_sha256` is SHA-256 of the
ordered `CJ(row)||LF` stream.  Globals are exactly `__name__="__main__"` and
`__file__=<source_absolute_path>`; `sys.argv` is the singleton source path;
cwd equals the retained base root; environment is empty.  The bootstrap does
not resolve, stat, or reopen `__file__`.

STATUS_WRITE is exactly eight ASCII bytes `PFG3VST1`, u64 length, strict
`CF(vector_capture_status)`, and EOF.  It binds operation/attempt, control and
source frame identities, bootstrap identity/review, compiled-code identity,
complete recursive code-object projection, filename/`__file__`/argv/cwd/
environment, child PID/process-start observation, actual `sys.executable`,
flags/path/import denials, `status_emitted_before_gate:true`, and
`ready_for_gate:true`.  The parent validates it against its retained source,
executable, process, host, and handle observations before authorizing
execution.

Because actual process identity exists only after spawn, vector mode uses a
closed authenticated gate rather than the parity mode's one byte.  After
validating status the parent computes:

```text
capture_run_id = "pfg3vcr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_VECTOR_CAPTURE_RUN_V2",
  capture_operation_id,attempt_ordinal,base_snapshot,source_binding,
  bootstrap_binding,interpreter,host_receipt,argv,cwd,environment,
  control_frame_identity,source_frame_identity,compiled_code_identity,
  code_object_projection_sha256,status_identity,
  actual_process_identity,output_framing_contract,
  source_to_process_join_sha256
}))[0:32]
```

`actual_process_identity` is parent-observed
`{pid,process_start_identity,executable_handle_identity,
native_creation_event_identity,job_or_process_group_identity}` and joins the
child PID/start/executable status fields.  `source_to_process_join_sha256` is
SHA-256 of `CJ({source_binding,source_frame_identity,compiled_code_identity,
code_object_projection_sha256,actual_process_identity,status_identity})`.
`output_framing_contract` fixes `PFG3VBC1`, u64 big-endian, strict CF candidate,
16,777,216-byte payload limit, EOF, zero stderr, exit zero, and process-tree
zero; it does not contain actual stdout or candidate bytes, avoiding an output
cycle.

START_GATE then carries exactly eight ASCII bytes `PFG3VGA1`, u64 length,
strict `CF(vector_capture_run_authorization)`, and EOF.  The authorization
contains the run ID, operation/attempt, status identity, actual-process
identity, source-to-process join digest, framing contract, and all-false
authority.  The bootstrap compares it to its retained compiled code and status,
exposes only the exact run ID and already authenticated outer context to the
capture source, and executes the retained code object once.  Wrong run ID,
status, PID/start token, executable, source join, arbitrary argv, or a repeated/
trailing gate frame rejects without source execution.  Thus bootstrap review,
raw source, compiled bytes, filenames, `__file__`, argv, cwd, environment,
status, actual executable/process, framing, and source-to-process join all enter
both the run ID and the later receipt without a self-reference.

#### 15.4.2 Durable observation before output publication

Each attempt has an immutable attempt record before spawn and an immutable
observation after process-tree zero.  The parent drains bounded stdout/stderr to
the two exact private spool paths while the child runs.  It writes neither the
candidate nor receipt canonical path at this stage.  After EOF, exit zero,
empty stderr, native observation, and process-tree zero, it file-durably seals
both spools and writes:

```text
vector_capture_observation_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("OBSERVATION"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),capture_run_id:S(40,40,
  "^pfg3vcr-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
  intent:R(file_identity),bootstrap_binding:R(vector_capture_bootstrap_binding),
  source_binding:R(vector_capture_source_binding),
  control_frame:R(content_identity),source_frame:R(content_identity),
  compiled_code:R(vector_compiled_code_identity),
  code_object_projection_sha256:HEX,status:R(vector_capture_status_binding),
  run_authorization:R(vector_capture_run_authorization),
  actual_process_identity:R(vector_actual_process_identity),
  source_to_process_join_sha256:HEX,stdout_spool:R(artifact_ref),
  stderr_spool:R(artifact_ref),stdout_frame:R(content_identity),
  stderr:C({"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size_bytes":0}),
  exit_code:C(0),process_tree_zero:C(true),native_observation_complete:C(true),
  state:C("CHILD_OBSERVED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_OBSERVATION_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

The observation's own file and parent directory are durable before candidate
parsing or staging.  It contains enough authenticated process/stream evidence
to parse and publish after a crash without reconstructing a process event.
Status text or self-reported paths alone cannot populate it.

R3.1 permits no pre-observation rerun.  Any parent crash after process creation
and before a complete durable observation is
`QUARANTINED_PREOBSERVATION_UNREPLAYABLE`, even if the process tree is later
proved zero.  Attempt ordinal is always zero, the attempt limit is one, no
purity-proof object is accepted, and a retry outcome or attempt-one path is a
schema and state-machine error.  This removes unverifiable claims about what an
unobserved child did; containment evidence remains mandatory for safe kill/reap
and quarantine, but never authorizes replay.

#### 15.4.3 Marker-last publication and reconciliation

The vector transaction's immutable event states are exactly:

```text
INTENT_DURABLE -> ATTEMPT_PREPARED[0] -> STATUS_BOUND[0]
 -> CHILD_OBSERVED[0] -> CANDIDATE_STAGED[0] -> CANDIDATE_PUBLISHED[0]
 -> RECEIPT_STAGED[0] -> RECEIPT_PUBLISHED[0]
 -> COMPLETION_STAGED[0] -> COMMITTED -> ADOPTED
any non-COMMITTED/non-ADOPTED state -> QUARANTINED
```

Each transition creates/fsyncs/three-read-validates the exact immutable event,
then advances `capture.head.v2.json` by the same revisioned staging/CAS/history/
backup algorithm as the parity transaction head.  The event contains exact
artifact slots for intent, attempt, observation, stdout/stderr spools, candidate
stage/final, receipt stage/final, completion stage/final, and quarantine.
`capture_quarantine_intent` is null for every non-`QUARANTINED` event and is the
complete exact `vector_capture_quarantine_prepared_root` value for the
`QUARANTINED` event.  That event is durable and current through the fixed head
before any quarantine move.  A published final is `CURRENT` only when its file
ID equals the preceding staged
inode; content equality at a different file ID is conflict, not adoption.

After `CHILD_OBSERVED`, the parent parses the exact spool frame, validates the
candidate and run ID, writes the unchanged candidate `CF` bytes to the exact
attempt staging path, and records its inode before a same-volume no-replace
rename to the existing canonical
`vector-captures/<base_snapshot_id>/<capture_run_id>/vector-bundle.candidate.v1.json`.
It reconciles source-or-destination only by that event-bound inode identity.
It then constructs the receipt from the durable observation and exact final
candidate, stages/records/publishes it identically to the existing canonical
`vector-bundle.capture-receipt.v1.json`.  Receipt `run_binding` is the complete
observation projection; no PID, bootstrap, source, status, compiled-code,
framing, or source-process field is optional.

Finally the parent constructs `vector_capture_completion_root`:

```text
vector_capture_completion_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("COMPLETION"),completion_id:S(40,40,
  "^pfg3vcm-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),capture_run_id:S(40,40,
  "^pfg3vcr-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
  intent:R(file_identity),observation:R(file_identity),
  candidate:R(file_identity),receipt:R(file_identity),
  candidate_id:S(39,39,"^pfg3vb-[0-9a-f]{32}$"),
  receipt_id:S(40,40,"^pfg3vbr-[0-9a-f]{32}$"),
  completion_path:PATH,
  commit_primitive:C("LINUX_RENAMEAT2_NOREPLACE_DIRFD_FSYNC_V1"),
  commit_linearization:C("VECTOR_CAPTURE_COMPLETION_CREATE_ONLY"),
  state:C("COMMITTED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_COMPLETE_ONLY"),
  accepted_scope:C(["DERIVED_PARITY_INPUT_MATERIALIZATION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

It stages and validates this exact marker, records the staged inode, then
publishes it no-replace at the fixed operation completion path.  That rename is
the only completion event.  Candidate and receipt are non-consumable without a
valid marker joining their exact file identities, IDs, body digests, run/
operation/attempt, source/bootstrap/process observation, and payload
projection.  The later materializer begins from `capture_operation_id`, opens
only the fixed completion path, and follows its exact candidate/receipt paths;
it never scans the run-ID directory.

Recovery begins only from the fixed intent/head/completion paths.  It follows
event-bound exact paths and file IDs.  For every staged-to-final publication,
source exact + destination absent means perform the move; source absent +
destination exact means finish barriers and append the event; both exact,
neither, or a different identity is ambiguous.  A valid completion marker is
adopted as private capture completion before any cleanup.  A candidate or
receipt at its final path without the exact prior staged-inode event is never
adopted by equal bytes and is quarantined.  No missing event, observation,
receipt, or marker is backfilled from a later object.

Ambiguous partial objects use a deterministic
`capture_quarantine_id = "pfg3vcq-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_PARITY_VECTOR_CAPTURE_QUARANTINE_V1",
capture_operation_id,attempt_ordinal,error_code,source_event,
conflicting_entries}))[0:32]`.  Its fixed intent/progress/complete paths are in
section 15.1; its complete prepared intent is first recorded in the immutable
`QUARANTINED` event selected by the fixed operation head before any move, and it
reuses the exact identity/volume/move rules in sections 15.2-15.3.  The event's
full value, fixed head path, source-event reference, and deterministic operation
ID make the prepared intent discoverable without enumeration.  COMPLETE then
permits the fixed terminal record.  There is no scan or random suffix.

The fault denominator has seams before and after: intent create/write/fsync/
directory barrier; attempt/event/head stage and CAS; process creation; control,
source, status, and gate frames; every stdout/stderr spool write and file/
directory barrier; observation create/write/fsync/barrier; candidate stage
create/every write/fsync/each read/event/rename/source+destination barrier;
receipt construction and the same complete staging/publication sequence;
completion stage construction/every write/fsync/each read/event/rename and
destination barrier; every quarantine locator/move/progress/COMPLETE/retirement
step; and cleanup.  Every forced crash yields exactly resume before spawn or
after a durable observation, committed-marker adoption, or terminal quarantine.
It never yields retry, purity-based replay, content-only adoption, backfill,
directory discovery, a false marker, or an unbounded retry.

### 15.5 R3 `$defs`, roots, IDs, and reference closure

The following exact definitions are appended to the shared `$defs`; definitions
with an existing name replace that definition.  Every object is closed through
the section-14 `O` notation, and every referenced name in this section is in the
same rendered schema's local `$defs`.

```text
vector_capture_bootstrap_binding =
O(source:R(file_identity),source_review:R(file_identity),
  template_utf8_sha256:HEX,instantiated_argv_sha256:HEX,
  mode:C("VECTOR_CAPTURE_V1"))

vector_capture_source_binding =
O(logical:R(snapshot_file_identity),physical:R(handle_identity),
  absolute_path:ABS,parent_resolved:C(true),child_lexical_path:ABS,
  child_parent_depth:C(3),child_lexical_root:ABS,
  implementation_review:R(file_identity),
  source_frame_identity:R(content_identity),source_frame_sha256:HEX,
  content_reopen_count:C(0),metadata_reopen_count:C(0))

vector_capture_framing_contract =
O(control_magic:C("PFG3VCT1"),status_magic:C("PFG3VST1"),
  gate_magic:C("PFG3VGA1"),stdout_magic:C("PFG3VBC1"),
  length_encoding:C("U64_BIG_ENDIAN"),control_payload:C("STRICT_CF_JSON"),
  source_payload:C("RAW_SELECTED_SOURCE"),status_payload:C("STRICT_CF_JSON"),
  gate_payload:C("STRICT_CF_JSON"),stdout_payload:C("STRICT_CF_JSON"),
  control_max_bytes:C(16777216),source_max_bytes:C(16777216),
  status_max_bytes:C(1048576),stdout_max_bytes:C(16777216),
  stderr_max_bytes:C(1048576),exact_eof:C(true))

base_snapshot_entry_validation =
O(base_snapshot_id:S(39,39,"^pfg3bs-[0-9a-f]{32}$"),
  logical_entry_roster_sha256:HEX,physical_member_projection_sha256:HEX,
  physical_member_bijection_complete:C(true),native_entry_count:I(1,20000),
  missing_entry_count:C(0),extra_entry_count:C(0),
  nonregular_entry_count:C(0),mount_or_volume_escape_count:C(0),
  hardlink_alias_count:C(0),reparse_alias_count:C(0),
  alternate_name_alias_count:C(0),exact_case_and_spelling:C(true),
  complete:C(true))

vector_capture_host_receipt =
O(identity:R(file_identity),
  schema_version:C("plamen.program_facts_parity_native_host_receipt.v1"),
  disposition:C("PASS_EXACT_NATIVE_HOST_ISOLATION_ONLY"),
  host_profile_id:S(39,39,"^pfg3hp-[0-9a-f]{32}$"),
  role:C("VECTOR_CAPTURE"),base_snapshot:R(base_input_snapshot_projection),
  base_entry_validation:R(base_snapshot_entry_validation),
  capture_source:R(vector_capture_source_binding),
  framing_contract:R(vector_capture_framing_contract),
  quarantine_move_profile:R(quarantine_move_profile),network_denied:C(true),
  filesystem_write_confined:C(true),child_creation_denied:C(true),
  process_tree_observation_supported:C(true))

host_receipt =
O(identity:R(file_identity),
  schema_version:C("plamen.program_facts_parity_native_host_receipt.v1"),
  disposition:C("PASS_EXACT_NATIVE_HOST_ISOLATION_ONLY"),
  host_profile_id:S(39,39,"^pfg3hp-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
  input_snapshot:R(input_snapshot_projection),
  snapshot_entry_validation:R(snapshot_entry_validation),
  readable_member_view:R(role_readable_member_view),
  bootstrap_protocol:R(bootstrap_protocol_contract),
  quarantine_move_profile:R(quarantine_move_profile))

vector_capture_execution_plan =
O(backend_id:S1,argv:T(ABS,C("-I"),C("-S"),C("-B"),C("-c"),S1),
  cwd:ABS,environment:C({}),control_protocol:C("PFG3VCT1"),
  status_protocol:C("PFG3VST1"),gate_protocol:C("PFG3VGA1"),
  stdout_protocol:C("PFG3VBC1"),stderr_max_bytes:C(1048576),
  timeout_seconds:C(3600),attempt_max_count:C(8))

vector_capture_paths =
O(intent:PATH,head:PATH,head_stage:PATH,head_history:PATH,head_backup:PATH,
  event:PATH,attempt:PATH,stdout_spool:PATH,stderr_spool:PATH,
  observation:PATH,candidate_stage:PATH,candidate_final:PATH,
  receipt_stage:PATH,receipt_final:PATH,completion_stage:PATH,
  completion_final:PATH,terminal:PATH,quarantine_root:PATH)

vector_compiled_code_identity =
O(marshal_version:C(4),size_bytes:I(1,16777216),sha256:HEX)

vector_code_object_row =
O(ordinal:I(0,19999),parent_ordinal_or_null:Q(I(0,19999)),
  const_index_or_null:Q(I(0,19999)),co_name:S1,co_qualname:S1,
  co_firstlineno:I(0,9007199254740991),co_flags:I(0,9007199254740991),
  co_code_sha256:HEX,co_filename:ABS)

vector_actual_process_identity =
O(pid:I(1,9007199254740991),process_start_identity:S1,
  executable_handle_identity:R(handle_identity),
  native_creation_event_identity:S1,job_or_process_group_identity:S1)

vector_capture_status_binding =
O(identity:R(content_identity),operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
  control_frame:R(content_identity),source_frame:R(content_identity),
  bootstrap_binding:R(vector_capture_bootstrap_binding),
  compiled_code:R(vector_compiled_code_identity),
  code_objects:A(R(vector_code_object_row),1,20000,true),
  code_object_projection_sha256:HEX,compile_filename:ABS,
  globals_name:C("__main__"),globals_file:ABS,sys_argv:T(ABS),cwd:ABS,
  environment:C({}),child_pid:I(1,9007199254740991),
  child_process_start_identity:S1,sys_executable:ABS,
  startup_flags_verified:C(true),startup_paths_verified:C(true),
  source_binding_verified:C(true),status_emitted_before_gate:C(true),
  ready_for_gate:C(true),authority_ceiling:R(authority_v2))

vector_capture_run_authorization =
O(schema_version:C("plamen.program_facts_parity_vector_capture_run_authorization.v1"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_run_id:S(40,40,"^pfg3vcr-[0-9a-f]{32}$"),
  attempt_ordinal:I(0,7),status_identity:R(content_identity),
  actual_process_identity:R(vector_actual_process_identity),
  source_to_process_join_sha256:HEX,
  framing_contract:R(vector_capture_framing_contract),
  authority_ceiling:R(authority_v2))

vector_capture_run_binding =
O(capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_run_id:S(40,40,"^pfg3vcr-[0-9a-f]{32}$"),
  backend_id:S1,interpreter:R(execution_interpreter),
  argv:T(ABS,C("-I"),C("-S"),C("-B"),C("-c"),S1),cwd:ABS,
  environment:C({}),bootstrap_binding:R(vector_capture_bootstrap_binding),
  control_frame:R(content_identity),source_frame:R(content_identity),
  compiled_code:R(vector_compiled_code_identity),
  code_object_projection_sha256:HEX,status:R(vector_capture_status_binding),
  run_authorization:R(vector_capture_run_authorization),
  actual_process_identity:R(vector_actual_process_identity),
  source_to_process_join_sha256:HEX,
  framing_contract:R(vector_capture_framing_contract),
  framed_stdout:R(content_identity),frame_sha256:HEX,
  stderr:C({"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size_bytes":0}),
  exit_code:C(0),process_tree_zero:C(true))

vector_capture_purity_proof =
O(kind:C("PURE_PREOBSERVATION_ATTEMPT_V1"),prior_attempt_ordinal:I(0,6),
  process_tree_zero:C(true),inputs_unchanged:C(true),network_denied:C(true),
  child_creation_denied:C(true),no_writable_inherited_file_handle:C(true),
  output_paths_denied:C(true),mutable_host_namespace_absent:C(true),
  writable_descendants_absent_or_quarantined:C(true),proof_sha256:HEX)

vector_capture_attempt_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("ATTEMPT"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),intent:R(file_identity),
  prior_purity_proof:Q(R(vector_capture_purity_proof)),
  paths:R(vector_capture_paths),state:C("ATTEMPT_PREPARED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_ATTEMPT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_artifact_slot =
U(O(status:C("ABSENT")),O(status:C("CURRENT"),artifact:R(artifact_ref)),
  O(status:C("PREDECESSOR"),artifact:R(artifact_ref)))

vector_capture_artifacts =
O(intent:R(vector_capture_artifact_slot),attempt:R(vector_capture_artifact_slot),
  observation:R(vector_capture_artifact_slot),stdout_spool:R(vector_capture_artifact_slot),
  stderr_spool:R(vector_capture_artifact_slot),candidate_stage:R(vector_capture_artifact_slot),
  candidate_final:R(vector_capture_artifact_slot),receipt_stage:R(vector_capture_artifact_slot),
  receipt_final:R(vector_capture_artifact_slot),completion_stage:R(vector_capture_artifact_slot),
  completion_final:R(vector_capture_artifact_slot),quarantine:R(vector_capture_artifact_slot))

vector_capture_event_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("EVENT"),event_id:S(40,40,"^pfg3vce-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_revision:I(0,9007199254740991),previous_event:Q(R(artifact_ref)),
  attempt_ordinal:I(0,7),state:E("INTENT_DURABLE","ATTEMPT_PREPARED",
  "CHILD_OBSERVED","CANDIDATE_STAGED","CANDIDATE_PUBLISHED",
  "RECEIPT_STAGED","RECEIPT_PUBLISHED","COMPLETION_STAGED",
  "COMMITTED","ATTEMPT_ABORTED","QUARANTINED","EXHAUSTED"),
  paths:R(vector_capture_paths),artifacts:R(vector_capture_artifacts),
  capture_quarantine_intent:Q(R(vector_capture_quarantine_prepared_root)),
  last_error:Q(R(transaction_error)),
  disposition:C("PRIVATE_VECTOR_CAPTURE_EVENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_head_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("HEAD"),head_id:S(40,40,"^pfg3vch-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_revision:I(0,9007199254740991),
  predecessor_head_body_sha256:Q(HEX),event:R(artifact_ref),
  attempt_ordinal:I(0,7),state:E("INTENT_DURABLE","ATTEMPT_PREPARED",
  "CHILD_OBSERVED","CANDIDATE_STAGED","CANDIDATE_PUBLISHED",
  "RECEIPT_STAGED","RECEIPT_PUBLISHED","COMPLETION_STAGED",
  "COMMITTED","ATTEMPT_ABORTED","QUARANTINED","EXHAUSTED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_HEAD_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_terminal_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("TERMINAL"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),head:R(file_identity),
  state:E("QUARANTINED","EXHAUSTED"),error:R(transaction_error),
  quarantine_record:Q(R(file_identity)),
  disposition:C("PRIVATE_VECTOR_CAPTURE_TERMINAL_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_prepared_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_PREPARED"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),error_code:S1,
  source_event:R(artifact_ref),conflicting_entries:A(R(quarantine_entry_ref),1,32,true),
  intent_path:PATH,planned_moves:A(R(quarantine_move),1,32,true),
  state:C("PREPARED"),disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINE_INTENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_progress_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_PROGRESS"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),
  intent:R(file_identity),move_ordinal:I(0,31),planned_move:R(quarantine_move),
  reconciled_from:E("SOURCE_IDENTITY","DESTINATION_IDENTITY"),
  destination_entry:R(quarantine_entry_ref),source_absent:C(true),
  destination_current:C(true),durability_barriers_complete:C(true),
  state:C("MOVE_DURABLE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINE_PROGRESS_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_progress_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_PROGRESS"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  run_paths:Q(R(vector_capture_run_paths)),
  serialization_lease:R(kernel_serialization_lease),move_ordinal:I(0,31),
  planned_move:R(quarantine_move),
  reconciled_from:E("SOURCE_IDENTITY","DESTINATION_IDENTITY"),
  destination_entry:R(quarantine_entry_ref),
  destination_metadata_observation:R(native_metadata_capture_observation),
  source_identity_state:E("ABSENT_AFTER_DURABLE_MOVE",
  "DISTINCT_CURRENT_SOURCE_ENTRY"),
  distinct_source_entry:Q(R(quarantine_entry_ref)),destination_current:C(true),
  durability_barriers_complete:C(true),state:C("MOVE_DURABLE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINE_PROGRESS_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_complete_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_COMPLETE"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:I(0,7),error_code:S1,
  intent:R(file_identity),move_progress:A(R(file_identity),1,32,true),
  cleanup_disposition:C("MOVED_COMPLETE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINED_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_transaction_root =
U(R(vector_capture_intent_root),R(vector_capture_attempt_root),
  R(vector_capture_observation_root),R(vector_capture_event_root),
  R(vector_capture_head_root),R(vector_capture_completion_root),
  R(vector_capture_terminal_root),R(vector_capture_quarantine_prepared_root),
  R(vector_capture_quarantine_progress_root),
  R(vector_capture_quarantine_complete_root))
```

`artifact_ref.kind` is an R3 replacement enum adding
`VECTOR_CAPTURE_INTENT`, `VECTOR_CAPTURE_ATTEMPT`,
`VECTOR_CAPTURE_OBSERVATION`, `VECTOR_CAPTURE_STDOUT`,
`VECTOR_CAPTURE_STDERR`, `VECTOR_CAPTURE_CANDIDATE_STAGE`,
`VECTOR_CAPTURE_CANDIDATE`, `VECTOR_CAPTURE_RECEIPT_STAGE`,
`VECTOR_CAPTURE_RECEIPT`, `VECTOR_CAPTURE_COMPLETION_STAGE`,
`VECTOR_CAPTURE_COMPLETION`, `VECTOR_CAPTURE_EVENT`, and
`VECTOR_CAPTURE_HEAD` to the existing exact enum.  The identity remains a
regular-file `inode_content_identity`; nonregular conflicts use the separate
quarantine branch.

`coordination_quarantine_move_progress_root` is replaced by the section-14
root with `source_absent` removed and the required
`source_identity_state`/`distinct_source_entry` pair from section 15.2 added.
`quarantine_root` and `coordination_lock_quarantine_root` retain their exact
three record branches, using the R3 identity/move definitions.  The added
locator records are accepted only by `quarantine_locator_root`; no old root is
widened to accept them.

All vector lifecycle bodies except the specialized operation/run/completion
identities use the exact generic body rule with the displayed ID where present
and `capture_body_sha256 = SHA-256(CJ(full record without only
capture_body_sha256))`.  Event ID domain is
`PROGRAM_FACTS_G3_PARITY_VECTOR_CAPTURE_EVENT_V2`; head ID domain is
`PROGRAM_FACTS_G3_PARITY_VECTOR_CAPTURE_HEAD_V2`; labels are `event` and
`head`.  Completion ID is:

```text
completion_id = "pfg3vcm-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_VECTOR_CAPTURE_COMPLETION_V2",
  completion:(full marker without completion_id and capture_body_sha256)
}))[0:32]
```

Candidate `vector_bundle_id` remains the logical section-4.4 ID.  Its body now
contains the exact R3 `capture_run_id`.  Receipt ID remains the section-4.4
body-derived ID, while its `run_binding` is replaced by the complete closed
observation projection and its `output` joins the event-bound published inode.
`vector_capture_projection` is replaced by
`O(completion:R(file_identity),candidate:R(file_identity),receipt:R(file_identity),
vector_bundle_id:S(39,39,"^pfg3vb-[0-9a-f]{32}$"),
vector_bundle_body_sha256:HEX,receipt_id:S(40,40,
"^pfg3vbr-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
"^pfg3vop-[0-9a-f]{32}$"),capture_run_id:S(40,40,
"^pfg3vcr-[0-9a-f]{32}$"),payload_set_sha256:HEX)`.  Candidate-set
materialization requires the completion field and validates the entire chain.

The two R3 roots are rendered with the same complete `$defs` copy and exact
Draft-2020-12 wrapper as every other schema:

| Schema file suffix | `ROOT_DEF` | Root schema-version family |
|---|---|---|
| `program_facts_parity_quarantine_locator.v1.schema.json` | `quarantine_locator_root` | `plamen.program_facts_parity_quarantine_locator.v1` |
| `program_facts_parity_vector_capture_transaction.v2.schema.json` | `vector_capture_transaction_root` | `plamen.program_facts_parity_vector_capture_transaction.v2` |

The complete 25-row registry order is the old 23-row order with quarantine
locator inserted immediately after
`program_facts_parity_quarantine.v2.schema.json`, and vector-capture transaction
inserted immediately after
`program_facts_parity_vector_bundle_capture_receipt.v1.schema.json`.  No other
row moves.  Let `schema_registry_rows` be the exact 25
`{ordinal,path,root_def,schema_version_family}` rows.  The exact registry
identity is recomputed as:

```text
schema_registry_stream = CONCAT CJ(row) || 0x0a in ordinal order
schema_registry_stream_size_bytes = 5315
schema_registry_sha256 = a63dac8bf7254ab7044e93de4ddd3455fb170251fb16554cb793cb07eca4c74d
```

Each rendered schema identity is computed only after expanding this amended
complete `$defs`, substituting its root row, strict schema-checking it, and
serializing exact `CF`.  Its `file_identity` uses those actual bytes.  The
renderer records all 25 `{ordinal,file_identity,root_def,schema_version_family}`
rows plus the registry stream size/digest in the amendment review.  A digest
from any 23-row/24-row render, old `$defs`, missing new `$ref`, remote-ref
fallback, or different registry order is invalid.  Because this is a contract-
only revision and no renderer output is created here, inventing literal future
schema byte sizes/digests would be false authority; exact recomputation from
the closed construction, not copied placeholder values, is mandatory.

### 15.6 R3.3-synchronized scenario, input, and review denominator

The exact section-10 parsed array contains the ten appended rows
`LRC2-42..51`; those row bytes are part of the displayed JSON block, not an
informative example.  Mechanical parsing and RFC-8785-style UTF-16/JCS
canonicalization used by `CJ` produce exactly:

```text
row_count                         52
method_count                      52
ordered_subcase_count            767
CJ(scenarios) bytes              84801
CJ(scenarios) SHA-256            2eb301a01e60847b1ce096c04b4df086869b216219714be49a70b1b4352b19c5
CJ(row)||LF stream bytes         84800
CJ(row)||LF stream SHA-256       70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99
```

The ten successor rows contribute respectively 39, 36, 32, 34, 79, 68, 16,
18, 20, and 28 subcases;
the first 42 rows contribute 397.  The harness has 52 top-level methods and
zero setup errors in both phases.  Manifest construction performs 54 recorded
validations: one `check_schema`, one complete root-constant validation, and 52
standalone row validations.  A 42-method/385-subcase result, or the prior
33,499/33,498-byte stream identity, is stale and invalid.

R3.2 replaces the scenario-related definitions as follows:

```text
mixed_subcase.expected_error_precedence = Q(I(1,51))
mixed_subcase.expected_outcome =
E("ACCEPT","REJECT","ABORT_ATTEMPT","QUARANTINE_TRANSACTION",
  "ADOPT_COMMITTED","RECOVERY_TRANSITION","QUARANTINE_VECTOR_CAPTURE",
  "ADOPT_VECTOR_CAPTURE")

scenario.expected_error_precedence = Q(I(1,51))
scenario.ordinal = I(0,51)
scenario.scenario_id = S(7,7,"^LRC2-(?:0[0-9]|[1-4][0-9]|5[01])$")

scenario_subcase_result.expected_error_precedence = Q(I(1,51))
scenario_subcase_result.observed_error_precedence = Q(I(1,51))
scenario_subcase_result expected/observed outcome = the same eight-value enum

scenario_result.ordinal = I(0,51)
scenario_result.scenario_id = S(7,7,"^LRC2-(?:0[0-9]|[1-4][0-9]|5[01])$")
scenario_result observed_error_precedence = Q(I(1,51))
```

The original scenario `allOf` constraints remain, with ranges replaced by
`0..51`; `PASS_EXPECTED_RECOVERY` remains limited to `[28,29,30]`; ordinary
non-mixed rejecting ordinals are `[43,44,45,47,48,49]`; mixed rows are exactly
`[23,32,33,34,35,38,42,46,50,51]`.  A mixed accepting/adoption/recovery outcome
has null error fields.  `REJECT`, `ABORT_ATTEMPT`,
`QUARANTINE_TRANSACTION`, and `QUARANTINE_VECTOR_CAPTURE` have integer/string
error fields.  `ADOPT_VECTOR_CAPTURE` has null fields.  The scenario category
enum is unchanged.

`scenario_manifest_root` is replaced with exact
`scenarios:C(<the parsed 52-object section-10 array>)`; its explanatory
`A(R(scenario),52,52,true)` shape cannot widen that constant.
`scenario_execution_root` replaces its counts with
`successor_inputs:A(R(file_identity),39,39,true)`, `method_count:C(52)`, and
`scenario_results:A(R(scenario_result),52,52,true)`.  `attempt_inputs`, every
source review, and the implementation-review subject replace the stale
predecessor `schema_files:A(R(file_identity),23,23,true)` with `25,25`.

The exact ordered 39 successor paths are the section-14.3 old list with the two
new schemas inserted at their registry positions.  In full:

```text
rules/schemas/program_facts_g3_00_parity_launcher_runtime_closure_amendment_review.v1.schema.json
rules/schemas/program_facts_parity_runtime_build_plan_lock.v1.schema.json
rules/schemas/program_facts_parity_runtime_build_plan_lock_review.v1.schema.json
rules/schemas/program_facts_parity_runtime_closure.v2.schema.json
rules/schemas/program_facts_parity_runtime_closure_review.v1.schema.json
rules/schemas/program_facts_parity_source_review.v1.schema.json
rules/schemas/program_facts_parity_candidate.v2.schema.json
rules/schemas/program_facts_parity_evidence.v2.schema.json
rules/schemas/program_facts_parity_completion.v2.schema.json
rules/schemas/program_facts_parity_scenario_manifest.v1.schema.json
rules/schemas/program_facts_parity_scenario_execution_evidence.v1.schema.json
rules/schemas/program_facts_parity_launcher_implementation_review.v1.schema.json
rules/schemas/program_facts_parity_transaction_journal.v2.schema.json
rules/schemas/program_facts_parity_staged_marker.v2.schema.json
rules/schemas/program_facts_parity_transaction_lock.v2.schema.json
rules/schemas/program_facts_parity_coordination_lock_quarantine.v1.schema.json
rules/schemas/program_facts_parity_quarantine.v2.schema.json
rules/schemas/program_facts_parity_quarantine_locator.v1.schema.json
rules/schemas/program_facts_parity_transaction_head.v2.schema.json
rules/schemas/program_facts_parity_attempt.v2.schema.json
rules/schemas/program_facts_parity_native_image_receipt.v2.schema.json
rules/schemas/program_facts_parity_vector_bundle_candidate.v1.schema.json
rules/schemas/program_facts_parity_vector_bundle_capture_receipt.v1.schema.json
rules/schemas/program_facts_parity_vector_capture_transaction.v2.schema.json
rules/schemas/program_facts_parity_pre_aggregate_lineage.v1.schema.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/parity_bootstrap_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/build_private_runtime_v1.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/generate_schema_contracts_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/evaluate_schema_contracts_independent_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/crosscheck_schema_contracts_stdlib_v2.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_BOOTSTRAP_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/RUNTIME_BUILDER_V1_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/GENERATOR_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/EVALUATOR_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/CROSSCHECK_V2_SOURCE_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_RUNTIME_BUILD_PLAN_LOCK.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_RUNTIME_BUILD_PLAN_LOCK_REVIEW.v1.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_LAUNCHER_RUNTIME_CLOSURE.v2.json
review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_LAUNCHER_RUNTIME_CLOSURE_REVIEW.v1.json
```

The first 25 are the complete schema registry; the last 14 retain their old
relative order.  Missing, extra, duplicate, reordered, or a 37-item predecessor
rejects before either RED or GREEN execution.

`amendment_check` appends exactly, after R13:

```text
G3LRC-R14-QUARANTINE-LOCATOR-AND-NATIVE-TRANSPORT
G3LRC-R15-AUTHENTICATED-FOURTH-CAPTURE-LIFECYCLE
G3LRC-R16-EXACT-NATIVE-METADATA-STREAMS
G3LRC-R17-CLOSED-CONTROL-STATUS-SOURCE-AND-PATH-BINDING
G3LRC-R18-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION
G3LRC-R19-NO-RETRY-STATE-ARTIFACT-TOTALITY
G3LRC-R20-PLATFORM-AUTHORITY-BOUNDARY
G3LRC-R21-IMMUTABLE-CONTAINMENT-POLICY-AND-TYPED-OBSERVATIONS
G3LRC-R22-DISJOINT-DERIVED-PATH-FAMILIES
G3LRC-R23-REGISTERED-PERSISTED-TRANSPORT-ROOTS
G3LRC-R24-HEADLESS-PRE-GENESIS-QUARANTINE
G3LRC-R25-SPAWN-UNCERTAINTY-CGROUP-TERMINATION
```

The amendment-review root therefore requires `checks:A(R(amendment_check),
25,25,true)`.  `implementation_check` appends exactly, after V2I-10:

```text
V2I-11-QUARANTINE-LOCATOR-AND-NATIVE-TRANSPORT
V2I-12-AUTHENTICATED-FOURTH-CAPTURE-LIFECYCLE
V2I-13-EXACT-NATIVE-METADATA-STREAMS
V2I-14-CONTROL-STATUS-SOURCE-AND-PATH-BINDING
V2I-15-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION
V2I-16-NO-RETRY-STATE-ARTIFACT-TOTALITY
V2I-17-PLATFORM-AUTHORITY-BOUNDARY
V2I-18-IMMUTABLE-CONTAINMENT-POLICY-AND-TYPED-OBSERVATIONS
V2I-19-DISJOINT-DERIVED-PATH-FAMILIES
V2I-20-REGISTERED-PERSISTED-TRANSPORT-ROOTS
V2I-21-HEADLESS-PRE-GENESIS-QUARANTINE
V2I-22-SPAWN-UNCERTAINTY-CGROUP-TERMINATION
```

The implementation-review root requires 22 ordered checks and every source
review requires eight.  R14/V2I-11 cover
the fixed locators, full intent embedding, repeated coordination CAS, closed
native identities, same-volume gate, exact native primitives/barriers, and all
recovery seams.  R15/V2I-12 cover bootstrap reuse/review, authenticated source
delivery and process join, durable observation, and marker-last lifecycle.
R16-R20/V2I-13-V2I-17 cover exact metadata, closed transport/path binding,
kernel serialization, the no-retry state matrix, and platform authority.  A
broad old check cannot substitute for an explicit check.

Canonical order is now: schema identities in 25-row registry order; scenario
rows/results `0..51`; the ten new subcase arrays in their displayed order;
successor inputs in the 39-path order above.  All other section-14 canonical
orders remain unchanged.

### 15.7 R3.1 closure map, acyclicity, and retained invariants

The ten blocking concern classes have the following non-substitutable contract and
test surfaces:

| Blocking concern | Normative closure | Scenario surface | Review checks |
|---|---|---|---|
| fixed-address transaction and repeatable coordination intent discovery | sections 15.1-15.2; both locator families embed the full prepared intent and bind its permanent path/content identity | `LRC2-42` | R14 / V2I-11 |
| exact regular, directory-tree, and OS-tagged nonregular identities | section 15.3 closed branches, native component codec, complete descendant stream, and cross-branch inequality | `LRC2-43` | R14 / V2I-11 |
| exact same-volume native no-replace move, barriers, receipt, and pre-spawn support gate | section 15.3 Linux move profile; no copy/delete fallback | `LRC2-44` | R14 / V2I-11 |
| authenticated bootstrap/source/compiled-code/actual-process binding for the fourth capture | sections 15.4.1-15.4.2 and the source-to-process join | `LRC2-45` | R15 / V2I-12 |
| marker-last capture publication, fixed-head quarantine intent, and no scan/backfill/adoption | section 15.4.3 and vector transaction roots | `LRC2-46` | R15 / V2I-12 |
| exact xattr/ACL/security-descriptor/EA/ADS source and normalized streams | section 16.1 metadata definitions and byte framing | `LRC2-43` | R16 / V2I-13 |
| non-self-referential control/status/gate binding and operation/run path split | section 16.2 closed payloads, frames, parent binding, and source review | `LRC2-45` | R17 / V2I-14 / SRV-07 |
| protected first anchors and role/operation kernel serialization | section 16.3 path/content anchors and Linux OFD leases | `LRC2-42`, `LRC2-46` | R18 / V2I-15 |
| one-attempt lifecycle and total state-by-artifact matrix | sections 16.3-16.4 no-retry containment, roots, matrix, and edge complement | `LRC2-46` | R19 / V2I-16 |
| Linux-only power-loss authority with non-authoritative Windows and unavailable macOS | section 16.5 closed platform results | `LRC2-44` | R20 / V2I-17 |

The identity dependency graph is acyclic by construction.  Transaction and
coordination quarantine family IDs depend on prepared intent inputs and native
entry/move identities, never on locator path, locator bytes, locator ID, or
locator body digest.  A locator then binds the already-derived family plus the
complete intent and the precomputable permanent-intent path/content identity.
Coordination locator ID/body identity excludes its own ID/body field.  Capture
operation ID depends only on the pre-spawn snapshot, source, reviewed bootstrap,
interpreter, host receipt, and execution plan; it excludes process identity,
run ID, output paths, output bytes, and completion.  Capture run ID adds the
durably observed actual process/status/compiled-code join, but excludes
candidate, receipt, stdout/stderr result bytes, and completion.  Candidate and
receipt bind that run; the completion marker binds their already-published exact
file identities and is last.  Capture quarantine ID depends on the pre-existing
operation/attempt/error/source-event/conflict set, never on its prepared record,
event/head identity, progress, or COMPLETE record.

R3.1 does not relax any earlier closure.  Retained-handle release remains the only
cleanup authority; quarantine still requires durable PREPARED, ordinal progress,
and COMPLETE records; genesis and revision/predecessor rules remain exact;
logical and physical source identities remain separate; the vector-capture lane
has no retry and never reopens the selected source by pathname; v1 remains
immutable; proposed v2 adoption remains unavailable and would require both the
accepted GREEN lineage and the section-15.8 bridge; private
capture/quarantine records remain non-authoritative; and only the exact final
completion marker can make a vector capture consumable.  This amendment creates
no implementation, fixture output, review receipt, current pointer, or acceptance
authority.

### 15.8 Non-waivable crosscheck-lineage admission blocker

The current governed crosscheck lineage does **not** terminate at the proposed
`crosscheck_schema_contracts_stdlib_v2.py` plus
`CROSSCHECK_V2_SOURCE_REVIEW.v1.json` pair used by this R3.1 design.  The repaired
lineage ends at a distinct v3 crosscheck source and a v4 adoption marker.  This
amendment has no accepted artifact that bridges those identities and semantics
into its launcher, runtime build plan/closure, source review, GREEN evidence,
pre-aggregate lineage, or later G3-01 adoption.  Therefore the v2 path/review
rows in sections 2, 6.1, 14, and 15.6 are frozen **proposed predecessor design
inputs only**.  They are neither current nor a permissible substitute for the
v3 source or v4 adoption marker.

This is an admission dependency, not a launcher feature.  No implementer may
rename v3 to a v2 path, copy a v2 review forward, infer semantic equivalence,
manufacture a lineage row, or modify the launcher to bless the gap.  A separate
independently accepted bridge must pin the exact governed v3 source, its exact
review lineage, and the exact v4 adoption marker; state the allowed projection;
bind them through runtime/source/GREEN/pre-aggregate/G3-01 consumers; prove
reviewer separation and non-self-certification; and version/recompute every
affected path roster, schema root, source review, scenario/input denominator,
and identity.  The bridge may preserve an R3 value only by proving it unchanged,
not by silent substitution.

Until that bridge is accepted and this contract is revised to name its exact
identities, the R3 DAG stops before schema rendering and RED/GREEN execution.
It grants no runtime build, process spawn, host validation, fourth capture,
materialization, parity transaction, pre-aggregate promotion, G2 review, G3-01
adoption, or cutover authority.  An independent review of these contract bytes
must leave the amendment pending (or reject it); it cannot issue a passing
admission receipt.  Every literal `PASS_*` disposition elsewhere in this file
is only a closed conditional schema value for a future complete lineage and is
not a statement that v2 is current, accepted, executable, or ready.

## 16. R3.1 metadata, transport, serialization, and state-totality closure

R3.1 repairs the independent-review findings against frozen R3 identity
`0086c7d8f633ec03ac4a3b76551194d5b6b280975c6907a5ae234fd5c9f82658`.
It is a contract-only Part-0 successor: it creates no renderer output, fixture,
receipt, host proof, process authority, or acceptance.  The section-15.8 v3/v4
lineage blocker remains exact and non-waivable.  Schema registry and successor
path rosters remain 25 and 39 because R3.1 replaces definitions inside the same
two R3 schema roots; their future rendered file identities must be recomputed.

### 16.1 Exact metadata source bytes and deterministic streams

Hash-only xattr, ACL, security-descriptor, EA, or alternate-stream fields are
invalid.  The shared `$defs` append the following closed byte and observation
types; the same-named section-15 metadata definitions are replaced.

```text
metadata_bytes =
O(bytes_hex:S(0,33554432,"^(?:[0-9a-f]{2})*$"),
  size_bytes:I(0,16777216),sha256:HEX)

metadata_presence_bytes =
O(presence:E("ABSENT","PRESENT"),value:Q(R(metadata_bytes)))

native_metadata_capture_profile =
O(os_family:E("LINUX","MACOS","WINDOWS"),
  collector_contract:R(file_identity),collector_contract_review:R(file_identity),
  api_profile:E("LINUX_HANDLE_XATTR_ACL_V1",
    "MACOS_NOFOLLOW_XATTR_ACL_V1","WINDOWS_BACKUPREAD_METADATA_V1"),
  retained_parent_or_object_handle:C(true),
  path_fallback_requires_serialization:C(true),
  raw_and_normalized_streams_bound:C(true))

native_metadata_capture_observation =
O(profile:R(native_metadata_capture_profile),
  before_identity:R(quarantine_entry_ref),
  after_identity:R(quarantine_entry_ref),identity_unchanged:C(true),
  enumeration_complete:C(true),api_error_count:C(0))

posix_xattr_row =
O(name:R(metadata_bytes),value:R(metadata_bytes))

posix_xattr_stream =
O(api_profile:E("LINUX_FLISTXATTR_FGETXATTR_V1",
  "LINUX_LLISTXATTR_LGETXATTR_SERIALIZED_V1",
  "MACOS_LISTXATTR_GETXATTR_XATTR_NOFOLLOW_V1"),
  raw_source_bytes:C(true),acl_names_excluded:C(true),
  order:C("UNSIGNED_NATIVE_NAME_BYTES_ASCENDING"),
  rows:A(R(posix_xattr_row),0,4096,true),row_count:I(0,4096),
  stream:R(metadata_bytes))

linux_acl_stream =
O(api_profile:C("LINUX_POSIX_ACL_XATTR_RAW_V1"),
  access_acl:R(metadata_presence_bytes),default_acl:R(metadata_presence_bytes),
  stream:R(metadata_bytes))

macos_acl_ace =
O(ordinal:I(0,4095),tag_u32be_hex:S(8,8,"^[0-9a-f]{8}$"),
  qualifier_kind:E("NONE","UID","GID","UUID"),
  qualifier:R(metadata_bytes),
  permission_mask_u32be_hex:S(8,8,"^[0-9a-f]{8}$"),
  flag_mask_u32be_hex:S(8,8,"^[0-9a-f]{8}$"))

macos_acl_stream =
O(api_profile:C("MACOS_ACL_GET_LINK_NP_NORMALIZED_V1"),
  presence:E("ABSENT","PRESENT"),normalization:C(
  "NATIVE_ACE_ORDER_CLOSED_FIELDS_NO_TEXT_RENDERING"),
  aces:A(R(macos_acl_ace),0,4096,false),ace_count:I(0,4096),
  stream:R(metadata_bytes))

posix_acl_stream = U(R(linux_acl_stream),R(macos_acl_stream))

windows_security_descriptor_stream =
O(api_profile:C("WINDOWS_BACKUPREAD_BACKUP_SECURITY_DATA_RAW_V1"),
  backupread_source:R(metadata_bytes),descriptor:R(metadata_presence_bytes),
  self_relative_valid:Q(B),normalized_stream:R(metadata_bytes))

windows_ea_row =
O(name:R(metadata_bytes),flags_hex:S(2,2,"^[0-9a-f]{2}$"),
  value:R(metadata_bytes))

windows_ea_stream =
O(api_profile:C("WINDOWS_BACKUPREAD_BACKUP_EA_DATA_RAW_V1"),
  backupread_source:R(metadata_bytes),
  order:C("UNSIGNED_EA_NAME_BYTES_ASCENDING"),
  rows:A(R(windows_ea_row),0,4096,true),row_count:I(0,4096),
  normalized_stream:R(metadata_bytes))

windows_ads_row =
O(name_utf16le:R(metadata_bytes),stream_attributes_hex:S(8,8,"^[0-9a-f]{8}$"),
  data:R(metadata_bytes))

windows_ads_stream =
O(api_profile:C("WINDOWS_BACKUPREAD_BACKUP_ALTERNATE_DATA_RAW_V1"),
  backupread_source:R(metadata_bytes),unnamed_data_stream_excluded:C(true),
  order:C("UNSIGNED_UTF16_CODE_UNITS_ASCENDING"),
  rows:A(R(windows_ads_row),0,4096,true),row_count:I(0,4096),
  normalized_stream:R(metadata_bytes))

quarantine_posix_metadata =
O(os_family:E("LINUX","MACOS"),mode_octal:S(6,6,"^[0-7]{6}$"),
  uid:I(0,9007199254740991),gid:I(0,9007199254740991),
  rdev_major:I(0,9007199254740991),rdev_minor:I(0,9007199254740991),
  native_flags_hex:S(1,32,"^[0-9a-f]+$"),
  xattrs:R(posix_xattr_stream),acl:R(posix_acl_stream),
  metadata_stream:R(metadata_bytes))

quarantine_windows_metadata =
O(os_family:C("WINDOWS"),file_attributes_hex:S(8,8,"^[0-9a-f]{8}$"),
  reparse_tag_hex:S(8,8,"^[0-9a-f]{8}$"),
  allocation_size_bytes:I(0,9007199254740991),
  security_descriptor:R(windows_security_descriptor_stream),
  extended_attributes:R(windows_ea_stream),
  alternate_streams:R(windows_ads_stream),metadata_stream:R(metadata_bytes))

vector_capture_host_receipt =
O(identity:R(file_identity),
  schema_version:C("plamen.program_facts_parity_native_host_receipt.v1"),
  disposition:C("PASS_EXACT_NATIVE_HOST_ISOLATION_ONLY"),
  host_profile_id:S(39,39,"^pfg3hp-[0-9a-f]{32}$"),
  role:C("VECTOR_CAPTURE"),base_snapshot:R(base_input_snapshot_projection),
  base_entry_validation:R(base_snapshot_entry_validation),
  capture_source:R(vector_capture_source_binding),
  framing_contract:R(vector_capture_framing_contract),
  quarantine_move_profile:R(quarantine_move_profile),
  native_metadata_capture_profile:R(native_metadata_capture_profile),
  network_denied:C(true),filesystem_write_confined:C(true),
  child_creation_denied:C(true),process_tree_observation_supported:C(true))

host_receipt =
O(identity:R(file_identity),
  schema_version:C("plamen.program_facts_parity_native_host_receipt.v1"),
  disposition:C("PASS_EXACT_NATIVE_HOST_ISOLATION_ONLY"),
  host_profile_id:S(39,39,"^pfg3hp-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
  input_snapshot:R(input_snapshot_projection),
  snapshot_entry_validation:R(snapshot_entry_validation),
  readable_member_view:R(role_readable_member_view),
  bootstrap_protocol:R(bootstrap_protocol_contract),
  quarantine_move_profile:R(quarantine_move_profile),
  native_metadata_capture_profile:R(native_metadata_capture_profile))
```

For every `metadata_bytes`, decoded `bytes_hex` length equals `size_bytes` and
SHA-256 of those decoded bytes equals `sha256`.  A zero-length value is exact
`bytes_hex:""`, size zero, and the SHA-256 of zero bytes.  `ABSENT` requires
`value:null`; `PRESENT` requires a value and may contain zero bytes.  API error,
access denial, buffer truncation/growth between sizing and read, or unsupported
namespace is neither ABSENT nor empty and rejects the identity.

The POSIX xattr API returns raw name/value bytes.  ACL names
`system.posix_acl_access` and `system.posix_acl_default` are excluded from the
general Linux xattr rows and appear exactly once in the two ACL slots.  Each
general xattr name is nonempty, contains no NUL, and is unique.  The exact xattr
stream is:

```text
ASCII("PFG3XAT1") || U64BE(row_count) ||
CONCAT(U64BE(name.size_bytes) || name.bytes ||
       U64BE(value.size_bytes) || value.bytes) in declared order
```

No xattrs are represented by the eight-byte magic plus `U64BE(0)`.  Linux ACL
uses `ASCII("PFG3LAC1")`, then access and default slots in that order; each slot
is byte `00` for ABSENT or byte `01 || U64BE(size) || raw_bytes` for PRESENT.
Linux preserves the raw kernel xattr value and performs no text or ACE
normalization.  macOS uses `acl_get_link_np` and native entry APIs, never
`acl_to_text`; it preserves ACE ordinal and emits
`ASCII("PFG3MAC1") || presence_tag || U64BE(ace_count) ||
CONCAT(U64BE(len(CJ(ace))) || CJ(ace))`.  ABSENT uses tag `00` and zero rows;
PRESENT uses tag `01`.  The stored stream bytes must equal these constructions.
Each macOS numeric tag/permission/flag is normalized as unsigned fixed-width
u32 big-endian lowercase hex.  A `NONE` qualifier has zero bytes, `UID` and
`GID` contain the canonical U64BE numeric value, and `UUID` contains exactly the
16 raw UUID bytes.  No localized name, decimal rendering, host-endian integer,
or unknown qualifier width is accepted.

The POSIX aggregate `metadata_stream` is exactly
`ASCII("PFG3PMD1") || U64BE(len(CF(header))) || CF(header) ||
U64BE(len(xattr_stream)) || xattr_stream || U64BE(len(acl_stream)) ||
acl_stream`, where `header` is the complete scalar metadata object without
`xattrs`, `acl`, or `metadata_stream`.  Linux uses `flistxattr`/`fgetxattr` on a
retained object handle when the entry kind permits it.  A symlink/nonregular
fallback may use `llistxattr`/`lgetxattr` only while the protected-root kernel
serialization lock is held and only if no-follow before/after physical identity
is equal.  macOS uses the documented no-follow xattr options under the same
identity bracketing.  A path-only observation outside serialization rejects.

Windows obtains the three exact raw source classes by `BackupRead` on the
retained object handle and parses complete `WIN32_STREAM_ID` records.  Each
`backupread_source` is the byte-for-byte concatenation, in returned native
order, of the complete fixed header, stream-name bytes, and payload bytes for
the selected stream ID; it is preserved separately from the deterministic
normalized stream.  It never hashes an API-supplied digest or a rendered
security string.  Security descriptor bytes are the complete
`BACKUP_SECURITY_DATA` payload and must pass self-relative validation when
PRESENT.  Its normalized stream is exactly
`ASCII("PFG3WSD1") || presence_tag || [U64BE(size) || descriptor_bytes]`.

EA rows are parsed from complete `BACKUP_EA_DATA`, sorted by unsigned native EA
name bytes, and the normalized stream is exactly:

```text
ASCII("PFG3WEA1") || U64BE(row_count) ||
CONCAT(U64BE(name.size_bytes) || name.bytes || flags_byte ||
       U64BE(value.size_bytes) || value.bytes)
```

ADS rows use the complete `BACKUP_ALTERNATE_DATA` name UTF-16LE bytes, the raw
four-byte little-endian `dwStreamAttributes`, and raw data.  They exclude only
the unnamed primary data stream, sort by unsigned UTF-16 code units, and the
normalized stream is exactly:

```text
ASCII("PFG3WAD1") || U64BE(row_count) ||
CONCAT(U64BE(name_utf16le.size_bytes) || name_utf16le.bytes ||
       attributes_four_bytes_le || U64BE(data.size_bytes) || data.bytes)
```

Zero rows means the completely enumerated namespace contains no named EA/ADS
entry; an existing named entry with zero data remains a PRESENT row containing
zero `metadata_bytes` and is not collapsed into zero rows.  The Windows
aggregate is exactly `ASCII("PFG3WMD1") || U64BE(len(CF(header))) ||
CF(header) || U64BE(len(security.normalized_stream)) || security.normalized_stream
|| U64BE(len(ea.normalized_stream)) || ea.normalized_stream ||
U64BE(len(ads.normalized_stream)) || ads.normalized_stream`, where `header` is
the complete scalar Windows metadata object without the three stream objects
or `metadata_stream`.  Any duplicate name, malformed linked record, odd UTF-16
byte count, unsupported stream ID, incomplete `BackupRead`, raw-source/
normalized disagreement, or unreadable requested security scope rejects.

`native_metadata_capture_profile` is included in the native host receipt and
binds this exact metadata contract and its independent amendment review.
`collector_contract` is parsed-value equal to the amendment identity and
`collector_contract_review` to the accepted amendment-review identity; both are
available before any RED/GREEN execution, so the host receipt does not depend
on later implementation review or generated evidence.  V2I-13 later checks the
actual collector branches in the launcher source against this profile.  This
reuse adds no successor path and may not be inferred without both explicit
equalities.  It is observation
provenance, not part of cross-rename semantic equality.  Cross-rename equality
uses the complete POSIX/Windows metadata objects and their exact source-byte
streams.  Hash-only, normalized-when-raw, raw-when-normalized, API-profile
substitution, omitted empty/absent tags, and reordered rows are unequal.
Every `quarantine_move.source_metadata_observation` has before/after identities
parsed-value equal to `source`; every move-progress
`destination_metadata_observation` has before/after identities parsed-value
equal to `destination_entry`.  Profile OS/API and entry metadata branches agree,
and the source and destination metadata parsed values are equal under the
selected entry branch.  Observation provenance never enters the cross-rename
equality itself, avoiding a recursive identity.

### 16.2 Non-self-referential control, status, source review, and path split

`vector_capture_paths`, the implicit control object, and the child-authored
status binding are deleted replacements.  The intent can contain only operation-
known paths.  Run-bound canonical outputs are derived only after authenticated
status produces `capture_run_id` and never enter the operation or run ID
preimages.

```text
vector_capture_operation_paths =
O(serialization_lock:PATH,intent:PATH,head:PATH,head_stage:PATH,
  head_history:PATH,head_backup:PATH,event:PATH,attempt:PATH,
  control_binding:PATH,status_binding:PATH,run_authorization:PATH,
  stdout_spool:PATH,stderr_spool:PATH,observation:PATH,
  candidate_stage:PATH,receipt_stage:PATH,completion_stage:PATH,
  completion_final:PATH,terminal:PATH,quarantine_root:PATH)

vector_capture_run_paths =
O(capture_run_id:S(40,40,"^pfg3vcr-[0-9a-f]{32}$"),
  candidate_final:PATH,receipt_final:PATH)

vector_capture_json_frame_identity =
O(magic:S(8,8,"^[A-Z0-9]{8}$"),length_encoding:C("U64_BIG_ENDIAN"),
  payload:R(content_identity),frame:R(content_identity),exact_eof:C(true))

vector_capture_source_frame_identity =
O(length_encoding:C("U64_BIG_ENDIAN"),source:R(content_identity),
  frame:R(content_identity),exact_eof:C(true))

vector_capture_control_payload =
O(schema_version:C("plamen.program_facts_parity_vector_capture_control.v2"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  attempt_ordinal:C(0),base_snapshot:R(base_input_snapshot_projection),
  source_binding:R(vector_capture_source_binding),
  bootstrap_binding:R(vector_capture_bootstrap_binding),
  interpreter:R(execution_interpreter),host_receipt:R(vector_capture_host_receipt),
  execution_plan:R(vector_capture_execution_plan),
  operation_paths:R(vector_capture_operation_paths),
  start_gate_child_handle_value:S(1,20,"^(?:0|[1-9][0-9]*)$"),
  status_write_child_handle_value:S(1,20,"^(?:0|[1-9][0-9]*)$"),
  framing_contract:R(vector_capture_framing_contract),
  authority_ceiling:R(authority_v2))

vector_capture_control_binding =
O(payload:R(vector_capture_control_payload),
  control_frame:R(vector_capture_json_frame_identity),
  source_frame:R(vector_capture_source_frame_identity),
  complete_control_read:R(content_identity))

vector_capture_child_status_payload =
O(schema_version:C("plamen.program_facts_parity_vector_capture_child_status.v2"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  attempt_ordinal:C(0),control_payload:R(content_identity),
  source_frame:R(vector_capture_source_frame_identity),
  bootstrap_binding:R(vector_capture_bootstrap_binding),
  compiled_code:R(vector_compiled_code_identity),
  code_objects:A(R(vector_code_object_row),1,20000,true),
  code_object_projection_sha256:HEX,compile_filename:ABS,
  globals_name:C("__main__"),globals_file:ABS,sys_argv:T(ABS),cwd:ABS,
  environment:C({}),child_pid:I(1,9007199254740991),
  child_process_start_identity:S1,sys_executable:ABS,
  startup_flags_verified:C(true),startup_paths_verified:C(true),
  source_binding_verified:C(true),status_emitted_before_gate:C(true),
  ready_for_gate:C(true),authority_ceiling:R(authority_v2))

vector_capture_status_binding =
O(payload:R(vector_capture_child_status_payload),
  status_frame:R(vector_capture_json_frame_identity),
  parent_actual_process:R(vector_actual_process_identity),
  control_payload_match:C(true),source_frame_match:C(true),
  bootstrap_match:C(true),compiled_code_match:C(true),
  process_identity_match:C(true),executable_match:C(true),
  parent_created:C(true))

vector_capture_run_authorization =
O(schema_version:C("plamen.program_facts_parity_vector_capture_run_authorization.v2"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_run_id:S(40,40,"^pfg3vcr-[0-9a-f]{32}$"),attempt_ordinal:C(0),
  status_binding:R(file_identity),actual_process_identity:R(vector_actual_process_identity),
  run_paths:R(vector_capture_run_paths),source_to_process_join_sha256:HEX,
  framing_contract:R(vector_capture_framing_contract),
  authority_ceiling:R(authority_v2))

vector_capture_gate_binding =
O(payload:R(vector_capture_run_authorization),
  gate_frame:R(vector_capture_json_frame_identity))
```

For JSON frame `F(magic,payload)`, payload bytes are exactly `CF(payload)` and
frame bytes are `ASCII(magic) || U64BE(len(CF(payload))) || CF(payload)`.
`payload` and `frame` identities are computed by the parent from those bytes;
neither identity occurs inside its payload.  CONTROL_READ is exactly
`F("PFG3VCT1",control_payload) || U64BE(source.size_bytes) || source.bytes ||
EOF`; `source_frame.frame` covers only that u64 plus source bytes, while
`complete_control_read` covers the complete concatenation.  STATUS_WRITE is
exactly `F("PFG3VST1",child_status_payload) || EOF`.  The child status contains
no status-frame identity, parent status binding, parent-observed executable
handle, run ID, run paths, candidate, receipt, or completion.  The parent first
computes the frame identity, joins its own process observation, constructs the
closed status binding, and durably publishes `status.binding.v2.json` before
computing the run ID.

The R3.1 source/process join is computed before the run ID and is exactly:

```text
source_to_process_join_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_VECTOR_SOURCE_PROCESS_JOIN_V2",
  source_binding,
  control_payload_identity:control_binding.control_frame.payload,
  control_frame_identity:control_binding.control_frame.frame,
  source_frame:control_binding.source_frame,
  complete_control_read:control_binding.complete_control_read,
  bootstrap_binding,
  compiled_code_identity:status_binding.payload.compiled_code,
  code_object_projection_sha256:
    status_binding.payload.code_object_projection_sha256,
  child_status_frame_identity:status_binding.status_frame.frame,
  parent_actual_process:status_binding.parent_actual_process
}))
```

It contains neither itself, the status-binding file identity, run ID, run
paths, authorization/gate frame, output, candidate, receipt, nor completion.
The later run authorization separately binds the durable status-binding file
identity and the derived run paths.

The R3.1 run preimage is exactly:

```text
capture_run_id = "pfg3vcr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_PARITY_VECTOR_CAPTURE_RUN_V3",
  capture_operation_id,attempt_ordinal:0,base_snapshot,source_binding,
  bootstrap_binding,interpreter,host_receipt,argv,cwd,environment,
  control_binding,status_binding,compiled_code_identity,
  code_object_projection_sha256,actual_process_identity,
  output_framing_contract,source_to_process_join_sha256
}))[0:32]
```

Only after that ID exists does the parent derive `vector_capture_run_paths` as
the two exact protected-root paths
`vector-captures/<base_snapshot_id>/<capture_run_id>/vector-bundle.candidate.v1.json`
and `.../vector-bundle.capture-receipt.v1.json`.  The authorization payload
binds those paths; its frame is `F("PFG3VGA1",authorization) || EOF`.  A run
path in the intent/control/operation ID, a run ID or status-frame identity in
child status, a payload that names its own frame, or a frame identity copied
from child prose is a closed-schema/self-cycle error.

The operation ID retains the section-15.4.1 V1 domain and inputs, but its
`execution_plan` input is the complete R3.1 replacement, including the closed
`containment_plan` and attempt limit one.  `vector_capture_operation_paths` is
derived only after the operation ID and is not an operation-ID input.  The
intent embeds those derived operation paths; no path that contains the
operation ID is allowed to feed the operation-ID preimage.

The exact fourth-capture source is a distinct required
`implementation_review_root.subjects.vector_capture_source` even when its file
identity is parsed-value equal to `subjects.launcher`; both paths must be the
section-2 `capture_schema_contract_parity_evidence_v2.py` path and equality is
checked, not inferred.  `source_review_root` gains required
`reviewed_modes:A(E("PARITY_V2","VECTOR_CAPTURE_V1"),1,2,true)`.  BOOTSTRAP
requires exactly `['PARITY_V2','VECTOR_CAPTURE_V1']` in that order; every other
source kind requires exactly `['PARITY_V2']`.  `source_check` adds
`SRV-07-VECTOR-CAPTURE-BOOTSTRAP-MODE`.  V2I-12 explicitly checks the exact
capture-source subject, bootstrap source/review, VECTOR_CAPTURE_V1 mode,
control/status/gate payload schemas, raw-source compile binding, and persisted
parent status binding.  A parity-only bootstrap review cannot authorize vector
capture.

### 16.3 Protected first anchors, kernel serialization, and no-retry containment

The first fixed file in a family cannot contain or cite a physical identity that
did not exist before creation.  R3.1 uses this exact external anchor relation:

```text
protected_path_content_anchor =
O(protected_root:R(directory_locator),relative_path:R(quarantine_relative_path),
  expected_content:R(content_identity),
  publication:C("LINUX_CREATE_EXCLUSIVE_WRITE_FSYNC_PARENT_FSYNC_V1"),
  physical_binding_state:C("UNBOUND_UNTIL_DURABLE_SUCCESSOR"))

kernel_serialization_anchor =
U(O(scope:C("COORDINATION_LOCATOR_ROLE"),
    scope_id:E("GENERATOR","EVALUATOR","CROSSCHECK"),
    protected_root:R(directory_locator),
    relative_path:R(quarantine_relative_path),
    content:C({"sha256":"d5e827826cb1df3a96b22ba57b7410d6ec9bb552fc3dfe293d862c94319ba76c","size_bytes":8}),
    creation_authority:C("PROTECTED_ROOT_PATH_AND_CONTENT_ONLY")),
  O(scope:C("VECTOR_CAPTURE_OPERATION"),
    scope_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
    protected_root:R(directory_locator),
    relative_path:R(quarantine_relative_path),
    content:C({"sha256":"d5e827826cb1df3a96b22ba57b7410d6ec9bb552fc3dfe293d862c94319ba76c","size_bytes":8}),
    creation_authority:C("PROTECTED_ROOT_PATH_AND_CONTENT_ONLY")))

kernel_serialization_lease =
O(anchor:R(kernel_serialization_anchor),
  primitive:C("LINUX_OFD_EXCLUSIVE_WRITE_LOCK_V1"),
  retained_handle:R(handle_identity),owner_pid:I(1,9007199254740991),
  owner_process_start_identity:S1,acquisition_ordinal:I(0,9007199254740991),
  predecessor_read_under_lock:C(true),held_through_namespace_barriers:C(true))
```

The eight anchor-content bytes are exact ASCII `PFG3SL1` plus LF; the displayed
size/hash are validated from those bytes and never trusted as prose.  The lock
file is create-once, never renamed, truncated, replaced, quarantined, or deleted.
Its first authority is protected-root path plus content.  Acquisition opens that
fixed path under the retained root, validates bytes, records the physical handle,
and obtains a Linux OFD whole-file exclusive write lock.  Kernel release on
process death does not mutate the permanent anchor.  An equal-content different
inode after any lease has bound the handle is tampering.
The retained lock descriptor is opened `O_CLOEXEC`, is absent from every child
inherited-handle allowlist, and is held only by the parent open-file
description.  A duplicated or inherited descriptor that could retain the OFD
lock after parent death is a containment/serialization violation.

There is one coordination locator anchor per role and one capture anchor per
operation ID.  The applicable lease is held continuously across predecessor
read, intent/event construction, stage durability, head exchange, displaced-head
history install, source/destination directory barriers, locator retirement,
quarantine move, and coordination role-lock create/double-read.  Every recovery
acquires a new lease before opening current/stage/history/backup names.  A second
writer blocks in the kernel and, after acquisition, must re-read the successor;
it cannot continue from a pre-lock observation.  Exchange without the lease,
lease release before both barriers, two simultaneous next revisions, or a
validate/exchange interleaving is `KERNEL_SERIALIZATION_VIOLATION`, never a CAS.
Revision zero with null predecessor uses exactly
`LINUX_CREATE_EXCLUSIVE_WRITE_FSYNC_PARENT_FSYNC_V1`: exclusive create at the
fixed path, file `fsync`, parent-directory `fsync`, then later physical binding.
Every revision greater than zero has a nonnull predecessor and uses
`LOCK_SERIALIZED_VALIDATE_THEN_RENAME_EXCHANGE_V1`, not kernel compare-and-swap.
The primitive/revision/predecessor combinations are exclusive semantic
constraints; genesis via exchange or an update via exclusive create rejects.

For the transaction locator itself, coordination genesis head, capture intent,
and capture genesis event/head, recovery before a durable successor uses only
the fixed protected-root path and recomputed exact `CF` content.  The first
durable successor records the observed `artifact_ref`; physical continuity is
mandatory only from that point.  The locator replacements are:

```text
transaction_quarantine_active_locator_root =
O(schema_version:C("plamen.program_facts_parity_quarantine_locator.v1"),
  locator_kind:C("TRANSACTION_ACTIVE_INTENT"),locator_revision:C(0),
  transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),locator_path:PATH,
  intent:R(quarantine_prepared_root),
  permanent_intent_anchor:R(protected_path_content_anchor),
  family_id:S(39,39,"^pfg3pq-[0-9a-f]{32}$"),state:C("ACTIVE"),
  predecessor_locator_body_sha256:C(null),
  disposition:C("FIXED_TRANSACTION_QUARANTINE_DISCOVERY_ONLY"),
  accepted_scope:C(["TRANSACTION_QUARANTINE_RECOVERY_ONLY"]),
  authority_ceiling:R(authority_v2),locator_body_sha256:HEX)

transaction_quarantine_retired_locator_root =
O(schema_version:C("plamen.program_facts_parity_quarantine_locator.v1"),
  locator_kind:C("TRANSACTION_RETIRED"),locator_revision:C(1),
  transaction_id:S(40,40,"^pfg3ptx-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),locator_path:PATH,
  family_id:S(39,39,"^pfg3pq-[0-9a-f]{32}$"),
  active_locator:R(artifact_ref),permanent_intent:R(artifact_ref),
  complete_record:R(artifact_ref),state:C("RETIRED"),
  predecessor_locator_body_sha256:HEX,
  disposition:C("FIXED_TRANSACTION_QUARANTINE_RETIREMENT_ONLY"),
  accepted_scope:C(["TRANSACTION_QUARANTINE_RECOVERY_ONLY"]),
  authority_ceiling:R(authority_v2),locator_body_sha256:HEX)

coordination_locator_active_head_root =
O(schema_version:C("plamen.program_facts_parity_quarantine_locator.v1"),
  locator_kind:C("COORDINATION_ACTIVE_HEAD"),
  locator_id:S(40,40,"^pfg3qlh-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
  locator_revision:I(0,9007199254740991),
  predecessor_locator_body_sha256:Q(HEX),
  current_path:PATH,stage_path:PATH,history_path:PATH,backup_path:PATH,
  serialization_lease:R(kernel_serialization_lease),
  transition_primitive:E("LINUX_CREATE_EXCLUSIVE_WRITE_FSYNC_PARENT_FSYNC_V1",
  "LOCK_SERIALIZED_VALIDATE_THEN_RENAME_EXCHANGE_V1"),
  family_id:S(39,39,"^pfg3lq-[0-9a-f]{32}$"),
  intent:R(coordination_quarantine_prepared_root),
  permanent_intent_anchor:R(protected_path_content_anchor),state:C("ACTIVE"),
  disposition:C("REVISIONED_COORDINATION_QUARANTINE_DISCOVERY_ONLY"),
  accepted_scope:C(["COORDINATION_RECOVERY_NONAUTHORITY"]),
  authority_ceiling:R(authority_v2),locator_body_sha256:HEX)

coordination_locator_retired_head_root =
O(schema_version:C("plamen.program_facts_parity_quarantine_locator.v1"),
  locator_kind:C("COORDINATION_RETIRED_HEAD"),
  locator_id:S(40,40,"^pfg3qlh-[0-9a-f]{32}$"),
  role:E("GENERATOR","EVALUATOR","CROSSCHECK"),
  locator_revision:I(1,9007199254740991),predecessor_locator_body_sha256:HEX,
  current_path:PATH,stage_path:PATH,history_path:PATH,backup_path:PATH,
  serialization_lease:R(kernel_serialization_lease),
  transition_primitive:C("LOCK_SERIALIZED_VALIDATE_THEN_RENAME_EXCHANGE_V1"),
  family_id:S(39,39,"^pfg3lq-[0-9a-f]{32}$"),
  intent:R(coordination_quarantine_prepared_root),
  active_head_predecessor:R(artifact_ref),permanent_intent:R(artifact_ref),
  complete_record:R(artifact_ref),state:C("RETIRED"),
  disposition:C("REVISIONED_COORDINATION_QUARANTINE_RETIREMENT_ONLY"),
  accepted_scope:C(["COORDINATION_RECOVERY_NONAUTHORITY"]),
  authority_ceiling:R(authority_v2),locator_body_sha256:HEX)
```

Every quarantine progress/complete replacement uses `intent:R(artifact_ref)`,
not path/content-only `file_identity`.  The first progress is the later artifact
that binds the permanent intent's physical identity; complete and retirement
repeat it exactly.  `quarantine_locator_root` remains the four-branch union of
these replacements.

R3.1 deletes `vector_capture_purity_proof` from `$defs` and accepts no reference
to it.  The closed Linux containment objects are:

```text
vector_containment_plan =
O(backend:C("LINUX_USER_MOUNT_NET_LANDLOCK_SECCOMP_CGROUP_PIDFD_V1"),
  cgroup_root:R(directory_locator),
  cgroup_relative_path:R(quarantine_relative_path),
  cgroup_inode:R(directory_inode_identity),pids_max:C(1),
  user_namespace_policy:C("PRIVATE_UID_GID_MAP_NO_HOST_CAPABILITIES"),
  mount_namespace_policy:C("PRIVATE_READ_ONLY_ALLOWLIST_OPERATION_OUTPUT_ONLY"),
  network_namespace_policy:C("PRIVATE_NO_INTERFACES_LOOPBACK_DOWN"),
  landlock_ruleset_sha256:HEX,seccomp_filter_sha256:HEX,no_new_privs:C(true),
  inherited_handle_allowlist_sha256:HEX,
  accessible_root_roster_sha256:HEX,writable_root_roster_sha256:HEX,
  network_policy:C("DENY_ALL"),child_process_policy:C("DENY_DESCENDANTS"),
  output_namespace_policy:C("OPERATION_PRIVATE_ONLY"))

vector_containment_observation =
O(plan:R(vector_containment_plan),pidfd_identity:S1,
  user_namespace_identity:S1,mount_namespace_identity:S1,
  network_namespace_identity:S1,landlock_ruleset_active:C(true),
  seccomp_filter_active:C(true),no_new_privs_observed:C(true),
  cgroup_procs_before:A(I(1,9007199254740991),0,1,true),
  cgroup_procs_after:C([]),cgroup_events_populated_zero:C(true),
  inherited_handles_observed_sha256:HEX,
  accessible_roots_observed_sha256:HEX,writable_roots_before_sha256:HEX,
  writable_roots_after_sha256:HEX,network_violation_count:C(0),
  child_process_violation_count:C(0),out_of_scope_write_count:C(0),
  native_evidence:A(R(file_identity),1,64,true),process_tree_zero:C(true))

vector_actual_process_identity =
O(pid:I(1,9007199254740991),process_start_identity:S1,
  executable_handle_identity:R(handle_identity),
  native_creation_event_identity:S1,pidfd_identity:S1,
  containment_plan:R(vector_containment_plan))

vector_capture_execution_plan =
O(backend_id:C("LINUX_NATIVE_VECTOR_CAPTURE_V1"),
  argv:T(ABS,C("-I"),C("-S"),C("-B"),C("-c"),S1),cwd:ABS,
  environment:C({}),control_protocol:C("PFG3VCT1"),
  status_protocol:C("PFG3VST1"),gate_protocol:C("PFG3VGA1"),
  stdout_protocol:C("PFG3VBC1"),stderr_max_bytes:C(1048576),
  timeout_seconds:C(3600),attempt_max_count:C(1),
  containment_plan:R(vector_containment_plan))

vector_capture_intent_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("INTENT"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),base_snapshot:R(base_input_snapshot_projection),
  source_binding:R(vector_capture_source_binding),
  bootstrap_binding:R(vector_capture_bootstrap_binding),
  interpreter:R(execution_interpreter),host_receipt:R(vector_capture_host_receipt),
  execution_plan:R(vector_capture_execution_plan),
  operation_paths:R(vector_capture_operation_paths),
  serialization_anchor:R(kernel_serialization_anchor),
  attempt_limit:C(1),state:C("INTENT_DURABLE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_INTENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_attempt_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("ATTEMPT"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  operation_paths:R(vector_capture_operation_paths),
  serialization_lease:R(kernel_serialization_lease),
  state:C("ATTEMPT_PREPARED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_ATTEMPT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

Every containment mechanism in the plan is conjunctive.  Missing unprivileged
namespace support, Landlock ABI/rule installation, seccomp installation,
cgroup-v2 delegation, pidfd support, read-only mount construction, or private
network construction returns `LINUX_VECTOR_CONTAINMENT_UNAVAILABLE` before
process creation.  Observation of a different namespace/policy identity is
terminal; there is no cgroup-only or best-effort fallback.

Any crash after process creation and before durable observation forces contained
kill/reap, complete quarantine, and `QUARANTINED`; the containment observation
cannot authorize another attempt.  Attempt ordinal one, `ATTEMPT_ABORTED`,
`EXHAUSTED`, `RETRY_VECTOR_CAPTURE`, a purity-proof path/object, or a next-
attempt transition is forbidden by schema and semantic validation.

### 16.4 Total lifecycle and state-by-artifact contract

R3.1 replaces the permissive lifecycle roots with a closed no-retry state
machine.  `A`, `C`, and `P` below mean the exact `vector_capture_artifact_slot`
branches `ABSENT`, `CURRENT`, and `PREDECESSOR`.  The slot order is fixed as:

```text
I=intent, AT=attempt, CT=control_binding, ST=status_binding,
GA=run_authorization, O=observation, SO=stdout_spool, SE=stderr_spool,
CS=candidate_stage, CF=candidate_final, RS=receipt_stage, RF=receipt_final,
MS=completion_stage, MF=completion_final, QN=quarantine
```

```text
vector_capture_artifacts =
O(intent:R(vector_capture_artifact_slot),attempt:R(vector_capture_artifact_slot),
  containment_instance:R(vector_capture_artifact_slot),
  spawn_arm:R(vector_capture_artifact_slot),
  control_record:R(vector_capture_artifact_slot),
  status_record:R(vector_capture_artifact_slot),
  authorization_record:R(vector_capture_artifact_slot),
  observation:R(vector_capture_artifact_slot),
  stdout_spool:R(vector_capture_artifact_slot),
  stderr_spool:R(vector_capture_artifact_slot),
  candidate_stage:R(vector_capture_artifact_slot),
  candidate_final:R(vector_capture_artifact_slot),
  receipt_stage:R(vector_capture_artifact_slot),
  receipt_final:R(vector_capture_artifact_slot),
  completion_stage:R(vector_capture_artifact_slot),
  completion_final:R(vector_capture_artifact_slot),
  quarantine:R(vector_capture_artifact_slot))
```

The complete ordinary-state matrix is the following literal constant.  There
are no implied rows, wildcards, nullable slots, or additional states.

| state | run paths | I | AT | CT | ST | GA | O | SO | SE | CS | CF | RS | RF | MS | MF | QN |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `INTENT_DURABLE` | absent | C | A | A | A | A | A | A | A | A | A | A | A | A | A | A |
| `ATTEMPT_PREPARED` | absent | C | C | A | A | A | A | A | A | A | A | A | A | A | A | A |
| `STATUS_BOUND` | current | C | C | C | C | C | A | A | A | A | A | A | A | A | A | A |
| `CHILD_OBSERVED` | current | C | C | C | C | C | C | C | C | A | A | A | A | A | A | A |
| `CANDIDATE_STAGED` | current | C | C | C | C | C | C | C | C | C | A | A | A | A | A | A |
| `CANDIDATE_PUBLISHED` | current | C | C | C | C | C | C | C | C | P | C | A | A | A | A | A |
| `RECEIPT_STAGED` | current | C | C | C | C | C | C | C | C | P | C | C | A | A | A | A |
| `RECEIPT_PUBLISHED` | current | C | C | C | C | C | C | C | C | P | C | P | C | A | A | A |
| `COMPLETION_STAGED` | current | C | C | C | C | C | C | C | C | P | C | P | C | C | A | A |
| `COMMITTED` | current | C | C | C | C | C | C | C | C | P | C | P | C | P | C | A |
| `ADOPTED` | current | C | C | C | C | C | C | C | C | P | C | P | C | P | C | A |

`QUARANTINED` is a parameterized terminal row, not a wildcard.  Its required
`terminal_from_state` is exactly one of the first nine pre-commit states.  Its
first fourteen slots equal that source row byte-for-byte, except an unfinished
non-durable partial is never promoted into a slot; `MF` remains `ABSENT` and
`QN` is `CURRENT`.  `COMMITTED` and `ADOPTED` cannot transition to quarantine.
Thus every legal crash prefix has exactly one representable terminal shape and
every extra, missing, prematurely current, or incorrectly predecessor slot is
an illegal edge.

The replacement definitions are:

```text
vector_capture_artifacts =
O(intent:R(vector_capture_artifact_slot),attempt:R(vector_capture_artifact_slot),
  control_binding:R(vector_capture_artifact_slot),
  status_binding:R(vector_capture_artifact_slot),
  run_authorization:R(vector_capture_artifact_slot),
  observation:R(vector_capture_artifact_slot),
  stdout_spool:R(vector_capture_artifact_slot),
  stderr_spool:R(vector_capture_artifact_slot),
  candidate_stage:R(vector_capture_artifact_slot),
  candidate_final:R(vector_capture_artifact_slot),
  receipt_stage:R(vector_capture_artifact_slot),
  receipt_final:R(vector_capture_artifact_slot),
  completion_stage:R(vector_capture_artifact_slot),
  completion_final:R(vector_capture_artifact_slot),
  quarantine:R(vector_capture_artifact_slot))

vector_capture_prestatus_event_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("EVENT"),event_id:S(40,40,"^pfg3vce-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_revision:I(0,9007199254740991),previous_event:Q(R(artifact_ref)),
  attempt_ordinal:C(0),state:E("INTENT_DURABLE","ATTEMPT_PREPARED"),
  operation_paths:R(vector_capture_operation_paths),run_paths:C(null),
  serialization_lease:R(kernel_serialization_lease),
  artifacts:R(vector_capture_artifacts),terminal_from_state:C(null),
  capture_quarantine_intent:C(null),last_error:C(null),
  disposition:C("PRIVATE_VECTOR_CAPTURE_EVENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_poststatus_event_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("EVENT"),event_id:S(40,40,"^pfg3vce-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_revision:I(0,9007199254740991),previous_event:R(artifact_ref),
  attempt_ordinal:C(0),state:E("STATUS_BOUND","CHILD_OBSERVED",
  "CANDIDATE_STAGED","CANDIDATE_PUBLISHED","RECEIPT_STAGED",
  "RECEIPT_PUBLISHED","COMPLETION_STAGED","COMMITTED","ADOPTED"),
  operation_paths:R(vector_capture_operation_paths),
  run_paths:R(vector_capture_run_paths),
  serialization_lease:R(kernel_serialization_lease),
  artifacts:R(vector_capture_artifacts),terminal_from_state:C(null),
  capture_quarantine_intent:C(null),last_error:C(null),
  disposition:C("PRIVATE_VECTOR_CAPTURE_EVENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantined_event_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("EVENT"),event_id:S(40,40,"^pfg3vce-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_revision:I(1,9007199254740991),previous_event:R(artifact_ref),
  attempt_ordinal:C(0),state:C("QUARANTINED"),
  terminal_from_state:E("INTENT_DURABLE","ATTEMPT_PREPARED","STATUS_BOUND",
  "CHILD_OBSERVED","CANDIDATE_STAGED","CANDIDATE_PUBLISHED",
  "RECEIPT_STAGED","RECEIPT_PUBLISHED","COMPLETION_STAGED"),
  operation_paths:R(vector_capture_operation_paths),
  run_paths:Q(R(vector_capture_run_paths)),
  serialization_lease:R(kernel_serialization_lease),
  artifacts:R(vector_capture_artifacts),
  capture_quarantine_intent:R(vector_capture_quarantine_prepared_root),
  last_error:R(transaction_error),
  disposition:C("PRIVATE_VECTOR_CAPTURE_EVENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_event_root =
U(R(vector_capture_prestatus_event_root),R(vector_capture_poststatus_event_root),
  R(vector_capture_quarantined_event_root))

vector_capture_head_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("HEAD"),head_id:S(40,40,"^pfg3vch-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_revision:I(0,9007199254740991),
  predecessor_head_body_sha256:Q(HEX),event:R(artifact_ref),
  serialization_lease:R(kernel_serialization_lease),attempt_ordinal:C(0),
  transition_primitive:E("LINUX_CREATE_EXCLUSIVE_WRITE_FSYNC_PARENT_FSYNC_V1",
  "LOCK_SERIALIZED_VALIDATE_THEN_RENAME_EXCHANGE_V1"),
  state:E("INTENT_DURABLE","ATTEMPT_PREPARED","STATUS_BOUND",
  "CHILD_OBSERVED","CANDIDATE_STAGED","CANDIDATE_PUBLISHED",
  "RECEIPT_STAGED","RECEIPT_PUBLISHED","COMPLETION_STAGED","COMMITTED",
  "ADOPTED","QUARANTINED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_HEAD_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_observation_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("OBSERVATION"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),capture_run_id:S(40,40,
  "^pfg3vcr-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  operation_paths:R(vector_capture_operation_paths),
  run_paths:R(vector_capture_run_paths),
  serialization_lease:R(kernel_serialization_lease),
  bootstrap_binding:R(vector_capture_bootstrap_binding),
  source_binding:R(vector_capture_source_binding),
  control_binding:R(artifact_ref),control:R(vector_capture_control_binding),
  status_binding:R(artifact_ref),status:R(vector_capture_status_binding),
  run_authorization:R(artifact_ref),gate:R(vector_capture_gate_binding),
  compiled_code:R(vector_compiled_code_identity),
  code_object_projection_sha256:HEX,
  actual_process_identity:R(vector_actual_process_identity),
  containment_observation:R(vector_containment_observation),
  source_to_process_join_sha256:HEX,stdout_spool:R(artifact_ref),
  stderr_spool:R(artifact_ref),stdout_frame:R(content_identity),
  stderr:C({"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size_bytes":0}),
  exit_code:C(0),process_tree_zero:C(true),native_observation_complete:C(true),
  state:C("CHILD_OBSERVED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_OBSERVATION_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_completion_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("COMPLETION"),completion_id:S(40,40,
  "^pfg3vcm-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),capture_run_id:S(40,40,
  "^pfg3vcr-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  observation:R(artifact_ref),candidate:R(artifact_ref),receipt:R(artifact_ref),
  candidate_id:S(39,39,"^pfg3vb-[0-9a-f]{32}$"),
  receipt_id:S(40,40,"^pfg3vbr-[0-9a-f]{32}$"),
  operation_paths:R(vector_capture_operation_paths),
  run_paths:R(vector_capture_run_paths),
  serialization_lease:R(kernel_serialization_lease),
  commit_primitive:C("LINUX_RENAMEAT2_NOREPLACE_DIRFD_FSYNC_V1"),
  commit_linearization:C("VECTOR_CAPTURE_COMPLETION_CREATE_ONLY"),
  state:C("COMMITTED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_COMPLETE_ONLY"),
  accepted_scope:C(["DERIVED_PARITY_INPUT_MATERIALIZATION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_terminal_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("TERMINAL"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),head:R(artifact_ref),
  state:C("QUARANTINED"),terminal_from_state:E("INTENT_DURABLE",
  "ATTEMPT_PREPARED","STATUS_BOUND","CHILD_OBSERVED","CANDIDATE_STAGED",
  "CANDIDATE_PUBLISHED","RECEIPT_STAGED","RECEIPT_PUBLISHED",
  "COMPLETION_STAGED"),error:R(transaction_error),
  quarantine_record:R(artifact_ref),
  disposition:C("PRIVATE_VECTOR_CAPTURE_TERMINAL_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_prepared_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_PREPARED"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),error_code:S1,
  source_event:R(artifact_ref),serialization_lease:R(kernel_serialization_lease),
  preobservation_process:Q(R(vector_actual_process_identity)),
  containment_observation:Q(R(vector_containment_observation)),
  conflicting_entries:A(R(quarantine_entry_ref),1,32,true),intent_path:PATH,
  planned_moves:A(R(quarantine_move),1,32,true),state:C("PREPARED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINE_INTENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_progress_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_PROGRESS"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  serialization_lease:R(kernel_serialization_lease),move_ordinal:I(0,31),
  planned_move:R(quarantine_move),
  reconciled_from:E("SOURCE_IDENTITY","DESTINATION_IDENTITY"),
  destination_entry:R(quarantine_entry_ref),
  destination_metadata_observation:R(native_metadata_capture_observation),
  source_identity_state:E(
  "ABSENT_AFTER_DURABLE_MOVE","DISTINCT_CURRENT_SOURCE_ENTRY"),
  distinct_source_entry:Q(R(quarantine_entry_ref)),destination_current:C(true),
  durability_barriers_complete:C(true),state:C("MOVE_DURABLE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINE_PROGRESS_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_complete_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_COMPLETE"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),error_code:S1,
  intent:R(artifact_ref),serialization_lease:R(kernel_serialization_lease),
  move_progress:A(R(artifact_ref),1,32,true),
  cleanup_disposition:C("MOVED_COMPLETE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINED_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_transaction_root =
U(R(vector_capture_intent_root),R(vector_capture_attempt_root),
  R(vector_capture_observation_root),R(vector_capture_event_root),
  R(vector_capture_head_root),R(vector_capture_completion_root),
  R(vector_capture_terminal_root),R(vector_capture_quarantine_prepared_root),
  R(vector_capture_quarantine_progress_root),
  R(vector_capture_quarantine_complete_root))
```

The semantic validator applies the literal matrix after schema validation and
also requires the head state and revision to equal the referenced event.  The
only legal edges are the eleven-state chain in section 15.4.3, adoption from an
already valid `COMMITTED` marker, and quarantine from one of the nine listed
pre-commit states.  A skipped edge, attempt ordinal other than zero, run paths
before `STATUS_BOUND`, missing run paths afterward, final output before its
stage predecessor, terminal without complete quarantine, or quarantine after
commit is rejected.  Recovery never synthesizes a missing event from a loose
candidate, receipt, spool, or partial file.  The sole marker-last exception is
an exact completion marker joined to the prior `COMPLETION_STAGED` event: after
finishing its required directory barrier, recovery appends the deterministic
`COMMITTED` edge and may then append `ADOPTED`.  That is completion
reconciliation, not backfill.
For an error code denoting process creation without durable observation,
`vector_capture_quarantine_prepared_root.preobservation_process` and
`containment_observation` are both required for a process-created error and
bind the parent-observed process plus contained kill/reap and process-tree zero;
for a pre-spawn error both are exactly null.  The plan and pidfd identities in
the pair are equal.  That evidence permits quarantine only and never replay.

### 16.5 Platform authority is Linux-only

The sole power-loss-capable move/publication profile remains the section-15.3
`quarantine_move_profile`, whose `os_family` is the constant `LINUX` and whose
mount-ID, `st_dev`, `renameat2(RENAME_NOREPLACE)`, staged-object `fsync`,
bottom-up tree-directory `fsync`, and both-parent-directory `fsync` predicates
are all required.  The retained root/parent descriptors and applicable
`kernel_serialization_lease` cover validation, namespace mutation, re-open,
and both barriers.  Only that profile may later become eligible to satisfy
`MOVE_DURABLE` or `COMMITTED`, after separately accepted evidence and admission;
at this stable-draft boundary `accepting_authority` remains false.

The two non-authoritative platform results have these closed shapes:

```text
windows_process_crash_capability =
O(capability:C("WINDOWS_ORDINARY_USER_PROTECTED_ROOT_PROCESS_CRASH_V1"),
  scope:C("PROCESS_CRASH_ONLY"),protected_root:R(directory_locator),
  retained_source_handle:R(handle_identity),
  rename_information_class:C("FileRenameInfoEx"),
  rename_buffer_type:C("FILE_RENAME_INFO"),rename_flags:C(0),
  payload_open_flags:C(["FILE_FLAG_WRITE_THROUGH"]),
  payload_barrier:C("FlushFileBuffers"),
  parent_directory_power_loss_barrier:C("UNAVAILABLE"),
  ordinary_user_volume_power_loss_barrier:C("UNAVAILABLE"),
  namespace_power_loss_durability:C("UNAVAILABLE"),
  can_publish_move_durable:C(false),can_publish_committed:C(false),
  accepting_authority:C(false),authority_ceiling:R(authority_v2))

macos_namespace_capability =
O(capability:C("MACOS_NAMESPACE_DURABILITY_UNAVAILABLE_R3_1"),
  scope:C("UNAVAILABLE"),rename_excl_insufficient:C(true),
  regular_file_fullfsync_insufficient:C(true),
  parent_directory_power_loss_barrier:C("UNAVAILABLE"),
  can_spawn:C(false),can_publish_move_durable:C(false),
  can_publish_committed:C(false),accepting_authority:C(false),
  authority_ceiling:R(authority_v2))
```

The Windows capability is useful only for a future separately reviewed
process-crash lane.  It is not a branch of `quarantine_move_profile`, cannot
enter the R3.1 launcher acceptance precondition, and makes no power-loss claim.
`MoveFileExW` (including `MOVEFILE_WRITE_THROUGH`), `ReplaceFileW`, nonzero
rename flags, an administrative volume handle, an undocumented directory
flush, an empirical power-cut test, or a receipt boolean cannot promote it.
The macOS result is unconditional unavailability, not a probe-dependent branch.
The final `LRC2-44` subcase phrase "platform capability" denotes exactly these
Windows and macOS non-authoritative result objects; it does not denote the
Linux `quarantine_move_profile`; its `power_loss_capability:true` means only
that its closed native move predicates are the sole eligible construction, while
`accepting_authority:false` and `authority_v2` preserve the current ceiling.

The normative Windows type names and flag meanings are constrained by the
primary Microsoft documentation for
`SetFileInformationByHandle`, `FILE_RENAME_INFO`, `MoveFileExW`, and
`FlushFileBuffers`:

- `https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle`
- `https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_rename_info`
- `https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw`
- `https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers`

Those citations constrain the design; this contract-only document does not
claim that an implementation, host, filesystem, or power-loss behavior was
observed.

### 16.6 R3.1 review closure and acceptance boundaries

The exact ordered `amendment_check` roster is the former fifteen followed by
these ten successor checks:

```text
G3LRC-R16-EXACT-NATIVE-METADATA-STREAMS
G3LRC-R17-CLOSED-CONTROL-STATUS-SOURCE-AND-PATH-BINDING
G3LRC-R18-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION
G3LRC-R19-NO-RETRY-STATE-ARTIFACT-TOTALITY
G3LRC-R20-PLATFORM-AUTHORITY-BOUNDARY
G3LRC-R21-IMMUTABLE-CONTAINMENT-POLICY-AND-TYPED-OBSERVATIONS
G3LRC-R22-DISJOINT-DERIVED-PATH-FAMILIES
G3LRC-R23-REGISTERED-PERSISTED-TRANSPORT-ROOTS
G3LRC-R24-HEADLESS-PRE-GENESIS-QUARANTINE
G3LRC-R25-SPAWN-UNCERTAINTY-CGROUP-TERMINATION
```

`amendment_review_root.checks` is therefore
`A(R(amendment_check),25,25,true)`.  R16 checks every raw/normalized source,
framing, ordering, empty/absent/error rule, size, and digest in section 16.1.
R17 checks the non-self-referential control/status/gate construction, exact
capture-source subject, bootstrap mode, operation/run path split, and all
substitution/cycle negatives.  R18 checks path/content-only first anchors,
later physical binding, and the fixed Linux OFD lease around every locator/head
transition.  R19 checks every ordinary matrix row, every legal edge, every
illegal skip, every quarantine prefix, and complete absence of retry/purity/
exhaustion.  R20 checks Linux power-loss authority, Windows process-crash-only
nonauthority, and unconditional macOS unavailability.

The three check `$defs` are replaced, not widened, by these exact closed
expressions:

```text
amendment_check =
O(check_id:E("G3LRC-R01-PREDECESSOR-PINS-AND-HISTORY",
  "G3LRC-R02-IMMUTABLE-V1-ACYCLIC-V2",
  "G3LRC-R03-STARTUP-INTERPRETER-RUNTIME-CLOSURE",
  "G3LRC-R04-DEPENDENCY-ORIGIN-AND-PRODUCER-INDEPENDENCE",
  "G3LRC-R05-PARITY-AND-EVIDENCE-BINDING",
  "G3LRC-R06-DESCRIPTOR-HANDLE-STABLE-IO",
  "G3LRC-R07-MARKER-LAST-TRANSACTION-RECOVERY",
  "G3LRC-R08-EXACT-FIXTURE-FIRST-DENOMINATOR",
  "G3LRC-R09-CLOSED-SCHEMAS-CANONICALIZATION-LIMITS",
  "G3LRC-R10-NATIVE-NO-SPAWN-BOUNDARY",
  "G3LRC-R11-REVIEW-INDEPENDENCE-AND-ADOPTION-DAG",
  "G3LRC-R12-TRUST-AND-AUTHORITY-CEILING",
  "G3LRC-R13-RUNTIME-BUILD-AND-SNAPSHOT-PAYLOAD-CLOSURE",
  "G3LRC-R14-QUARANTINE-LOCATOR-AND-NATIVE-TRANSPORT",
  "G3LRC-R15-AUTHENTICATED-FOURTH-CAPTURE-LIFECYCLE",
  "G3LRC-R16-EXACT-NATIVE-METADATA-STREAMS",
  "G3LRC-R17-CLOSED-CONTROL-STATUS-SOURCE-AND-PATH-BINDING",
  "G3LRC-R18-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION",
  "G3LRC-R19-NO-RETRY-STATE-ARTIFACT-TOTALITY",
  "G3LRC-R20-PLATFORM-AUTHORITY-BOUNDARY",
  "G3LRC-R21-IMMUTABLE-CONTAINMENT-POLICY-AND-TYPED-OBSERVATIONS",
  "G3LRC-R22-DISJOINT-DERIVED-PATH-FAMILIES",
  "G3LRC-R23-REGISTERED-PERSISTED-TRANSPORT-ROOTS",
  "G3LRC-R24-HEADLESS-PRE-GENESIS-QUARANTINE",
  "G3LRC-R25-SPAWN-UNCERTAINTY-CGROUP-TERMINATION"),
  result:E("PASS","FAIL"),evidence:A(R(file_identity),1,10000000,true))

source_check =
O(check_id:E("SRV-01-SOURCE-IDENTITY","SRV-02-NO-PEER-IMPORT",
  "SRV-03-NO-SHARED-ALGORITHM","SRV-04-SEMANTIC-IMPORT-DECLARATIONS",
  "SRV-05-TRANSPORT-OR-BUILDER-BOUNDARY","SRV-06-NONAUTHORITY",
  "SRV-07-VECTOR-CAPTURE-BOOTSTRAP-MODE",
  "SRV-08-CONTAINMENT-SUPERVISOR-SOURCE"),result:E("PASS","FAIL"),
  evidence:A(R(file_identity),1,10000000,true))

implementation_check =
O(check_id:E("V2I-01-RED-CHRONOLOGY","V2I-02-SCHEMAS",
  "V2I-03-RUNTIME-CLOSURE","V2I-04-IMPORT-INDEPENDENCE",
  "V2I-05-HANDLE-IO","V2I-06-TRANSACTION-RECOVERY","V2I-07-PARITY",
  "V2I-08-NATIVE-NO-SPAWN","V2I-09-NONAUTHORITY",
  "V2I-10-RUNTIME-BUILD-CHAIN",
  "V2I-11-QUARANTINE-LOCATOR-AND-NATIVE-TRANSPORT",
  "V2I-12-AUTHENTICATED-FOURTH-CAPTURE-LIFECYCLE",
  "V2I-13-EXACT-NATIVE-METADATA-STREAMS",
  "V2I-14-CONTROL-STATUS-SOURCE-AND-PATH-BINDING",
  "V2I-15-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION",
  "V2I-16-NO-RETRY-STATE-ARTIFACT-TOTALITY",
  "V2I-17-PLATFORM-AUTHORITY-BOUNDARY",
  "V2I-18-IMMUTABLE-CONTAINMENT-POLICY-AND-TYPED-OBSERVATIONS",
  "V2I-19-DISJOINT-DERIVED-PATH-FAMILIES",
  "V2I-20-REGISTERED-PERSISTED-TRANSPORT-ROOTS",
  "V2I-21-HEADLESS-PRE-GENESIS-QUARANTINE",
  "V2I-22-SPAWN-UNCERTAINTY-CGROUP-TERMINATION"),result:E("PASS","FAIL"),
  evidence:A(R(file_identity),1,10000000,true))
```

The exact ordered `source_check` roster is the former six followed by
`SRV-07-VECTOR-CAPTURE-BOOTSTRAP-MODE` and
`SRV-08-CONTAINMENT-SUPERVISOR-SOURCE`; `source_review_root.checks` is
`A(R(source_check),8,8,true)`.  The root also requires
`reviewed_modes:A(E("PARITY_V2","VECTOR_CAPTURE_V1"),1,2,true)` with the
exclusive source-kind rule from section 16.2.  This changes no source-review
path count: the separately reviewed bootstrap file is one review artifact with
two explicitly reviewed modes, not a second artifact inferred from equality.

The renderer wraps the replaced `source_review_root` in this additional exact
constraint after adding `reviewed_modes` to its closed object:

```json
{"allOf":[{"if":{"properties":{"source_kind":{"const":"BOOTSTRAP"}},"required":["source_kind"]},"then":{"properties":{"reviewed_modes":{"const":["PARITY_V2","VECTOR_CAPTURE_V1"]}}},"else":{"properties":{"reviewed_modes":{"const":["PARITY_V2"]}}}}]}
```

The existing exclusive source-kind/disposition constraint remains conjunctive.
A mode in prose, a second review with the same bytes, or subject equality cannot
substitute for this parsed-value constant.

The exact ordered `implementation_check` roster is the former twelve, with
V2I-12 retaining its R3.1-expanded meaning from section 16.2, followed by:

```text
V2I-13-EXACT-NATIVE-METADATA-STREAMS
V2I-14-CONTROL-STATUS-SOURCE-AND-PATH-BINDING
V2I-15-PROTECTED-ANCHORS-AND-KERNEL-SERIALIZATION
V2I-16-NO-RETRY-STATE-ARTIFACT-TOTALITY
V2I-17-PLATFORM-AUTHORITY-BOUNDARY
V2I-18-IMMUTABLE-CONTAINMENT-POLICY-AND-TYPED-OBSERVATIONS
V2I-19-DISJOINT-DERIVED-PATH-FAMILIES
V2I-20-REGISTERED-PERSISTED-TRANSPORT-ROOTS
V2I-21-HEADLESS-PRE-GENESIS-QUARANTINE
V2I-22-SPAWN-UNCERTAINTY-CGROUP-TERMINATION
```

`implementation_review_root.subjects` is the section-15 closed object with the
required additional member `vector_capture_source:R(file_identity)` immediately
before `launcher`.  `vector_capture_source` and `launcher` are separately named
subjects, each equals the exact section-2
`capture_schema_contract_parity_evidence_v2.py` path and identity, and parsed-
value equality is explicitly tested.  The root has
`checks:A(R(implementation_check),22,22,true)`.  Its passing disposition and
all-false authority remain unchanged; it cannot review itself, its subjects,
or generated evidence.

The R3.1 acyclicity audit rejects all of the following before a renderer or
process can run: any payload containing its own frame identity; child status
containing status/run/output identity; operation ID depending on run paths;
run ID depending on candidate, receipt, completion, or its own value; first
anchor depending on an uncreated inode; lock anchor depending on a lease;
event/head identity depending on an unpersisted successor; source review
depending on generated capture output; or a review depending on itself.  ID
preimages remove only the named ID and body-digest members already specified;
no path, identity, or review value is discovered or backfilled.

All R3.1 passing review roots retain `authority_ceiling` with every flag false.
They establish only a reviewable future construction.  They do not create
schema files, execute scenarios, validate a host, authorize process spawn,
accept a native move, publish a marker, adopt a candidate, or satisfy the v3/v4
lineage bridge.  Admission remains exactly
`BLOCKED_PENDING_SEPARATELY_ACCEPTED_CROSSCHECK_V3_LINEAGE_BRIDGE`.


### 16.7 R3.1 frozen denominator and digest replacements

The section-10 JSON array, with the R3.1 `LRC2-42..46` rows displayed there,
is the only scenario constant.  Strict UTF-8 parsing and independent canonical
recomputation give:

```text
schema registry rows                         25
ordered successor inputs                     39
scenario rows / harness methods              52
ordered scenario subcases                    767
scenario IDs                                 LRC2-00..LRC2-51
mixed-scenario ordinals                      [23,32,33,34,35,38,42,46,50,51]
last-ten subcase counts                      [39,36,32,34,79,68,16,18,20,28]
CJ(scenarios) size bytes                     84801
CJ(scenarios) SHA-256                        2eb301a01e60847b1ce096c04b4df086869b216219714be49a70b1b4352b19c5
CONCAT(CJ(row)||LF) size bytes               84800
CONCAT(CJ(row)||LF) SHA-256                  70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99
top-level harness validations                54
amendment / implementation / source checks   25 / 22 / 8
```

The first 42 scenario rows contribute 397 subcases; the replacement
last ten contribute 370.  The 54 validations are one `check_schema`, one exact
root-constant validation, and 52 scenario methods.  A setup failure, skip,
subtest omission, method-count mismatch, subcase-count mismatch, or digest
mismatch is not a passing execution.

R3.1 replaces the mixed outcome enum with exactly eight values:

```text
E("ACCEPT","REJECT","ABORT_ATTEMPT","QUARANTINE_TRANSACTION",
  "ADOPT_COMMITTED","RECOVERY_TRANSITION","QUARANTINE_VECTOR_CAPTURE",
  "ADOPT_VECTOR_CAPTURE")
```

`RETRY_VECTOR_CAPTURE` is not an enum member.  `ACCEPT`, `ADOPT_COMMITTED`,
`RECOVERY_TRANSITION`, and `ADOPT_VECTOR_CAPTURE` require null error fields.
`REJECT`, `ABORT_ATTEMPT`, `QUARANTINE_TRANSACTION`, and
`QUARANTINE_VECTOR_CAPTURE` require an integer precedence and nonempty error
code.  Ordinary non-mixed rejection ordinals are `[43,44,45,47,48,49]`; mixed
rows remain the ten ordinals displayed above.  Scenario, result, and subcase
ordinal/ID ranges are `0..51` / `LRC2-00..LRC2-51`.

`scenario_manifest_root.scenarios` is the exact parsed 52-object constant,
with explanatory shape `A(R(scenario),52,52,true)` only.  The execution root
requires the exact 39 ordered successor identities, `method_count:C(52)`, and
`scenario_results:A(R(scenario_result),52,52,true)`.  Its nested subcase-result
arrays have the exact per-row cardinalities represented by the 767-subcase
constant.  The 25-row registry stream remains 5,315 bytes with SHA-256
`a63dac8bf7254ab7044e93de4ddd3455fb170251fb16554cb793cb07eca4c74d`;
the unchanged 39-path roster remains in section 15.6.  Actual rendered schema
file identities, scenario evidence identities, and review identities are
future outputs and MUST be recomputed; this contract does not fabricate them.

The marker-bounded section-14 `PARITY_V1_LOCAL_FRAGMENT` contains neither the
scenario constant nor the review rosters and is byte-unaffected by R3.1.
Independent marker extraction therefore remains exactly 22,213 UTF-8 bytes
with SHA-256
`97844a817f292066ae73dc554f7f747148e4569648dd783da7fdf0eb72f6ad3d`.
A renderer still recomputes that value from the marker-bounded bytes; it does
not copy the pin without checking it.

This freeze is still design-only.  No value in this section is an executed RED
or GREEN receipt, rendered schema, native-host capability proof, process-spawn
authorization, adoption, or admission.  The exact v3/v4 lineage blocker and
all-false authority ceiling remain unchanged.

## 17. R3.2 pre-spawn authority, path-family, and uncertain-spawn closure

R3.2 repairs the five independent-review blockers against the frozen R3.1
identity `40db2ea2749e831c8a6b4451455c69182389911883042db31d879217de30a98b`
(492,616 UTF-8 bytes).  It is a contract-only Part-0 successor.  It creates no
schema, fixture, implementation, process, native observation, receipt, review,
adoption, or admission authority.  Sections 16.1 and 16.5 remain unchanged:
Linux is the sole possible accepting native lane, Windows remains a
process-crash-only nonauthority, and macOS remains unavailable.  The no-retry
rule and the section-15.8 v3/v4 bridge blocker remain exact.

The R3.2 definitions below replace the same-named R3.1 definitions and delete
the permissive `vector_capture_operation_paths` object.  A renderer MUST reject
that old object, a generic `file_identity` where a typed native observation is
required, or any unregistered transaction-root discriminator.

### 17.1 Four disjoint, derived path families

Let `P` be the already retained, no-follow, Linux protected root ending in
`process_evidence_v2`; `B` the validated `base_snapshot_id`; `O` the already
computed `capture_operation_id`; `R` a 16-digit, zero-padded capture revision;
`Q` an already computed capture-quarantine ID; and `U` an authenticated
`capture_run_id`.  `J(P,x...)` is descriptor-relative joining of the listed
ASCII components, never string concatenation followed by a path reopen.  It
rejects empty, dot, dot-dot, separator-containing, NUL-containing, non-ASCII,
case-variant, normalization-variant, device, alternate-stream, or reserved
components.  The retained `P` handle, mount ID, `st_dev`, and root inode are
equal before and after every derivation and open.

The four relative prefixes are exact and pairwise prefix-disjoint:

```text
STATIC     = vector-captures/B/static/O
REVISION   = vector-captures/B/revisions/O/R
QUARANTINE = vector-captures/B/quarantine/O/Q
RUN        = vector-captures/B/runs/O/U
```

Containment policy bytes are immutable static inputs at
`vector-captures/B/containment-policies/<policy_set_id>`; this prefix is also
disjoint from the four operation families.  It is derived before `O`, and its
complete policy-set identity enters the execution-plan input to `O`.  No path
containing `O`, `R`, `Q`, or `U` enters the preimage that creates that value.

The exact objects are:

```text
vector_capture_static_paths =
O(family:C("STATIC"),base_snapshot_id:S1,
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  serialization_lock:PATH,intent:PATH,attempt:PATH,
  containment_instance:PATH,spawn_arm:PATH,control_record:PATH,
  status_record:PATH,authorization_record:PATH,stdout_spool:PATH,
  stderr_spool:PATH,observation:PATH,head:PATH,completion_stage:PATH,
  completion_final:PATH,terminal:PATH,operation_private_tree:PATH,
  family_sha256:HEX)

vector_capture_revision_paths =
O(family:C("REVISION"),base_snapshot_id:S1,
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_revision:I(0,9007199254740991),revision_text:S(16,16,"^[0-9]{16}$"),
  event:PATH,head_stage:PATH,head_history:PATH,head_backup:PATH,
  family_sha256:HEX)

vector_capture_quarantine_paths =
O(family:C("QUARANTINE"),base_snapshot_id:S1,
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_quarantine_id:S(40,41,"^pfg3v(?:cq|pgq)-[0-9a-f]{32}$"),
  intent:PATH,uncertainty_record:PATH,progress_root:PATH,complete:PATH,terminal:PATH,
  artifacts_root:PATH,private_tree_destination:PATH,family_sha256:HEX)

vector_capture_run_paths =
O(family:C("RUN"),base_snapshot_id:S1,
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_run_id:S(40,40,"^pfg3vcr-[0-9a-f]{32}$"),
  candidate_stage:PATH,candidate_final:PATH,
  receipt_stage:PATH,receipt_final:PATH,family_sha256:HEX)
```

Within each family, the leaf roster and order are the field order displayed
above.  Static leaf names are respectively `serialization.lock.v1.bin`,
`intent.v2.json`, `attempt.v2.json`, `containment-instance.v1.json`,
`spawn-arm.v1.json`, `control.binding.v3.json`, `status.binding.v3.json`,
`run-authorization.v3.json`, `stdout.spool.v1.bin`, `stderr.spool.v1.bin`,
`observation.v2.json`, `head.v2.json`, `completion.stage.v2.json`,
`completion.v2.json`, `terminal.v2.json`, and `operation-private`.  Revision
leaf names are `event.v2.json`, `head.next.v2.json`, `head.previous.v2.json`,
and `head.displaced.v2.json`.  Quarantine leaf names are
`quarantine.intent.v3.json`, `spawn-uncertainty.v1.json`, `move-progress`, `quarantine.v3.json`,
`terminal.v3.json`, `artifacts`, and `operation-private`.  Run leaf names are
`vector-bundle.candidate.stage.v1.json`, `vector-bundle.candidate.v1.json`,
`vector-bundle.capture-receipt.stage.v1.json`, and
`vector-bundle.capture-receipt.v1.json`.

Every path equals `J(P,<the exact prefix>,<the exact leaf>)`.  The four digests
are exactly:

```text
STATIC.family_sha256 = SHA-256(CJ({domain:
  "PROGRAM_FACTS_G3_VECTOR_STATIC_PATH_FAMILY_V1",base_snapshot_id,
  capture_operation_id,ordered_paths}))
REVISION.family_sha256 = SHA-256(CJ({domain:
  "PROGRAM_FACTS_G3_VECTOR_REVISION_PATH_FAMILY_V1",base_snapshot_id,
  capture_operation_id,capture_revision,revision_text,ordered_paths}))
QUARANTINE.family_sha256 = SHA-256(CJ({domain:
  "PROGRAM_FACTS_G3_VECTOR_QUARANTINE_PATH_FAMILY_V1",base_snapshot_id,
  capture_operation_id,capture_quarantine_id,ordered_paths}))
RUN.family_sha256 = SHA-256(CJ({domain:
  "PROGRAM_FACTS_G3_VECTOR_RUN_PATH_FAMILY_V1",base_snapshot_id,
  capture_operation_id,capture_run_id,ordered_paths}))
```

The semantic validator recomputes all members and the digest; it never accepts
a caller-supplied path as derivation evidence.  The four path sets have empty
intersection, no member aliases a policy path, and every transaction root below
names exactly the family permitted for its lifecycle state.  `run_paths` is
null before durable authenticated status.  `quarantine_paths` is null before
the quarantine-ID preimage is complete.  A revision path uses its own revision
and cannot be reused by an adjacent revision.  `revision_text` is exactly the
unsigned base-10 rendering of `capture_revision`, left-padded with ASCII zero to
16 bytes; parse(render(x)) equals x and any sign, space, non-digit, overflow, or
alternate-width rendering rejects.

### 17.2 Immutable policy bytes and operation-private containment

R3.2 replaces digest-only containment claims with immutable artifacts whose
preimages and native encodings are closed.  The policy preimages are:

```text
vector_root_policy_row =
O(ordinal:I(0,255),root_kind:E("SYSTEM_RUNTIME_READ_ONLY",
  "INPUT_SNAPSHOT_READ_ONLY","OPERATION_PRIVATE_WRITABLE"),
  root:Q(R(directory_locator)),root_template:Q(C("STATIC_OPERATION_PRIVATE_TREE")),
  access:E("READ_EXECUTE","READ_ONLY","READ_WRITE"),
  recursive:C(true),no_device:C(true),no_suid:C(true),
  no_exec:U(C(true),C(false)))

vector_handle_policy_row =
O(ordinal:I(0,15),phase:E("SUPERVISOR_SETUP","BOOTSTRAP_RUNTIME"),
  role:E("RUNTIME_ROOT","INPUT_ROOT","OUTPUT_PARENT","POLICY_ROOT",
  "CONTROL_READ","STATUS_WRITE","START_GATE_READ","STDOUT_WRITE",
  "STDERR_WRITE"),direction:E("CHILD_READ","CHILD_WRITE",
  "CHILD_READ_WRITE"),cloexec:U(C(true),C(false)),
  close_before_bootstrap:U(C(true),C(false)),all_other_handles_denied:C(true))

vector_landlock_rule =
O(ordinal:I(0,255),root_ordinal:I(0,255),
  handled_access_fs:A(E("EXECUTE","WRITE_FILE","READ_FILE","READ_DIR",
  "REMOVE_DIR","REMOVE_FILE","MAKE_CHAR","MAKE_DIR","MAKE_REG",
  "MAKE_SOCK","MAKE_FIFO","MAKE_BLOCK","MAKE_SYM","REFER","TRUNCATE"),
  1,15,true),allowed_access_fs:A(S1,0,15,true))

vector_seccomp_instruction =
O(ordinal:I(0,4095),code:I(0,65535),jt:I(0,255),jf:I(0,255),
  k:I(0,4294967295))

vector_mount_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_MOUNT_POLICY_V1"),
  roots:A(R(vector_root_policy_row),3,256,true),
  private_mount_namespace:C(true),root_propagation:C("MS_PRIVATE_REC"),
  pivot_root:C("EMPTY_TMPFS_ROOT"),proc_mount:C("PRIVATE_HIDE_OTHER_PIDS"),
  dev_mount:C("MINIMAL_EMPTY_NO_DEVICE_NODES"),
  operation_private_single_writable:C(true))

vector_landlock_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_LANDLOCK_POLICY_V1"),abi:I(1,64),
  rules:A(R(vector_landlock_rule),1,256,true),no_best_effort:C(true))

vector_seccomp_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_SECCOMP_POLICY_V1"),
  architecture:E("AUDIT_ARCH_X86_64","AUDIT_ARCH_AARCH64"),
  default_action:C("SECCOMP_RET_KILL_PROCESS"),
  instructions:A(R(vector_seccomp_instruction),1,4096,true))

vector_network_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_NETWORK_POLICY_V1"),
  new_network_namespace:C(true),interfaces:C([]),loopback_up:C(false),
  socket_syscalls_denied:C(true),outbound_packets_allowed:C(0))

vector_cgroup_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_CGROUP_POLICY_V1"),version:C(2),
  clone_primitive:C("CLONE3_CLONE_INTO_CGROUP_PIDFD_V1"),pids_max:C("1"),
  delegated_controllers:C(["cpu","memory","pids"]),
  memory_max_bytes:I(67108864,8589934592),cpu_quota_us:I(1000,1000000),
  cpu_period_us:I(1000,1000000),cgroup_kill_required:C(true),
  empty_poll_count:C(2),reuse:C("FORBIDDEN"))

vector_handle_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_HANDLE_POLICY_V1"),
  allowed:A(R(vector_handle_policy_row),9,9,true),setup_handle_count:C(4),
  runtime_handle_count:C(5),
  retained_parent_handles_in_child:C(0),close_range_applied:C(true))

vector_namespace_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_NAMESPACE_POLICY_V1"),
  clone_flags:C(["CLONE_NEWCGROUP","CLONE_NEWIPC","CLONE_NEWNET",
  "CLONE_NEWNS","CLONE_NEWPID","CLONE_NEWUSER","CLONE_NEWUTS",
  "CLONE_PIDFD","CLONE_INTO_CGROUP"]),
  uid_map:C("SINGLE_CALLER_UID_NO_HOST_CAPABILITIES"),
  gid_map:C("SINGLE_CALLER_GID_SETGROUPS_DENY"),
  trusted_supervisor_before_exec:C(true))

vector_policy_preimage =
U(R(vector_mount_policy_preimage),R(vector_landlock_policy_preimage),
  R(vector_seccomp_policy_preimage),R(vector_network_policy_preimage),
  R(vector_cgroup_policy_preimage),R(vector_handle_policy_preimage),
  R(vector_namespace_policy_preimage))
```

Cross-row rules require exactly one `OPERATION_PRIVATE_WRITABLE`
row, no other writable row, unique ascending ordinals, and
`allowed_access_fs` to be a subset of the applicable handled mask.  Read-only
rows require nonnull `root` and null `root_template`; the operation-private row
requires null `root`, the constant template, `READ_WRITE`, and is instantiated
only with `static_paths.operation_private_tree` after `O` exists.  Thus no
operation-derived path enters the policy-set or operation-ID preimage.  Seccomp
instruction ordinals are contiguous from zero and jump targets remain within
the array.
Handle rows are exactly, in ordinal order, the four `SUPERVISOR_SETUP` roles
RUNTIME_ROOT, INPUT_ROOT, OUTPUT_PARENT, POLICY_ROOT followed by the five
`BOOTSTRAP_RUNTIME` roles CONTROL_READ, STATUS_WRITE, START_GATE_READ,
STDOUT_WRITE, STDERR_WRITE.  Setup rows have `cloexec:true` and
`close_before_bootstrap:true`; runtime rows have both false.  OUTPUT_PARENT
alone is read/write during setup and resolves to the retained static-family
parent.  The reviewed supervisor may exclusively create only the exact derived
`operation-private` leaf below it; the other setup roots are read-only.  The
supervisor closes all setup
root descriptors and applies `close_range`/explicit enumeration before exec.
The delegated cgroup descriptor, policy artifact descriptors, serialization
lease, host roots, and parent pipe ends are never runtime handles.

The immutable binding and set are:

```text
vector_policy_artifact =
O(policy_kind:E("MOUNT","LANDLOCK","SECCOMP","NETWORK","CGROUP",
  "HANDLES","NAMESPACES"),preimage:R(vector_policy_preimage),
  encoding:E("STRICT_CF_JSON_V1","CLASSIC_BPF_SOCK_FILTER_LE_V1"),
  materialized_bytes:R(content_identity),artifact:R(file_identity),
  preimage_sha256:HEX,materialization_sha256:HEX)

vector_containment_policy_set =
O(policy_set_id:S(40,40,"^pfg3vps-[0-9a-f]{32}$"),
  policy_root:R(directory_locator),
  policies:A(R(vector_policy_artifact),7,7,true),policy_set_sha256:HEX,
  immutable_three_read_complete:C(true),authority_ceiling:R(authority_v2))
```

Policy order is exactly MOUNT, LANDLOCK, SECCOMP, NETWORK, CGROUP, HANDLES,
NAMESPACES.  Every non-seccomp `materialized_bytes` is exactly `CF(preimage)`.
The seccomp bytes are the concatenation, in ordinal order, of each classic-BPF
`sock_filter` instruction encoded `u16(code) || u8(jt) || u8(jf) || u32(k)`,
all little-endian where wider than one byte.  `preimage_sha256` hashes
`CJ(preimage)`.  `materialization_sha256` hashes
`CJ({domain:"PROGRAM_FACTS_G3_VECTOR_POLICY_MATERIALIZATION_V1",policy_kind,
encoding,preimage_sha256,materialized_bytes})`.  Each artifact's retained-handle
three-read bytes equal `materialized_bytes`, its path equals the policy-root
derivation for its policy kind, and its file identity is unique.  The set ID is
the first 32 hex characters of `SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_VECTOR_POLICY_SET_ID_V1",base_snapshot_id,
policy_materializations:[{policy_kind,encoding,preimage_sha256,
materialized_bytes,materialization_sha256}...]}))`.  The ID preimage expressly
excludes `policy_set_id`, `policy_root`, every artifact path/file identity, and
`policy_set_sha256`.  Only after that ID exists are the seven artifact paths
derived.  `policy_set_sha256` then hashes `CJ({domain:
"PROGRAM_FACTS_G3_VECTOR_POLICY_SET_V1",policy_set_id,policy_root,policies})`
and covers their complete ordered identities.  Equal digests, filenames, or
prose without byte equality do not satisfy a policy.

The operation-private cgroup is never a caller-supplied directory and never a
shared pool entry:

```text
vector_containment_plan =
O(backend:C("LINUX_CLONE3_POLICY_ARTIFACT_CGROUP_V2_V1"),
  policy_set:R(vector_containment_policy_set),
  delegated_cgroup_root:R(directory_locator),
  cgroup_path_template:C("plamen-vector/<capture_operation_id>"),
  trusted_supervisor:R(file_identity),trusted_supervisor_review:R(file_identity),
  clone_primitive:C("CLONE3_CLONE_INTO_CGROUP_PIDFD_V1"),
  attempt_max_count:C(1),network_policy:C("DENY_ALL"),
  child_process_policy:C("CGROUP_PIDS_MAX_ONE"),
  output_policy:C("STATIC_OPERATION_PRIVATE_TREE_ONLY"),
  authority_ceiling:R(authority_v2))

vector_cgroup_instance =
O(instance_id:S(40,40,"^pfg3vcg-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  policy_set_id:S(40,40,"^pfg3vps-[0-9a-f]{32}$"),
  delegated_root:R(directory_locator),relative_path:R(quarantine_relative_path),
  directory_inode:R(directory_inode_identity),creation:C("MKDIRAT_EXCLUSIVE"),
  precreate_absent:C(true),initial_procs:C([]),pids_max_written:C("1"),
  pids_max_reread:C("1"),memory_max_written:I(67108864,8589934592),
  memory_max_reread:I(67108864,8589934592),cpu_max_written:S1,
  cpu_max_reread:S1,kill_supported:C(true),reuse:C("FORBIDDEN"),
  configuration_observation:R(vector_cgroup_stage_observation),
  state:C("CONFIGURED_EMPTY"))

vector_containment_instance_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("CONTAINMENT_INSTANCE"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  policy_set:R(vector_containment_policy_set),
  cgroup:R(vector_cgroup_instance),trusted_supervisor:R(file_identity),
  trusted_supervisor_review:R(file_identity),state:C("CONTAINMENT_READY"),
  policy_instantiation_sha256:HEX,
  disposition:C("PRIVATE_VECTOR_CONTAINMENT_INSTANCE_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

This `vector_containment_plan` replaces the R3.1 object in
`vector_capture_execution_plan`.  It contains only stable pre-operation inputs
and the literal templates; it contains no operation ID, derived cgroup path,
cgroup inode, namespace/process observation, or run output.  The plan and the
complete execution plan enter the operation-ID preimage; the instantiated
cgroup and static writable path do not.  This ordering is mechanically checked
to reject both the former cgroup-path cycle and the policy-root cycle.
`policy_instantiation_sha256` is exactly `SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_VECTOR_POLICY_INSTANTIATION_V1",policy_set_id,
capture_operation_id,static_paths.operation_private_tree,cgroup,
trusted_supervisor,trusted_supervisor_review}))`; it is computed after the
operation ID and cannot feed that ID.  Every template occurrence is replaced
only for native construction, never by modifying the immutable policy bytes.

No unlisted source or new successor path is implied by `trusted_supervisor`.
Its source is the exact named native-template byte region in the already listed
and independently reviewed `build_private_runtime_v1.py` runtime-builder
subject; that region's offset, length, SHA-256, compiler invocation, toolchain,
and resulting runtime-member identity are added to the existing build-plan lock
and closure.  The binary is one expected private-runtime member, not a host
binary or downloaded helper.  SRV-08 reviews that exact region and build join;
the existing source-review artifact carries the extra check, so the 25-schema
registry and 39-path successor roster do not grow.  A generated C string whose
bytes are not independently extracted/reviewed, a host helper, or a binary-only
pin without the source/build join rejects.

`relative_path` is exactly `plamen-vector/<capture_operation_id>` below the
delegated cgroup-v2 root.  The instance ID derives from domain, operation ID,
policy-set ID, delegated-root physical identity, and relative path.  Exclusive
creation, initial empty read, configuration write/reread, and a durable
`CONTAINMENT_READY` record occur before `SPAWN_ARMED`.  `clone3` uses the
retained cgroup descriptor with `CLONE_INTO_CGROUP|CLONE_PIDFD`; there is no
create-then-attach race.  The child first runs only the immutable independently
reviewed supervisor.  It constructs namespaces, mount tree, Landlock, seccomp,
handle closure, and the private network before it can exec the reviewed Python
bootstrap.  The untrusted producer cannot execute before authenticated status
is durably bound and the parent sends the authorization gate.
The embedded configuration observation has stage `CONFIGURED_EMPTY`, the same
instance ID and directory inode, zero-byte `cgroup.procs`, `populated 0`, and
typed native calls covering exclusive mkdir, `pids.max` write/reread,
`memory.max` and `cpu.max` write/reread, `cgroup.kill` capability open, and the
complete initial reads.  The two memory integers equal the policy value; both
CPU strings equal `ASCII(cpu_quota_us) || 0x20 || ASCII(cpu_period_us)` and
round-trip exactly.  A boolean in
the instance cannot substitute for these native bytes.

Typed native observations replace the R3.1 generic `native_evidence` array:

```text
vector_native_call =
O(ordinal:I(0,4095),api:S1,arguments_sha256:HEX,result:I(-4095,9007199254740991),
  errno:I(0,4095),raw_result:R(content_identity))

vector_namespace_observation =
O(kind:C("NAMESPACE"),name:E("USER","MOUNT","NETWORK","PID","IPC","UTS",
  "CGROUP"),parent_namespace:R(handle_identity),child_namespace:R(handle_identity),
  distinct:C(true),readlink_bytes:R(content_identity),calls:A(R(vector_native_call_r3_6),1,64,true))

vector_mount_observation =
O(kind:C("MOUNT"),policy:R(artifact_ref),mountinfo_bytes:R(content_identity),
  parsed_root_roster_sha256:HEX,only_operation_private_writable:C(true),
  propagation_private:C(true),calls:A(R(vector_native_call_r3_6),1,4096,true))

vector_landlock_observation =
O(kind:C("LANDLOCK"),policy:R(artifact_ref),abi:I(1,64),ruleset_fd:R(handle_identity),
  restrict_self_result:C(0),denial_probe_count:I(1,256),all_denied:C(true),
  calls:A(R(vector_native_call_r3_6),1,4096,true))

vector_seccomp_observation =
O(kind:C("SECCOMP"),policy:R(artifact_ref),no_new_privs_result:C(0),
  filter_install_result:C(0),seccomp_mode:C(2),denial_probe_count:I(1,256),
  all_denied:C(true),calls:A(R(vector_native_call_r3_6),1,4096,true))

vector_handle_observation =
O(kind:C("HANDLES"),policy:R(artifact_ref),proc_fd_bytes:R(content_identity),
  observed_roles:C(["CONTROL_READ","STATUS_WRITE","START_GATE_READ",
  "STDOUT_WRITE","STDERR_WRITE"]),unexpected_count:C(0),
  calls:A(R(vector_native_call_r3_6),1,4096,true))

vector_network_observation =
O(kind:C("NETWORK"),policy:R(artifact_ref),interfaces:C([]),loopback_up:C(false),
  packet_count:C(0),socket_success_count:C(0),
  calls:A(R(vector_native_call_r3_6),1,4096,true))

vector_cgroup_stage_observation =
O(kind:C("CGROUP"),stage:E("CONFIGURED_EMPTY","SPAWN_ARMED","PROCESS_OBSERVED",
  "KILL_REQUESTED","EMPTY_FIRST","EMPTY_SECOND"),
  instance_id:S(40,40,"^pfg3vcg-[0-9a-f]{32}$"),
  directory_inode:R(directory_inode_identity),cgroup_procs:R(content_identity),
  cgroup_events:R(content_identity),populated:E(0,1),
  calls:A(R(vector_native_call_r3_6),1,256,true))

vector_cgroup_removed_observation =
O(kind:C("CGROUP_REMOVED"),stage:C("REMOVED"),
  instance_id:S(40,40,"^pfg3vcg-[0-9a-f]{32}$"),
  prior_directory_inode:R(directory_inode_identity),
  retained_parent:R(directory_locator),relative_path:R(quarantine_relative_path),
  unlink_call:R(vector_native_call_r3_6),derived_entry_absent:C(true))

vector_cgroup_terminal_observation =
U(R(vector_cgroup_stage_observation),R(vector_cgroup_removed_observation))

vector_native_observation =
U(R(vector_namespace_observation),R(vector_mount_observation),
  R(vector_landlock_observation),R(vector_seccomp_observation),
  R(vector_handle_observation),R(vector_network_observation),
  R(vector_cgroup_stage_observation),R(vector_cgroup_removed_observation))

vector_confirmed_post_operation_instance =
O(instance_kind:C("CONFIRMED_PROCESS"),
  policy_set:R(vector_containment_policy_set),cgroup:R(vector_cgroup_instance),
  actual_process:R(vector_actual_process_identity),
  native_observations:A(R(vector_native_observation),13,10000,true),
  cgroup_final_state:E("EMPTY_RETAINED_FOR_QUARANTINE",
  "EMPTY_REMOVED_AFTER_COMMIT"),operation_private_tree_writers:C(0),
  inherited_child_handles_open:C(0),out_of_scope_write_count:C(0),
  network_packet_count:C(0),descendant_process_count:C(0),
  observation_set_sha256:HEX)

vector_uncertain_post_operation_instance =
O(instance_kind:C("SPAWN_UNCERTAIN"),
  policy_set:R(vector_containment_policy_set),cgroup:R(vector_cgroup_instance),
  native_execution_authority:R(vector_native_ffi_authority_r3_6),
  native_execution_receipt:R(vector_native_execution_receipt_r3_6),
  actual_process:C(null),trusted_supervisor_only_possible:C(true),
  authorization_gate_released:C(false),run_paths:C(null),
  atomic_clone_namespace_request:C(["CGROUP","IPC","NETWORK","MOUNT","PID",
  "USER","UTS"]),native_observations:A(R(vector_cgroup_stage_observation),3,3,true),
  cgroup_final_state:C("EMPTY_RETAINED_FOR_QUARANTINE"),
  operation_private_tree_writers:C(0),inherited_child_handles_open:C(0),
  out_of_scope_write_count:C(0),network_packet_count:C(0),
  descendant_process_count:C(0),observation_set_sha256:HEX)

vector_no_spawn_post_operation_instance =
O(instance_kind:C("NO_SPAWN"),policy_set:R(vector_containment_policy_set),
  cgroup:R(vector_cgroup_instance),actual_process:C(null),
  authorization_gate_released:C(false),run_paths:C(null),
  native_observations:A(R(vector_cgroup_terminal_observation),1,2,true),
  cgroup_final_state:E("EMPTY_RETAINED_FOR_QUARANTINE",
  "EMPTY_REMOVED_BEFORE_SPAWN"),operation_private_tree_writers:C(0),
  inherited_child_handles_open:C(0),out_of_scope_write_count:C(0),
  network_packet_count:C(0),descendant_process_count:C(0),
  observation_set_sha256:HEX)

vector_post_operation_instance =
U(R(vector_confirmed_post_operation_instance),
  R(vector_uncertain_post_operation_instance),
  R(vector_no_spawn_post_operation_instance))
```

For `CONFIRMED_PROCESS`, the minimum 13 observations are seven distinct
namespaces, one each of mount, Landlock, seccomp, handles, and network, plus at
least one cgroup stage; every required cgroup lifecycle stage is additionally
present.  For `SPAWN_UNCERTAIN`, no child/process/namespace identity may be
invented: the exact cgroup observations are `KILL_REQUESTED`, `EMPTY_FIRST`,
`EMPTY_SECOND` in that order, and the uncertainty lane
depends only on the atomically requested clone namespaces, immutable reviewed
supervisor, unreleased authorization gate, and stable cgroup empty.  In both
branches `observation_set_sha256` hashes the complete typed ordered array.
Generic identities, prose booleans, wrong union branches, policy substitutions,
cgroup reuse, absent post-operation state, or missing native call bytes fail
before evidence or cleanup authority.
The uncertain branch's three-element `native_observations` array is parsed-value
equal, in order, to the enclosing uncertainty object's `kill_requested`,
`empty_first`, and `empty_second` members; duplication with merely equal hashes
or a fourth generic row rejects.
The `NO_SPAWN` branch begins with the instance's parsed-value-equal
`CONFIGURED_EMPTY` observation and may end with its matching typed `REMOVED`
row.  The removed final state requires exactly those two rows; the retained
state requires only the first.  It is available from `CONTAINMENT_READY` and
from `ATTEMPT_PREPARED` only when recovery finds the one derived cgroup path
after a crash during exclusive creation/configuration.  In the latter case it
must reconstruct the complete instance and typed configuration bytes from the
retained delegated-root/path handles, prove empty, and use them only as cleanup
evidence; it may not publish/backfill `CONTAINMENT_READY`.  An absent derived
path selects `PRE_CONTAINMENT`.  A malformed, foreign, reused, or populated
derived cgroup path blocks automatically rather than being removed.  The
branch is never available from `SPAWN_ARMED` or a post-status state.
For a confirmed instance, `EMPTY_REMOVED_AFTER_COMMIT` requires the final typed
observation to be the matching `vector_cgroup_removed_observation`; the retained
state forbids that branch.  The uncertain instance is captured before artifact
quarantine and therefore always ends `EMPTY_RETAINED_FOR_QUARANTINE`; any later
cgroup removal is a terminal cleanup event after COMPLETE and cannot replace
the two empty-stage observations.

The normative Linux API meanings are constrained by the kernel documentation
for cgroup v2, Landlock, seccomp filters, and namespaces and by the Linux
`clone3(2)` interface description:

- `https://docs.kernel.org/admin-guide/cgroup-v2.html`
- `https://docs.kernel.org/userspace-api/landlock.html`
- `https://docs.kernel.org/userspace-api/seccomp_filter.html`
- `https://man7.org/linux/man-pages/man7/namespaces.7.html`
- `https://man7.org/linux/man-pages/man2/clone3.2.html`

Those sources constrain future implementation and fixtures; their presence is
not evidence that a current host executed any predicate.

### 17.3 Registered control, status, and authorization roots

The three transport bindings are persisted transaction roots, not implicit
objects.  They have these exact closed schemas:

```text
vector_capture_control_payload =
O(schema_version:C("plamen.program_facts_parity_vector_capture_control.v3"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  attempt_ordinal:C(0),base_snapshot:R(base_input_snapshot_projection),
  source_binding:R(vector_capture_source_binding),
  bootstrap_binding:R(vector_capture_bootstrap_binding),
  interpreter:R(execution_interpreter),host_receipt:R(vector_capture_host_receipt),
  execution_plan:R(vector_capture_execution_plan),
  static_paths:R(vector_capture_static_paths),
  start_gate_child_handle_value:S(1,20,"^(?:0|[1-9][0-9]*)$"),
  status_write_child_handle_value:S(1,20,"^(?:0|[1-9][0-9]*)$"),
  framing_contract:R(vector_capture_framing_contract),
  authority_ceiling:R(authority_v2))

vector_capture_control_record_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("CONTROL_RECORD"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  payload:R(vector_capture_control_payload),payload_bytes:R(content_identity),
  control_frame:R(vector_capture_json_frame_identity),
  source_frame:R(vector_capture_source_frame_identity),
  complete_control_read:R(content_identity),record_path:PATH,
  disposition:C("PRIVATE_VECTOR_CONTROL_RECORD_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_status_record_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("STATUS_RECORD"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  control_record:R(artifact_ref),static_paths:R(vector_capture_static_paths),
  payload:R(vector_capture_child_status_payload),payload_bytes:R(content_identity),
  status_frame:R(vector_capture_json_frame_identity),
  parent_actual_process:R(vector_actual_process_identity),
  source_to_process_join_sha256:HEX,record_path:PATH,
  disposition:C("PRIVATE_VECTOR_STATUS_RECORD_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_authorization_record_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("AUTHORIZATION_RECORD"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),capture_run_id:S(40,40,
  "^pfg3vcr-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  status_record:R(artifact_ref),static_paths:R(vector_capture_static_paths),
  run_paths:R(vector_capture_run_paths),
  payload:R(vector_capture_run_authorization),payload_bytes:R(content_identity),
  gate_frame:R(vector_capture_json_frame_identity),record_path:PATH,
  disposition:C("PRIVATE_VECTOR_AUTHORIZATION_RECORD_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

R3.2 deletes the standalone `vector_capture_control_binding`,
`vector_capture_status_binding`, and `vector_capture_gate_binding` definitions.
Every former parsed-value use becomes respectively the complete parsed
`vector_capture_control_record_root`, `vector_capture_status_record_root`, or
`vector_capture_authorization_record_root`; every identity use becomes the
corresponding persisted `artifact_ref`.  The source/process join substitutes
the registered control/status payload and frame members one-for-one.  The run
ID preimage substitutes `control_record` and `status_record` and still excludes
the authorization record, run ID, run paths, candidate, receipt, and completion.
The observation root contains `{control_record,control,status_record,status,
authorization_record,authorization}` with exact artifact-to-parsed-root body
equality.  No old binding object remains reachable from a rendered root.

For each record, persisted file bytes are exactly `CF(root)` after recomputing
the body digest by removing only `capture_body_sha256`.  `record_path` equals
the corresponding derived static-family member.  The exact native streams are:

```text
CONTROL = ASCII("PFG3VCT1") || U64BE(len(CF(control_payload))) ||
          CF(control_payload) || U64BE(source.size_bytes) || source.bytes || EOF
STATUS  = ASCII("PFG3VST1") || U64BE(len(CF(status_payload))) ||
          CF(status_payload) || EOF
GATE    = ASCII("PFG3VGA1") || U64BE(len(CF(authorization_payload))) ||
          CF(authorization_payload) || EOF
```

`payload_bytes`, each frame payload identity, each complete-frame identity, and
the complete CONTROL identity are independently recomputed from these bytes.
No identity supplied inside a payload authenticates its containing frame.
Missing EOF, trailing bytes, a copied digest, another operation's root, or a
record-file/transport-frame substitution rejects.

`vector_capture_transaction_root` is replaced by this exact closed union; order
is normative for renderer/reference auditing even though JSON Schema union
membership is set-like:

```text
vector_capture_transaction_root =
U(R(vector_capture_intent_root),R(vector_capture_attempt_root),
  R(vector_containment_instance_root),R(vector_spawn_arm_root),
  R(vector_capture_control_record_root),R(vector_capture_status_record_root),
  R(vector_capture_authorization_record_root),
  R(vector_capture_observation_root),R(vector_capture_event_root),
  R(vector_capture_head_root),R(vector_capture_completion_root),
  R(vector_capture_terminal_root),R(vector_capture_quarantine_prepared_root),
  R(vector_capture_quarantine_progress_root),
  R(vector_capture_quarantine_complete_root),
  R(vector_pre_genesis_quarantine_prepared_root),
  R(vector_pre_genesis_quarantine_progress_root),
  R(vector_pre_genesis_quarantine_complete_root),
  R(vector_pre_genesis_quarantine_terminal_root),
  R(vector_spawn_uncertainty_quarantine_root))
```

Thus every root discriminator is registered in the same rendered schema; no
open-ended `record_kind` dispatcher or side parser exists.  The following field
map is also exact and replaces every old `operation_paths` member:

| Root | Required path-family fields |
|---|---|
| intent, attempt, containment instance, spawn arm, control, status | `static_paths` only |
| authorization | `static_paths`, `run_paths` |
| event, head | `static_paths`, `revision_paths`; `run_paths` null before status and exact afterward |
| observation, completion | `static_paths`, `revision_paths`, `run_paths` |
| ordinary quarantine prepared/progress/complete, uncertainty quarantine | `static_paths`, `revision_paths`, `quarantine_paths`; `run_paths` only if source state has one |
| pre-genesis prepared/progress/complete/terminal | `static_paths`, `quarantine_paths`; event/head/revision/run absent |

Each named field is required, additional path fields are forbidden, and every
family object is parsed-value equal to the independently rederived object for
the root's IDs and state.  This map is a renderer rule, not informative prose.

### 17.4 Headless pre-genesis malformed-intent quarantine

The operation ID is deterministically recomputed from validated invocation
inputs before opening its fixed intent path.  If that path exists but cannot be
strictly parsed and validated, its bytes cannot supply an ID, event, head,
revision, or transaction identity.  Recovery captures the exact no-follow
entry identity and derives:

```text
pre_genesis_quarantine_id = "pfg3vpgq-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_PRE_GENESIS_QUARANTINE_V1",
  expected_capture_operation_id,static_paths.family_sha256,
  error_code:"PRE_GENESIS_INTENT_MALFORMED"
}))[0:32]
```

The closed family is:

```text
vector_pre_genesis_quarantine_prepared_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("PRE_GENESIS_QUARANTINE_PREPARED"),
  capture_quarantine_id:S(41,41,"^pfg3vpgq-[0-9a-f]{32}$"),
  expected_capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  attempt_ordinal:C(0),event:C(null),head:C(null),transaction_id:C(null),
  static_paths:R(vector_capture_static_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  malformed_intent_entry:R(quarantine_entry_ref),
  error_code:C("PRE_GENESIS_INTENT_MALFORMED"),
  planned_moves:A(R(quarantine_move),1,1,true),state:C("PREPARED"),
  disposition:C("PRIVATE_VECTOR_PRE_GENESIS_QUARANTINE_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_pre_genesis_quarantine_progress_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("PRE_GENESIS_QUARANTINE_PROGRESS"),
  capture_quarantine_id:S(41,41,"^pfg3vpgq-[0-9a-f]{32}$"),
  expected_capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  event:C(null),head:C(null),transaction_id:C(null),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  move_ordinal:C(0),planned_move:R(quarantine_move),
  reconciled_from:E("SOURCE_IDENTITY","DESTINATION_IDENTITY"),
  destination_entry:R(quarantine_entry_ref),source_absent:C(true),
  durability_barriers_complete:C(true),state:C("MOVE_DURABLE"),
  disposition:C("PRIVATE_VECTOR_PRE_GENESIS_QUARANTINE_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_pre_genesis_quarantine_complete_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("PRE_GENESIS_QUARANTINE_COMPLETE"),
  capture_quarantine_id:S(41,41,"^pfg3vpgq-[0-9a-f]{32}$"),
  expected_capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  event:C(null),head:C(null),transaction_id:C(null),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  move_progress:A(R(artifact_ref),1,1,true),state:C("COMPLETE"),
  disposition:C("PRIVATE_VECTOR_PRE_GENESIS_QUARANTINE_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_pre_genesis_quarantine_terminal_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("PRE_GENESIS_QUARANTINE_TERMINAL"),
  capture_quarantine_id:S(41,41,"^pfg3vpgq-[0-9a-f]{32}$"),
  expected_capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  event:C(null),head:C(null),transaction_id:C(null),complete:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  state:C("PRE_GENESIS_QUARANTINED"),retry_allowed:C(false),
  disposition:C("PRIVATE_VECTOR_PRE_GENESIS_TERMINAL_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

The family ID intentionally excludes the malformed entry identity, so the
fixed operation ID and error class rediscover the same family after the source
has moved; the prepared record itself binds the retained malformed entry and
rejects replacement under the serialization lease.  The prepared record is
durably created at the derived quarantine-family path before moving the
malformed fixed entry.  Progress uses source-or-destination
identity reconciliation and both directory barriers exactly as section 16.5.
The terminal follows exact COMPLETE and is discoverable from the independently
recomputed operation and quarantine IDs.  It does not create or mutate a
capture head/event and never authorizes intent recreation or spawn.

### 17.5 `SPAWN_MAY_HAVE_OCCURRED` without fabricated identity

Two durable states are inserted between `ATTEMPT_PREPARED` and `STATUS_BOUND`:
`CONTAINMENT_READY` and `SPAWN_ARMED`.  The arm is persisted before the sole
`clone3` call:

```text
vector_spawn_arm_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("SPAWN_ARM"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  containment_instance:R(artifact_ref),static_paths:R(vector_capture_static_paths),
  clone_primitive:C("CLONE3_CLONE_INTO_CGROUP_PIDFD_V1"),
  call_count_limit:C(1),call_started:C(false),actual_process:C(null),
  state:C("SPAWN_ARMED"),
  disposition:C("PRIVATE_VECTOR_SPAWN_ARM_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

`call_started:false` means only that no syscall result is part of these bytes;
it is not evidence the call did not occur.  If recovery sees `SPAWN_ARMED`
without a valid durable status root, it classifies exactly
`SPAWN_MAY_HAVE_OCCURRED`.  It neither reads a PID from a partial status pipe
nor fabricates PID, start time, pidfd, executable, namespace, or process
identity.

Recovery first operates only on the arm's exact cgroup instance.  It writes
the one exact ASCII byte `1` to `cgroup.kill`, verifies the exact write result,
reads `cgroup.events`
with `populated 0`, reads empty `cgroup.procs`, performs one poll/barrier cycle,
and repeats both reads as a second typed empty observation.  It closes the
clone pidfd slot if the kernel returned one to the live recovering process, but
does not claim one existed after a prior crash.  Only after both empty
observations and zero retained child/pipe/private-tree-writer handles may it
move artifacts or remove the cgroup.

For `KILL_REQUESTED`, the native-call argument bytes bind exact hex `31` and the
write result is 1.  `EMPTY_FIRST` and `EMPTY_SECOND` each bind a zero-byte
`cgroup.procs` identity and exact UTF-8 `cgroup.events` bytes whose strict line
parser contains one unique `populated 0` row; duplicate keys, CR, trailing
garbage, an unknown required key, or `populated 1` rejects.  All three rows use
the same retained delegated-root handle, relative component, directory inode,
mount ID, and `st_dev` as the durable instance.  The poll barrier observes the
cgroup events descriptor between the two complete reads.  `REMOVED`, if used,
occurs only after the second empty row and the private-tree disposition, uses
`unlinkat(AT_REMOVEDIR)` on the retained parent, and records the now-absent
derived entry; it cannot stand in for either empty observation.

```text
vector_spawn_uncertainty_observation =
O(classification:C("SPAWN_MAY_HAVE_OCCURRED"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),
  spawn_arm:R(artifact_ref),containment_instance:R(artifact_ref),
  actual_process:C(null),pid:C(null),process_start_identity:C(null),
  pidfd_identity:C(null),clone_result:C("UNOBSERVABLE_AFTER_CRASH"),
  kill_requested:R(vector_native_observation_record),
  empty_first:R(vector_native_observation_record),
  empty_second:R(vector_native_observation_record),
  poll_barrier_between:C(true),child_handles_open:C(0),
  operation_private_tree_writers:C(0),journaled_status_current:C(false),
  journaled_authorization_current:C(false),run_paths:C(null),
  replay_allowed:C(false),post_operation:R(vector_post_operation_instance),
  observation_sha256:HEX)

vector_operation_private_tree_entry =
O(entry_kind:C("OPERATION_PRIVATE_TREE"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  path:R(quarantine_source_path),tree_identity:R(quarantine_tree_identity),
  cgroup_stable_empty:C(true),writer_handle_count:C(0))

quarantine_entry_ref =
U(O(entry_kind:C("REGULAR_ARTIFACT"),artifact:R(artifact_ref)),
  O(entry_kind:C("WRITABLE_PROFILE_TREE"),writable_kind:E("PROFILE_ROOT",
    "LOCALAPPDATA","TEMP","TMP"),path:R(quarantine_source_path),
    tree_identity:R(quarantine_tree_identity)),
  O(entry_kind:C("NONREGULAR_CONFLICT"),path:R(quarantine_source_path),
    path_identity:R(quarantine_nonregular_identity)),
  R(vector_operation_private_tree_entry))

vector_uncertain_artifact_entry =
U(O(kind:C("ABSENT"),slot:E("CONTROL_RECORD","STATUS_RECORD",
    "AUTHORIZATION_RECORD","STDOUT_SPOOL","STDERR_SPOOL",
    "OPERATION_PRIVATE_TREE")),
  O(kind:C("FIXED_ENTRY"),slot:E("CONTROL_RECORD","STATUS_RECORD",
    "AUTHORIZATION_RECORD","STDOUT_SPOOL","STDERR_SPOOL"),
    source:R(quarantine_entry_ref),
    planned_move:R(quarantine_move)),
  O(kind:C("PRIVATE_TREE"),slot:C("OPERATION_PRIVATE_TREE"),
    source:R(vector_operation_private_tree_entry),planned_move:R(quarantine_move)))

vector_spawn_uncertainty_artifacts =
O(entries:A(R(vector_uncertain_artifact_entry),6,6,true),
  fixed_slot_order:C(["CONTROL_RECORD","STATUS_RECORD","AUTHORIZATION_RECORD",
  "STDOUT_SPOOL","STDERR_SPOOL","OPERATION_PRIVATE_TREE"]),
  directory_scan_count:C(0),
  outside_private_scope_count:C(0),all_sources_fixed_or_intact_tree:C(true))

vector_quarantine_process_basis =
U(O(kind:C("PRE_CONTAINMENT"),actual_process:C(null),post_operation:C(null),
    spawn_uncertainty:C(null)),
  O(kind:C("CONTAINMENT_NO_SPAWN"),actual_process:C(null),
    post_operation:R(vector_no_spawn_post_operation_instance),
    spawn_uncertainty:C(null)),
  O(kind:C("CONFIRMED_PROCESS"),actual_process:R(vector_actual_process_identity),
    post_operation:R(vector_post_operation_instance),spawn_uncertainty:C(null)),
  O(kind:C("SPAWN_UNCERTAIN"),actual_process:C(null),
    post_operation:R(vector_post_operation_instance),
    spawn_uncertainty:R(vector_spawn_uncertainty_observation)))

vector_capture_quarantine_prepared_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_PREPARED"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),error_code:S1,
  source_event:R(artifact_ref),static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  run_paths:Q(R(vector_capture_run_paths)),
  serialization_lease:R(kernel_serialization_lease),
  process_basis:R(vector_quarantine_process_basis),
  conflicting_entries:A(R(quarantine_entry_ref),0,32,true),
  planned_moves:A(R(quarantine_move),0,32,true),state:C("PREPARED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINE_INTENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_complete_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_COMPLETE"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),error_code:S1,
  intent:R(artifact_ref),serialization_lease:R(kernel_serialization_lease),
  static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  run_paths:Q(R(vector_capture_run_paths)),
  move_progress:A(R(artifact_ref),0,32,true),
  cleanup_disposition:E("ZERO_ARTIFACTS_COMPLETE","MOVED_COMPLETE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINED_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_terminal_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("TERMINAL"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),head:R(artifact_ref),
  state:C("QUARANTINED"),terminal_from_state:E("INTENT_DURABLE",
  "ATTEMPT_PREPARED","CONTAINMENT_READY","SPAWN_ARMED","STATUS_BOUND",
  "CHILD_OBSERVED","CANDIDATE_STAGED","CANDIDATE_PUBLISHED",
  "RECEIPT_STAGED","RECEIPT_PUBLISHED","COMPLETION_STAGED"),
  static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  run_paths:Q(R(vector_capture_run_paths)),error:R(transaction_error),
  quarantine_record:R(artifact_ref),spawn_uncertainty_record:Q(R(artifact_ref)),
  disposition:C("PRIVATE_VECTOR_CAPTURE_TERMINAL_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_spawn_uncertainty_quarantine_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("SPAWN_UNCERTAINTY_QUARANTINE"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),
  source_state:C("SPAWN_ARMED"),uncertainty:R(vector_spawn_uncertainty_observation),
  static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),run_paths:C(null),
  artifacts:R(vector_spawn_uncertainty_artifacts),
  quarantine_intent:R(vector_capture_quarantine_prepared_root),
  record_path:PATH,
  state:C("SPAWN_MAY_HAVE_OCCURRED_QUARANTINE_PREPARED"),
  disposition:C("PRIVATE_VECTOR_SPAWN_UNCERTAINTY_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantined_event_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("EVENT"),event_id:S(40,40,"^pfg3vce-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  capture_revision:I(1,9007199254740991),previous_event:R(artifact_ref),
  attempt_ordinal:C(0),state:C("QUARANTINED"),
  terminal_from_state:E("INTENT_DURABLE","ATTEMPT_PREPARED",
  "CONTAINMENT_READY","SPAWN_ARMED","STATUS_BOUND","CHILD_OBSERVED",
  "CANDIDATE_STAGED","CANDIDATE_PUBLISHED","RECEIPT_STAGED",
  "RECEIPT_PUBLISHED","COMPLETION_STAGED"),
  static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  run_paths:Q(R(vector_capture_run_paths)),
  serialization_lease:R(kernel_serialization_lease),
  artifacts:R(vector_capture_artifacts),
  capture_quarantine_intent:R(artifact_ref),
  spawn_uncertainty_record:Q(R(artifact_ref)),last_error:R(transaction_error),
  disposition:C("PRIVATE_VECTOR_CAPTURE_EVENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

The four `process_basis` branches are mutually exclusive.  `INTENT_DURABLE` or
`ATTEMPT_PREPARED` with the derived cgroup path absent requires
`PRE_CONTAINMENT`, while its exact interrupted-creation shape and
`CONTAINMENT_READY` require `CONTAINMENT_NO_SPAWN`; a
durable confirmed actual-process/status state requires `CONFIRMED_PROCESS` and
exact process equality in post-operation evidence; only `SPAWN_ARMED` may use
`SPAWN_UNCERTAIN`, whose actual process is necessarily null and whose
post-operation object equals the uncertainty observation's object.  This
replacement deletes the R3.1 rule that required a fabricated
`preobservation_process` merely because process creation might have started.
For `SPAWN_UNCERTAIN`, the conflicting-entry and move arrays equal, in order,
the non-ABSENT entries in the six-slot roster.  Empty arrays require the exact
all-ABSENT roster and `ZERO_ARTIFACTS_COMPLETE`; nonempty arrays require
contiguous progress `0..n-1` and `MOVED_COMPLETE`.  Other process-basis
branches retain the R3.1 minimum of one conflict/move and cannot select the
zero-artifact disposition.
For a `SPAWN_ARMED` source, `spawn_uncertainty_record` is nonnull and identifies
the exact `vector_spawn_uncertainty_quarantine_root`; its embedded uncertainty,
artifact roster, and ordinary prepared intent are parsed-value/artifact-equal
to the event's artifacts and `capture_quarantine_intent`.  Every other source
state requires `spawn_uncertainty_record:null`.  `vector_capture_event_root`
uses this quarantined-event replacement, so the uncertainty proof cannot remain
an unjoined side object.  The terminal repeats the same nullable artifact ref:
nonnull only for `SPAWN_ARMED`, byte-equal to the event ref, and joined through
the exact prepared intent and COMPLETE record.
The uncertainty root's `record_path` equals
`quarantine_paths.uncertainty_record`.  That fixed path is absent for every
non-`SPAWN_ARMED` ordinary family and every pre-genesis family; its presence in
those branches is a path-family mismatch, not an ignorable sidecar.

The six-entry roster is positional and exact; absence is an explicit branch.
Thus all-six-ABSENT is a justified zero-artifact result, not a failed scan.
`journaled_*_current:false` describes the durable head/event slots, not a claim
that the corresponding fixed pathname is absent.  A fully written but
unjournaled control, status, or authorization record is captured only as an
opaque `FIXED_ENTRY`; recovery neither parses it to invent process/run authority
nor backfills an event.  The authorization gate is released only after the
`STATUS_BOUND` event and head, which join all three registered records, are
durable.  Therefore an unjournaled authorization record cannot imply that the
producer gate was released.
The only movable child-writable object is the fixed operation-private tree.
It is captured as one same-mount intact-tree entry after stable cgroup empty and
moved no-replace using the section-16.1 metadata roster and section-16.5 Linux
barriers.  Parent spools and binding records use their fixed static names.
No run family exists because no authenticated status was durably bound.  Inputs,
runtime, policies, and all host roots were read-only; networking was private
with no interfaces; the reviewed supervisor could not release the producer
gate; and the cgroup admits at most one process.  Those closed facts plus typed
post-operation evidence justify zero out-of-scope side effects.  They authorize
quarantine only, never a retry, candidate, receipt, completion, or admission.

### 17.6 R3.2 lifecycle totality

The artifact-slot order is replaced by the following 17 slots:

```text
I=intent, AT=attempt, CI=containment_instance, SA=spawn_arm,
CT=control_record, ST=status_record, GA=authorization_record,
O=observation, SO=stdout_spool, SE=stderr_spool, CS=candidate_stage,
CF=candidate_final, RS=receipt_stage, RF=receipt_final,
MS=completion_stage, MF=completion_final, QN=quarantine
```

The complete ordinary matrix is:

| state | run paths | I | AT | CI | SA | CT | ST | GA | O | SO | SE | CS | CF | RS | RF | MS | MF | QN |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `INTENT_DURABLE` | absent | C | A | A | A | A | A | A | A | A | A | A | A | A | A | A | A | A |
| `ATTEMPT_PREPARED` | absent | C | C | A | A | A | A | A | A | A | A | A | A | A | A | A | A | A |
| `CONTAINMENT_READY` | absent | C | C | C | A | A | A | A | A | A | A | A | A | A | A | A | A | A |
| `SPAWN_ARMED` | absent | C | C | C | C | A | A | A | A | A | A | A | A | A | A | A | A | A |
| `STATUS_BOUND` | current | C | C | C | C | C | C | C | A | A | A | A | A | A | A | A | A | A |
| `CHILD_OBSERVED` | current | C | C | C | C | C | C | C | C | C | C | A | A | A | A | A | A | A |
| `CANDIDATE_STAGED` | current | C | C | C | C | C | C | C | C | C | C | C | A | A | A | A | A | A |
| `CANDIDATE_PUBLISHED` | current | C | C | C | C | C | C | C | C | C | C | P | C | A | A | A | A | A |
| `RECEIPT_STAGED` | current | C | C | C | C | C | C | C | C | C | C | P | C | C | A | A | A | A |
| `RECEIPT_PUBLISHED` | current | C | C | C | C | C | C | C | C | C | C | P | C | P | C | A | A | A |
| `COMPLETION_STAGED` | current | C | C | C | C | C | C | C | C | C | C | P | C | P | C | C | A | A |
| `COMMITTED` | current | C | C | C | C | C | C | C | C | C | C | P | C | P | C | P | C | A |
| `ADOPTED` | current | C | C | C | C | C | C | C | C | C | C | P | C | P | C | P | C | A |

`QUARANTINED` remains a source-prefix terminal over the first eleven pre-commit
states and has current QN and absent MF.  The `SPAWN_ARMED` uncertain branch
additionally requires the exact uncertainty root and six-slot artifact roster.
Pre-genesis terminal objects are outside the event/head matrix and use only the
headless family in section 17.4.  `vector_capture_artifacts`, event/head state
enums, legal-edge enumeration, and total cartesian complement are replaced to
match this table.  Legal ordinary edges are the displayed adjacent chain;
quarantine is legal from any of the first eleven states; commit/adopt can never
quarantine.  The former direct `ATTEMPT_PREPARED -> STATUS_BOUND` edge is
illegal.  No state called RETRY, EXHAUSTED, or ATTEMPT_ABORTED exists.

The pre-status event enum is exactly `INTENT_DURABLE`, `ATTEMPT_PREPARED`,
`CONTAINMENT_READY`, `SPAWN_ARMED`; the post-status enum is exactly
`STATUS_BOUND` through `ADOPTED` in table order; and the head enum is their
union plus `QUARANTINED`.  A pre-status event has null `run_paths`; a
post-status event has nonnull exact `run_paths`.  Each event and head has
nonnull exact `static_paths` and `revision_paths`, whose revision equals the
event/head revision.  A quarantined event's `terminal_from_state` is exactly
one of the first eleven pre-commit states and its family nullability equals the
field-map row in section 17.3.  `SPAWN_ARMED` quarantine requires the exact
uncertainty root; every other source state forbids it.  The semantic validator
enumerates all 14-by-14 ordered lifecycle-state pairs and rejects the complement
of the 12 adjacent edges (including COMMITTED-to-ADOPTED) plus the eleven
source-state-to-QUARANTINED edges.

### 17.7 Scenario, review, and schema-root replacements

The section-10 parsed array now has the five appended rows `LRC2-47..51`.
Independent strict parsing and canonical recomputation produce:

```text
schema registry rows                         25
ordered successor inputs                     39
scenario rows / harness methods              52
ordered scenario subcases                    767
scenario IDs                                 LRC2-00..LRC2-51
mixed-scenario ordinals                      [23,32,33,34,35,38,42,46,50,51]
last-ten subcase counts                      [39,36,32,34,79,68,16,18,20,28]
CJ(scenarios) size bytes                     84801
CJ(scenarios) SHA-256                        2eb301a01e60847b1ce096c04b4df086869b216219714be49a70b1b4352b19c5
CONCAT(CJ(row)||LF) size bytes               84800
CONCAT(CJ(row)||LF) SHA-256                  70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99
top-level harness validations                54
amendment / implementation / source checks   25 / 22 / 8
```

The first 42 rows contribute 397 subcases; rows 42..51 contribute 370.  Ranges
for ordinals and error precedence become `0..51` and `1..51`.  Scenario IDs use
`^LRC2-(?:0[0-9]|[1-4][0-9]|5[01])$`.  Ordinary non-mixed rejecting ordinals are
`[43,44,45,47,48,49]`; mixed rows are exactly the ten ordinals above.  The
eight-value outcome enum and its null/error-field rules are unchanged.
`scenario_manifest_root.scenarios` is the exact parsed 52-object constant with
explanatory `A(R(scenario),52,52,true)`.  `scenario_execution_root` requires
the unchanged exact 39 successor identities, `method_count:C(52)`, and 52
results with the exact 767-subcase nested cardinalities.  The harness performs
one schema check, one exact-root-constant check, and 52 methods: 54 validations.

The registry remains 25 schemas and the successor roster remains 39 paths
because all new `$defs` and discriminated roots are inside the existing
`program_facts_parity_vector_capture_transaction.v2` schema.  Its root union
must register every section-17.3 through 17.5 record.  A renderer that silently
drops a new root, retains the old generic path object, leaves a dangling `$ref`,
or accepts an old root under an open discriminator fails the root-constant
validation.

The ordered amendment roster appends:

```text
G3LRC-R21-IMMUTABLE-CONTAINMENT-POLICY-AND-TYPED-OBSERVATIONS
G3LRC-R22-DISJOINT-DERIVED-PATH-FAMILIES
G3LRC-R23-REGISTERED-PERSISTED-TRANSPORT-ROOTS
G3LRC-R24-HEADLESS-PRE-GENESIS-QUARANTINE
G3LRC-R25-SPAWN-UNCERTAINTY-CGROUP-TERMINATION
```

The ordered implementation roster appends:

```text
V2I-18-IMMUTABLE-CONTAINMENT-POLICY-AND-TYPED-OBSERVATIONS
V2I-19-DISJOINT-DERIVED-PATH-FAMILIES
V2I-20-REGISTERED-PERSISTED-TRANSPORT-ROOTS
V2I-21-HEADLESS-PRE-GENESIS-QUARANTINE
V2I-22-SPAWN-UNCERTAINTY-CGROUP-TERMINATION
```

`amendment_check` and `implementation_check` add exactly those enums;
`amendment_review_root.checks` becomes `A(R(amendment_check),25,25,true)` and
`implementation_review_root.checks` becomes
`A(R(implementation_check),22,22,true)`.  The source roster becomes eight by
appending `SRV-08-CONTAINMENT-SUPERVISOR-SOURCE`.  SRV-08 requires the exact
supervisor source, compiler/toolchain/build-plan lineage, binary identity,
independent review, no target/protocol imports, no network or host-write logic,
and the rule that it may only construct containment then wait for the gate.
For the runtime-builder subject this proves the named region and build join;
for every other source subject it proves that the subject is not named by the
supervisor binding and cannot supply or replace that region.  There is no N/A
or omitted check result.
R21/V2I-18 cover every policy preimage, exact byte
encoding, policy-set join, operation-private cgroup lifecycle, supervisor
binding, and typed pre/post native observation.  R22/V2I-19 cover every literal
path derivation, family disjointness, state-dependent nullability, and
cross-family substitution.  R23/V2I-20 cover union registration, persisted CF
bytes, exact three native frames, non-self-reference, and cross-operation
substitution.  R24/V2I-21 cover every headless root, ID preimage, source/
destination reconciliation, and the prohibition on invented event/head/
transaction identity.  R25/V2I-22 cover the arm-before-clone order, ambiguous
clone recovery, kill/stable-empty proof, null process identity, six-slot
zero/movable roster, private-tree move, and no replay.

The exact repair-to-fixture mapping is:

| Review blocker | Normative replacement | RED scenario | Review checks |
|---|---|---|---|
| immutable containment policy and native observation | sections 17.2, 18.1-18.2, and 19.1-19.5/19.9 policy semantics/materialization, operation-private cgroup, exact native ABI/FFI evidence, and success-root post-operation join | `LRC2-47` (68) | R21 / V2I-18 |
| conflated paths | section 17.1 four literal derived families and equality rules | `LRC2-48` (16) | R22 / V2I-19 |
| unregistered/framing-implicit roots | section 17.3 three registered roots and exact persisted/native bytes | `LRC2-49` (18) | R23 / V2I-20 |
| malformed pre-genesis intent invented lineage | sections 17.4 and 18.3 headless four-root family, destination metadata, and legacy/vector type boundary | `LRC2-50` (20) | R24 / V2I-21 |
| ambiguous process creation | sections 17.5-17.6, 18.3-18.5, and 19.6-19.7 arm, cgroup kill/empty, non-self-referential uncertainty observation, null PID, exact movable set, vector-only types, and total matrix | `LRC2-51` (28) | R25 / V2I-22 |

R3.2 preserves the marker-last rule, all retained-handle and native-metadata
requirements, Linux same-mount no-replace/barrier authority, Windows and macOS
ceilings, source/bootstrap/process joins, schema review independence, and all-
false `authority_v2`.  The marker-bounded `PARITY_V1_LOCAL_FRAGMENT` remains
22,213 bytes with SHA-256
`97844a817f292066ae73dc554f7f747148e4569648dd783da7fdf0eb72f6ad3d`
because section 17 is outside its markers.  No R3.2 passing value can render,
spawn, move, publish, adopt, bridge, admit, or cut over anything without future
fixture-first GREEN evidence and independent review.  Admission remains
`BLOCKED_PENDING_SEPARATELY_ACCEPTED_CROSSCHECK_V3_LINEAGE_BRIDGE`.

## 18. R3.3 semantic-review closure

This section is a normative replacement over section 17 only where stated.  It
closes the success-observation, containment-semantics, lifecycle-fixture,
quarantine-type, and Windows file-identity blockers found by the independent
R3.2 review.  It does not add an accepting OS, a retry, a discovery scan, a
renderer, an adoption path, or any authority.  The Linux lane remains the only
lane that can become accepting after later implementation evidence; Windows
remains process-crash-only nonauthority and macOS remains unavailable.

### 18.1 Exact containment semantics

The section-17 `vector_root_policy_row`, `vector_mount_policy_preimage`, and
`vector_landlock_policy_preimage` definitions are replaced by these closed
objects.  The three root positions are constants, not a minimum-cardinality
array or an implementer-selected allowlist:

```text
vector_system_runtime_root_policy =
O(ordinal:C(0),root_kind:C("SYSTEM_RUNTIME_READ_ONLY"),
  root:R(directory_locator),root_template:C(null),access:C("READ_EXECUTE"),
  recursive:C(true),no_device:C(true),no_suid:C(true),no_exec:C(false))

vector_input_snapshot_root_policy =
O(ordinal:C(1),root_kind:C("INPUT_SNAPSHOT_READ_ONLY"),
  root:R(directory_locator),root_template:C(null),access:C("READ_ONLY"),
  recursive:C(true),no_device:C(true),no_suid:C(true),no_exec:C(true))

vector_operation_private_root_policy =
O(ordinal:C(2),root_kind:C("OPERATION_PRIVATE_WRITABLE"),root:C(null),
  root_template:C("STATIC_OPERATION_PRIVATE_TREE"),access:C("READ_WRITE"),
  recursive:C(true),no_device:C(true),no_suid:C(true),no_exec:C(true))

vector_mount_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_MOUNT_POLICY_V2"),
  roots:T(R(vector_system_runtime_root_policy),
    R(vector_input_snapshot_root_policy),
    R(vector_operation_private_root_policy)),
  root_roster_sha256:HEX,private_mount_namespace:C(true),
  root_propagation:C("MS_PRIVATE_REC"),pivot_root:C("EMPTY_TMPFS_ROOT"),
  proc_mount:C("PRIVATE_HIDE_OTHER_PIDS"),
  dev_mount:C("MINIMAL_EMPTY_NO_DEVICE_NODES"),
  operation_private_single_writable:C(true))

vector_landlock_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_LANDLOCK_POLICY_V2"),
  required_minimum_abi:C(10),
  handled_access_fs:C(["EXECUTE","WRITE_FILE","READ_FILE","READ_DIR",
  "REMOVE_DIR","REMOVE_FILE","MAKE_CHAR","MAKE_DIR","MAKE_REG",
  "MAKE_SOCK","MAKE_FIFO","MAKE_BLOCK","MAKE_SYM","REFER","TRUNCATE",
  "IOCTL_DEV","RESOLVE_UNIX"]),
  handled_access_fs_u64_hex:C("000000000001ffff"),
  handled_access_net:C(["BIND_TCP","CONNECT_TCP","BIND_UDP",
  "CONNECT_SEND_UDP"]),handled_access_net_u64_hex:C("000000000000000f"),
  scoped:C(["ABSTRACT_UNIX_SOCKET","SIGNAL"]),
  scoped_u64_hex:C("0000000000000003"),quiet_access_fs_u64_hex:C("0000000000000000"),
  quiet_access_net_u64_hex:C("0000000000000000"),
  quiet_scoped_u64_hex:C("0000000000000000"),
  system_runtime_allowed_fs:C(["EXECUTE","READ_FILE","READ_DIR"]),
  system_runtime_allowed_fs_u64_hex:C("000000000000000d"),
  input_snapshot_allowed_fs:C(["READ_FILE","READ_DIR"]),
  input_snapshot_allowed_fs_u64_hex:C("000000000000000c"),
  operation_private_allowed_fs:C(["WRITE_FILE","READ_FILE","READ_DIR",
  "REMOVE_DIR","REMOVE_FILE","MAKE_DIR","MAKE_REG","REFER","TRUNCATE"]),
  operation_private_allowed_fs_u64_hex:C("00000000000061be"),
  allowed_network_rules:C([]),no_best_effort:C(true))
```

`root_roster_sha256 = SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_VECTOR_ROOT_ROSTER_V2",roots}))`.  The runtime row root is
the exact immutable runtime root from the host receipt; the input row root is
the exact immutable input-snapshot root; neither may name a descendant or an
alias.  The operation-private row is instantiated only as the exact static
family leaf.  Mountinfo must show those three and only those three accessible
roots below the empty pivot root, with `ro,nodev,nosuid` plus executable only
for the runtime root, `ro,nodev,nosuid,noexec` for the input root, and
`rw,nodev,nosuid,noexec` only for the operation-private root.  The output tree
therefore cannot be executable.  An extra readable root is as invalid as an
extra writable root.

The Landlock host probe must report ABI `>=10`; an older ABI fails before
containment creation.  The global masks above are exact: every named filesystem
and network action is handled and both scopes are enabled.  Each path-beneath
rule uses exactly the applicable per-root mask above.  There are no network
port rules and no quiet bits.  Unknown ABI rights, missing handled rights,
additional allowed rights, a missing scope, a best-effort subset, or a mask/list
disagreement rejects.  This deliberately chooses a narrower fail-closed host
floor instead of silently weakening policy for an older kernel.

The section-17 seccomp preimage is replaced by:

```text
vector_seccomp_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_SECCOMP_POLICY_V2"),
  architecture:E("AUDIT_ARCH_X86_64","AUDIT_ARCH_AARCH64"),
  default_action:C("SECCOMP_RET_KILL_PROCESS"),
  allowed_syscalls:C(["access","brk","clock_gettime",
  "clock_nanosleep","close","execve","execveat","exit","exit_group",
  "faccessat2","fcntl","fstat","futex","getdents64","getegid","geteuid",
  "getgid","getpid","getppid","getrandom","gettid","getuid","ioctl",
  "lseek","madvise","mmap","mprotect","mremap","munmap","nanosleep",
  "newfstatat","openat","pread64","prlimit64","read","readlink",
  "readlinkat","readv","rseq","rt_sigaction","rt_sigprocmask",
  "rt_sigreturn","sched_getaffinity","set_robust_list","set_tid_address",
  "sigaltstack","statx","sysinfo","uname","write","writev"]),
  architecture_specific_syscalls:U(
    O(architecture:C("AUDIT_ARCH_X86_64"),syscalls:C(["arch_prctl"])),
    O(architecture:C("AUDIT_ARCH_AARCH64"),syscalls:C([]))),
  uapi_mapping:R(file_identity),verifier_contract:R(file_identity),
  verifier_contract_review:R(file_identity),
  instructions:A(R(vector_seccomp_instruction),1,4096,true),
  semantic_proof_sha256:HEX)
```

The three file identities equal the exact independently reviewed runtime build
inputs; they are not caller-selected hashes.  The deterministic verifier parses
every classic-BPF instruction, rejects an invalid jump or an unreachable
instruction, and symbolically partitions the full unsigned 32-bit `arch` and
`nr` input domain.  It accepts iff: the first decision checks the exact selected
audit architecture; every other architecture reaches
`SECCOMP_RET_KILL_PROCESS`; on the selected architecture the return is
`SECCOMP_RET_ALLOW` iff `nr` is the UAPI mapping of exactly one name in the
constant list above; every other number reaches `SECCOMP_RET_KILL_PROCESS`;
and no path returns TRACE, TRAP, ERRNO, LOG, USER_NOTIF, or an action with
nonzero data.  `semantic_proof_sha256 = SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_VECTOR_SECCOMP_SEMANTIC_PROOF_V1",architecture,
allowed_syscalls,architecture_specific_syscalls,uapi_mapping,
verifier_contract,verifier_contract_review,
instructions,partition_result:"EXACT_ALLOW_IFF"}))`.  The materialized BPF
bytes remain the exact little-endian instruction concatenation from section
17.2.  Consequently an allow-all program, an architecture fall-through, or a
program merely sharing a digest field cannot pass.  The selected architecture
equals the architecture-specific row; the exact allow set is the union of the
common list and that row, so an AArch64 policy cannot smuggle the x86-only
`arch_prctl` number and an x86 policy cannot omit it.

The policy artifact definition is replaced in full:

```text
vector_policy_artifact =
O(policy_artifact_id:S(40,40,"^pfg3vpa-[0-9a-f]{32}$"),
  policy_kind:E("MOUNT","LANDLOCK","SECCOMP","NETWORK","CGROUP",
  "HANDLES","NAMESPACES"),
  artifact_filename:E("mount.policy.v2.json","landlock.policy.v2.json",
  "seccomp.x86_64.policy.v2.bpf","seccomp.aarch64.policy.v2.bpf",
  "network.policy.v1.json","cgroup.policy.v1.json","handles.policy.v1.json",
  "namespaces.policy.v1.json"),preimage:R(vector_policy_preimage),
  encoding:E("STRICT_CF_JSON_V1","CLASSIC_BPF_SOCK_FILTER_LE_V1"),
  materialized_bytes:R(content_identity),artifact:R(file_identity),
  preimage_sha256:HEX,materialization_sha256:HEX)
```

The filename is exactly MOUNT ->
`mount.policy.v2.json`, LANDLOCK -> `landlock.policy.v2.json`, the selected
SECCOMP architecture -> its one matching filename, and the remaining kinds ->
their same-named v1 filename.  No unused seccomp architecture artifact appears
in the seven-row set.  The artifact ID is
`"pfg3vpa-" || SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_VECTOR_POLICY_ARTIFACT_ID_V1",policy_kind,
artifact_filename,encoding,preimage_sha256,materialized_bytes,
materialization_sha256}))[0:32]`.  Artifact paths are exactly
`J(policy_root,artifact_filename)`.  `policy_set_id` and `policy_set_sha256`
retain the section-17 formulas but their ordered materialization rows now also
contain `policy_artifact_id` and `artifact_filename`.

The cgroup instance ID formula is no longer prose:

```text
instance_id = "pfg3vcg-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_CGROUP_INSTANCE_ID_V1",
  capture_operation_id,policy_set_id,
  delegated_root_inode:{volume_id:delegated_root.volume_id,
                        file_id:delegated_root.file_id},
  relative_path:"plamen-vector/" || capture_operation_id
}))[0:32]
```

The configuration observation is part of that instance only after recomputing
the formula and exact policy values; it cannot feed `instance_id`.  Every later
cgroup observation repeats that ID and the same directory inode.

### 18.2 Persisted typed native evidence and the ordinary success root

The section-17 `vector_native_call` is replaced, and every native observation
is wrapped, by these definitions:

```text
vector_exact_native_bytes =
O(bytes_hex:S(0,33554432,"^(?:[0-9a-f]{2})*$"),
  size_bytes:I(0,16777216),sha256:HEX)

vector_native_argument_projection =
O(api:E("mkdirat","openat","read","write","pread64","readlinkat",
  "fstat","statx","mount","umount2","pivot_root","prctl","seccomp",
  "landlock_get_abi","landlock_create_ruleset","landlock_add_rule","landlock_restrict_self",
  "close_range","clone3","pidfd_send_signal","poll","unlinkat"),
  abi:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  argument_names:A(S1,0,8,false),argument_kinds:A(E("S64","U64","FD_ROLE",
  "FLAGS_U64","MODE_U32","SIZE_U64","STRUCT","INPUT_BYTES"),0,8,false),
  normalized_values:A(S1,0,8,false),struct_members:A(S1,0,128,false))

vector_native_result_projection =
O(return_kind:E("S64","FD","BYTE_COUNT","STRUCT","NO_RETURN"),
  signed_result:I(-4095,9007199254740991),errno:I(0,4095),
  output_kind:E("NONE","BYTES","STRUCT"),normalized_members:A(S1,0,128,false))

vector_native_call =
O(ordinal:I(0,4095),call_id:S(40,40,"^pfg3vnc-[0-9a-f]{32}$"),
  arguments_bytes:R(vector_exact_native_bytes),
  arguments:R(vector_native_argument_projection),
  result_bytes:R(vector_exact_native_bytes),result:R(vector_native_result_projection),
  call_sha256:HEX)

vector_native_observation_record =
O(observation_id:S(40,40,"^pfg3vno-[0-9a-f]{32}$"),
  observation:R(vector_native_observation),persisted_bytes:R(vector_exact_native_bytes),
  observation_sha256:HEX)
```

For each API, `argument_names`, `argument_kinds`, count, order, and ABI are the
exact reviewed C prototype projection in the pinned supervisor contract.
`arguments_bytes` is the byte-for-byte little-endian scalar/struct input copied
at the call boundary, including explicit padding zeroes; `result_bytes` is the
byte-for-byte signed return plus every initialized output byte, with no
uninitialized padding.  The normalized projection is independently decoded
from those bytes and compared to the policy/root/cgroup object used by the
semantic validator.  `errno` is zero for nonnegative results and equals the
captured positive errno for a `-1` result.  A digest without bytes, bytes without
a typed projection, an opaque API name, reordered arguments, host-endian
ambiguity, padding drift, or a projection not exactly decoding the bytes
rejects.

The API signature roster is the following exact 22-row constant.  Names and
kinds are ordered; `-` means the exact empty array.  The result column fixes
`return_kind/output_kind`:

| API | argument names | argument kinds | result |
|---|---|---|---|
| `mkdirat` | `dirfd,path,mode` | `FD_ROLE,INPUT_BYTES,MODE_U32` | `S64/NONE` |
| `openat` | `dirfd,path,flags,mode` | `FD_ROLE,INPUT_BYTES,FLAGS_U64,MODE_U32` | `FD/NONE` |
| `read` | `fd,count` | `FD_ROLE,SIZE_U64` | `BYTE_COUNT/BYTES` |
| `write` | `fd,input,count` | `FD_ROLE,INPUT_BYTES,SIZE_U64` | `BYTE_COUNT/NONE` |
| `pread64` | `fd,count,offset` | `FD_ROLE,SIZE_U64,S64` | `BYTE_COUNT/BYTES` |
| `readlinkat` | `dirfd,path,count` | `FD_ROLE,INPUT_BYTES,SIZE_U64` | `BYTE_COUNT/BYTES` |
| `fstat` | `fd` | `FD_ROLE` | `S64/STRUCT` |
| `statx` | `dirfd,path,flags,mask` | `FD_ROLE,INPUT_BYTES,FLAGS_U64,FLAGS_U64` | `S64/STRUCT` |
| `mount` | `source,target,fstype,flags,data` | `INPUT_BYTES,INPUT_BYTES,INPUT_BYTES,FLAGS_U64,INPUT_BYTES` | `S64/NONE` |
| `umount2` | `target,flags` | `INPUT_BYTES,FLAGS_U64` | `S64/NONE` |
| `pivot_root` | `new_root,put_old` | `INPUT_BYTES,INPUT_BYTES` | `S64/NONE` |
| `prctl` | `option,arg2,arg3,arg4,arg5` | `U64,U64,U64,U64,U64` | `S64/NONE` |
| `seccomp` | `operation,flags,sock_fprog` | `U64,FLAGS_U64,STRUCT` | `S64/NONE` |
| `landlock_get_abi` | `flags` | `FLAGS_U64` | `S64/NONE` |
| `landlock_create_ruleset` | `attr,size,flags` | `STRUCT,SIZE_U64,FLAGS_U64` | `FD/NONE` |
| `landlock_add_rule` | `ruleset_fd,rule_type,rule_attr,flags` | `FD_ROLE,U64,STRUCT,FLAGS_U64` | `S64/NONE` |
| `landlock_restrict_self` | `ruleset_fd,flags` | `FD_ROLE,FLAGS_U64` | `S64/NONE` |
| `close_range` | `first,last,flags` | `U64,U64,FLAGS_U64` | `S64/NONE` |
| `clone3` | `clone_args,size` | `STRUCT,SIZE_U64` | `S64/STRUCT` |
| `pidfd_send_signal` | `pidfd,signal,siginfo,flags` | `FD_ROLE,S64,STRUCT,FLAGS_U64` | `S64/NONE` |
| `poll` | `pollfds,timeout` | `STRUCT,S64` | `S64/STRUCT` |
| `unlinkat` | `dirfd,path,flags` | `FD_ROLE,INPUT_BYTES,FLAGS_U64` | `S64/NONE` |

The row stream digest is
`SHA-256(CONCAT(CJ(row)||LF))` in table order and is joined by SRV-08 to the
reviewed supervisor source.  The projection arrays must equal their row
exactly; no optional argument, variadic tail, API alias, or alternative return
shape exists.  Each `STRUCT` member roster is the exact named Linux UAPI struct
for the selected LP64 little-endian ABI, with its size, offsets, zero padding,
and UAPI file identity carried by the pinned call-projection table.

The exact formulas are:

```text
call_sha256 = SHA-256(CJ({domain:"PROGRAM_FACTS_G3_VECTOR_NATIVE_CALL_V2",
  ordinal,arguments_bytes,arguments,result_bytes,result}))
call_id = "pfg3vnc-" || call_sha256[0:32]
observation_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_NATIVE_OBSERVATION_V2",observation}))
observation_id = "pfg3vno-" || observation_sha256[0:32]
persisted_bytes = EXACT_BYTES(CF({observation_id,observation,
  observation_sha256}))
observation_set_sha256 = SHA-256(CONCAT(
  CJ(native_observations[i]) || LF for i in ordinal order))
post_operation_id = "pfg3vpo-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_POST_OPERATION_ID_V2",policy_set,
  cgroup,native_execution_authority,native_execution_receipt,
  actual_process,native_observations,cgroup_final_state,
  operation_private_tree_writers,inherited_child_handles_open,
  out_of_scope_write_count,network_packet_count,descendant_process_count
}))[0:32]
```

`EXACT_BYTES(x)` means `{bytes_hex:LOWER_HEX(x),size_bytes:len(x),
sha256:SHA-256(x)}`.  The instance and post-operation definitions are replaced
in full:

```text
vector_cgroup_instance =
O(instance_id:S(40,40,"^pfg3vcg-[0-9a-f]{32}$"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  policy_set_id:S(40,40,"^pfg3vps-[0-9a-f]{32}$"),
  delegated_root:R(directory_locator),relative_path:R(quarantine_relative_path),
  directory_inode:R(directory_inode_identity),creation:C("MKDIRAT_EXCLUSIVE"),
  precreate_absent:C(true),initial_procs:C([]),pids_max_written:C("1"),
  pids_max_reread:C("1"),memory_max_written:I(67108864,8589934592),
  memory_max_reread:I(67108864,8589934592),cpu_max_written:S1,
  cpu_max_reread:S1,kill_supported:C(true),reuse:C("FORBIDDEN"),
  configuration_observation:R(vector_native_observation_record),
  state:C("CONFIGURED_EMPTY"))

vector_confirmed_post_operation_instance =
O(instance_kind:C("CONFIRMED_PROCESS"),
  post_operation_id:S(40,40,"^pfg3vpo-[0-9a-f]{32}$"),
  policy_set:R(vector_containment_policy_set),cgroup:R(vector_cgroup_instance),
  actual_process:R(vector_actual_process_identity),
  native_execution_authority:R(vector_native_ffi_authority_r3_6),
  native_execution_receipt:R(vector_native_execution_receipt_r3_6),
  native_observations:A(R(vector_native_observation_record),13,10000,true),
  cgroup_final_state:E("EMPTY_RETAINED_FOR_QUARANTINE",
  "EMPTY_REMOVED_AFTER_COMMIT"),operation_private_tree_writers:C(0),
  inherited_child_handles_open:C(0),out_of_scope_write_count:C(0),
  network_packet_count:C(0),descendant_process_count:C(0),
  observation_set_sha256:HEX)

vector_uncertain_post_operation_instance =
O(instance_kind:C("SPAWN_UNCERTAIN"),
  post_operation_id:S(40,40,"^pfg3vpo-[0-9a-f]{32}$"),
  policy_set:R(vector_containment_policy_set),cgroup:R(vector_cgroup_instance),
  native_execution_authority:R(vector_native_ffi_authority_r3_6),
  native_execution_receipt:R(vector_native_execution_receipt_r3_6),
  actual_process:C(null),trusted_supervisor_only_possible:C(true),
  authorization_gate_released:C(false),run_paths:C(null),
  atomic_clone_namespace_request:C(["CGROUP","IPC","NETWORK","MOUNT","PID",
  "USER","UTS"]),native_observations:A(R(vector_native_observation_record),3,3,true),
  cgroup_final_state:C("EMPTY_RETAINED_FOR_QUARANTINE"),
  operation_private_tree_writers:C(0),inherited_child_handles_open:C(0),
  out_of_scope_write_count:C(0),network_packet_count:C(0),
  descendant_process_count:C(0),observation_set_sha256:HEX)

vector_no_spawn_post_operation_instance =
O(instance_kind:C("NO_SPAWN"),
  post_operation_id:S(40,40,"^pfg3vpo-[0-9a-f]{32}$"),
  policy_set:R(vector_containment_policy_set),cgroup:R(vector_cgroup_instance),
  native_execution_authority:R(vector_native_ffi_authority_r3_6),
  native_execution_receipt:R(vector_native_execution_receipt_r3_6),
  actual_process:C(null),authorization_gate_released:C(false),run_paths:C(null),
  native_observations:A(R(vector_native_observation_record),1,2,true),
  cgroup_final_state:E("EMPTY_RETAINED_FOR_QUARANTINE",
  "EMPTY_REMOVED_BEFORE_SPAWN"),operation_private_tree_writers:C(0),
  inherited_child_handles_open:C(0),out_of_scope_write_count:C(0),
  network_packet_count:C(0),descendant_process_count:C(0),
  observation_set_sha256:HEX)

vector_post_operation_instance =
U(R(vector_confirmed_post_operation_instance),
  R(vector_uncertain_post_operation_instance),
  R(vector_no_spawn_post_operation_instance))
```

The cgroup configuration wrapper's inner branch is the exact
`CONFIGURED_EMPTY` observation.  Required post-operation branch counts and
order remain those in section 17.2.  Every roster digest (mount roots, handles,
Landlock rules, seccomp instructions, namespace observations, and cgroup
stages) is SHA-256 of `CONCAT(CJ(row)||LF)` in its declared ordinal order;
cardinality and unique contiguous ordinals are separately checked.  No digest
or observation ID can stand in for the rows it commits to.

The ordinary success root is replaced in full by:

```text
vector_capture_observation_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("OBSERVATION"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),capture_run_id:S(40,40,
  "^pfg3vcr-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),run_paths:R(vector_capture_run_paths),
  serialization_lease:R(kernel_serialization_lease),
  containment_instance:R(artifact_ref),
  containment:R(vector_containment_instance_root),
  bootstrap_binding:R(vector_capture_bootstrap_binding),
  source_binding:R(vector_capture_source_binding),
  control_record:R(artifact_ref),control:R(vector_capture_control_record_root),
  status_record:R(artifact_ref),status:R(vector_capture_status_record_root),
  authorization_record:R(artifact_ref),
  authorization:R(vector_capture_authorization_record_root),
  compiled_code:R(vector_compiled_code_identity),
  code_object_projection_sha256:HEX,
  actual_process_identity:R(vector_actual_process_identity),
  post_operation:R(vector_confirmed_post_operation_instance),
  source_to_process_join_sha256:HEX,stdout_spool:R(artifact_ref),
  stderr_spool:R(artifact_ref),stdout_frame:R(content_identity),
  stderr:C({"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size_bytes":0}),
  exit_code:C(0),process_tree_zero:C(true),native_observation_complete:C(true),
  state:C("CHILD_OBSERVED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_OBSERVATION_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_TRANSACTION_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

The containment artifact reference identifies the embedded containment root.
Its operation/static paths/intent equal the observation's; its policy set is
parsed-value equal to `post_operation.policy_set`; and its cgroup is
parsed-value equal to `post_operation.cgroup`.  The observation's actual
process is parsed-value equal to both `post_operation.actual_process` and
`status.parent_actual_process`; that process's containment plan equals the
intent/control execution-plan containment plan.  Control, status, and
authorization refs identify their embedded roots and form the exact
control->status->authorization chain for this operation/run.  Every required
typed native record is embedded in `post_operation`, persisted before the
observation root, and joined to its policy artifact, cgroup instance, or actual
process.  A sidecar alone supplies no field and no authority.

The rendered `$defs` graph has no reachable definition or reference named
`vector_containment_observation`.  The only accepted success evidence is the
in-body `post_operation:R(vector_confirmed_post_operation_instance)` above.
The old opaque object, a missing post-operation value, a correct policy with a
different cgroup, a correct cgroup with a different process, or typed evidence
available only beside the root rejects before `CHILD_OBSERVED` publication.

### 18.3 Vector-only quarantine types and pre-genesis metadata

The shared `quarantine_entry_ref`, `quarantine_move`, and
`native_metadata_capture_observation` definitions remain byte-for-byte the
legacy three-branch types from section 16.1.  Section 17.5's attempted
redefinition of `quarantine_entry_ref` is deleted from the effective `$defs`.
Only vector roots may use these additional types:

```text
quarantine_entry_ref =
U(O(entry_kind:C("REGULAR_ARTIFACT"),artifact:R(artifact_ref)),
  O(entry_kind:C("WRITABLE_PROFILE_TREE"),writable_kind:E("PROFILE_ROOT",
    "LOCALAPPDATA","TEMP","TMP"),path:R(quarantine_source_path),
    tree_identity:R(quarantine_tree_identity)),
  O(entry_kind:C("NONREGULAR_CONFLICT"),path:R(quarantine_source_path),
    path_identity:R(quarantine_nonregular_identity)))

vector_quarantine_entry_ref =
U(R(quarantine_entry_ref),R(vector_operation_private_tree_entry))

vector_native_metadata_capture_observation =
O(profile:R(native_metadata_capture_profile),
  before_identity:R(vector_quarantine_entry_ref),
  after_identity:R(vector_quarantine_entry_ref),identity_unchanged:C(true),
  enumeration_complete:C(true),api_error_count:C(0))

vector_quarantine_move =
O(move_ordinal:I(0,19999),source:R(vector_quarantine_entry_ref),
  source_metadata_observation:R(vector_native_metadata_capture_observation),
  source_parent:R(directory_locator),source_relative_path:R(quarantine_relative_path),
  destination_parent:R(directory_locator),
  destination_relative_path:R(quarantine_relative_path),
  identity_branch:E("REGULAR_FILE","DIRECTORY_TREE","NONREGULAR"),
  source_mount_id:S1,destination_mount_id:S1,
  source_st_dev:S1,destination_st_dev:S1,
  primitive:C("LINUX_RENAMEAT2_NOREPLACE_DIRFD_V1"))

vector_destination_absence_observation =
O(parent:R(directory_locator),relative_path:R(quarantine_relative_path),
  nofollow_open_result:C("ENOENT"),native_call:R(vector_native_call_r3_6),
  observed_before_rename:C(true))

vector_destination_postmove_observation =
O(parent:R(directory_locator),relative_path:R(quarantine_relative_path),
  destination_entry:R(vector_quarantine_entry_ref),
  metadata:R(vector_native_metadata_capture_observation),
  native_call:R(vector_native_call_r3_6),observed_after_rename:C(true))

vector_uncertain_artifact_entry =
U(O(kind:C("ABSENT"),slot:E("CONTROL_RECORD","STATUS_RECORD",
    "AUTHORIZATION_RECORD","STDOUT_SPOOL","STDERR_SPOOL",
    "OPERATION_PRIVATE_TREE")),
  O(kind:C("FIXED_ENTRY"),slot:E("CONTROL_RECORD","STATUS_RECORD",
    "AUTHORIZATION_RECORD","STDOUT_SPOOL","STDERR_SPOOL"),
    source:R(quarantine_entry_ref),planned_move:R(quarantine_move)),
  O(kind:C("PRIVATE_TREE"),slot:C("OPERATION_PRIVATE_TREE"),
    source:R(vector_operation_private_tree_entry),
    planned_move:R(vector_quarantine_move)))

vector_spawn_uncertainty_observation =
O(classification:C("SPAWN_MAY_HAVE_OCCURRED"),
  capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),
  spawn_arm:R(artifact_ref),containment_instance:R(artifact_ref),
  actual_process:C(null),pid:C(null),process_start_identity:C(null),
  pidfd_identity:C(null),clone_result:C("UNOBSERVABLE_AFTER_CRASH"),
  kill_requested:R(vector_native_observation_record),
  empty_first:R(vector_native_observation_record),
  empty_second:R(vector_native_observation_record),
  poll_barrier_between:C(true),child_handles_open:C(0),
  operation_private_tree_writers:C(0),journaled_status_current:C(false),
  journaled_authorization_current:C(false),run_paths:C(null),
  replay_allowed:C(false),
  post_operation:R(vector_uncertain_post_operation_instance),
  observation_sha256:HEX)

vector_capture_quarantine_prepared_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_PREPARED"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),error_code:S1,
  source_event:R(artifact_ref),static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  run_paths:Q(R(vector_capture_run_paths)),
  serialization_lease:R(kernel_serialization_lease),
  process_basis:R(vector_quarantine_process_basis),
  conflicting_entries:A(R(vector_quarantine_entry_ref),0,32,true),
  planned_moves:A(R(vector_quarantine_move),0,32,true),state:C("PREPARED"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINE_INTENT_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_capture_quarantine_progress_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("QUARANTINE_PROGRESS"),capture_quarantine_id:S(40,40,
  "^pfg3vcq-[0-9a-f]{32}$"),capture_operation_id:S(40,40,
  "^pfg3vop-[0-9a-f]{32}$"),attempt_ordinal:C(0),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  revision_paths:R(vector_capture_revision_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  run_paths:Q(R(vector_capture_run_paths)),
  serialization_lease:R(kernel_serialization_lease),move_ordinal:I(0,31),
  planned_move:R(vector_quarantine_move),
  reconciled_from:E("SOURCE_IDENTITY","DESTINATION_IDENTITY"),
  destination_entry:R(vector_quarantine_entry_ref),
  destination_metadata_before:R(vector_destination_absence_observation),
  destination_metadata_after:R(vector_destination_postmove_observation),
  source_identity_state:E("ABSENT_AFTER_DURABLE_MOVE",
  "DISTINCT_CURRENT_SOURCE_ENTRY"),
  distinct_source_entry:Q(R(vector_quarantine_entry_ref)),
  destination_current:C(true),durability_barriers_complete:C(true),
  state:C("MOVE_DURABLE"),
  disposition:C("PRIVATE_VECTOR_CAPTURE_QUARANTINE_PROGRESS_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

Every ordinary vector quarantine conflicting-entry array, planned-move array,
and progress destination uses the vector-specific types.  Non-vector
transaction and coordination quarantine roots continue to accept only the
legacy types.  A vector operation-private tree can therefore never leak into a
legacy root or expand a global union.

The process-basis union is also narrowed rather than referring to the generic
post-operation union:

```text
vector_quarantine_process_basis =
U(O(kind:C("PRE_CONTAINMENT"),actual_process:C(null),post_operation:C(null),
    spawn_uncertainty:C(null)),
  O(kind:C("CONTAINMENT_NO_SPAWN"),actual_process:C(null),
    post_operation:R(vector_no_spawn_post_operation_instance),
    spawn_uncertainty:C(null)),
  O(kind:C("CONFIRMED_PROCESS"),actual_process:R(vector_actual_process_identity),
    post_operation:R(vector_confirmed_post_operation_instance),
    spawn_uncertainty:C(null)),
  O(kind:C("SPAWN_UNCERTAIN"),actual_process:C(null),
    post_operation:R(vector_uncertain_post_operation_instance),
    spawn_uncertainty:R(vector_spawn_uncertainty_observation)))
```

The uncertainty observation's `post_operation` is likewise exactly
`R(vector_uncertain_post_operation_instance)`, and is parsed-value equal to the
process-basis member.  This prevents a schema-valid wrong union branch from
supplying success, no-spawn, or uncertain cleanup evidence.

The vector ordinary progress root is replaced so that `planned_move` is a
`vector_quarantine_move`, `destination_entry` is a
`vector_quarantine_entry_ref`, and it includes
`destination_metadata_before:R(vector_destination_absence_observation)` and
`destination_metadata_after:R(vector_destination_postmove_observation)`.
Both fields equal the planned destination parent/path; the after entry equals
both the planned source's pathless identity branch and `destination_entry`.

The pre-genesis family retains legacy entry/move types because the malformed
fixed intent is a regular legacy artifact, and is replaced in full:

```text
vector_pre_genesis_quarantine_prepared_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("PRE_GENESIS_QUARANTINE_PREPARED"),
  capture_quarantine_id:S(41,41,"^pfg3vpgq-[0-9a-f]{32}$"),
  expected_capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  attempt_ordinal:C(0),event:C(null),head:C(null),transaction_id:C(null),
  static_paths:R(vector_capture_static_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  serialization_lease:R(kernel_serialization_lease),
  malformed_intent_entry:R(quarantine_entry_ref),
  error_code:C("PRE_GENESIS_INTENT_MALFORMED"),
  planned_moves:A(R(quarantine_move),1,1,true),state:C("PREPARED"),
  disposition:C("PRIVATE_VECTOR_PRE_GENESIS_QUARANTINE_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_pre_genesis_quarantine_progress_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("PRE_GENESIS_QUARANTINE_PROGRESS"),
  capture_quarantine_id:S(41,41,"^pfg3vpgq-[0-9a-f]{32}$"),
  expected_capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  event:C(null),head:C(null),transaction_id:C(null),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  serialization_lease:R(kernel_serialization_lease),
  malformed_intent_entry:R(quarantine_entry_ref),move_ordinal:C(0),
  planned_move:R(quarantine_move),
  reconciled_from:E("SOURCE_IDENTITY","DESTINATION_IDENTITY"),
  destination_entry:R(quarantine_entry_ref),source_absent:C(true),
  destination_metadata_before:R(vector_destination_absence_observation),
  destination_metadata_after:R(vector_destination_postmove_observation),
  durability_barriers_complete:C(true),state:C("MOVE_DURABLE"),
  disposition:C("PRIVATE_VECTOR_PRE_GENESIS_QUARANTINE_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_pre_genesis_quarantine_complete_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("PRE_GENESIS_QUARANTINE_COMPLETE"),
  capture_quarantine_id:S(41,41,"^pfg3vpgq-[0-9a-f]{32}$"),
  expected_capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  event:C(null),head:C(null),transaction_id:C(null),intent:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  serialization_lease:R(kernel_serialization_lease),
  malformed_intent_entry:R(quarantine_entry_ref),
  move_progress:A(R(artifact_ref),1,1,true),state:C("COMPLETE"),
  disposition:C("PRIVATE_VECTOR_PRE_GENESIS_QUARANTINE_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)

vector_pre_genesis_quarantine_terminal_root =
O(schema_version:C("plamen.program_facts_parity_vector_capture_transaction.v2"),
  record_kind:C("PRE_GENESIS_QUARANTINE_TERMINAL"),
  capture_quarantine_id:S(41,41,"^pfg3vpgq-[0-9a-f]{32}$"),
  expected_capture_operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$"),
  event:C(null),head:C(null),transaction_id:C(null),complete:R(artifact_ref),
  static_paths:R(vector_capture_static_paths),
  quarantine_paths:R(vector_capture_quarantine_paths),
  serialization_lease:R(kernel_serialization_lease),
  malformed_intent_entry:R(quarantine_entry_ref),
  state:C("PRE_GENESIS_QUARANTINED"),retry_allowed:C(false),
  disposition:C("PRIVATE_VECTOR_PRE_GENESIS_TERMINAL_ONLY"),
  accepted_scope:C(["VECTOR_CAPTURE_QUARANTINE_ONLY"]),
  authority_ceiling:R(authority_v2),capture_body_sha256:HEX)
```

For this root the destination before/after wrappers are semantically restricted
to their legacy regular-artifact branch.  Their parent/path equal the sole
prepared move, after identity equals the prepared malformed-intent pathless
identity, and both native calls are under the same serialization lease.  The
progress record repeats `malformed_intent_entry:R(quarantine_entry_ref)`; it is
parsed-value equal to the prepared root and to the after destination identity.
The COMPLETE root repeats `malformed_intent_entry` and the sole progress ref;
the terminal joins that COMPLETE.  Cross-family entry tags, a move referring to
another prepared root, changed security/xattr/ACL/EA/ADS/reparse metadata, a
different destination between before and after, or an after identity that only
matches content rejects.

All four pre-genesis roots use the same operation
OFD lease in prepared, progress, COMPLETE, and terminal, remains held across
the before observation, no-replace move, after observation, both directory
barriers, and record publication, and is released only after the terminal is
durable.  A path-only lock, a different lease artifact, or early release is a
cross-root mismatch.

### 18.4 Windows `FILE_ID_INFO` canonical identity

The Windows host-profile branch replaces every generic Windows `volume_id` and
`file_id` occurrence in `handle_identity`, `inode_content_identity`,
`file_locator`, `directory_locator`, `directory_inode_identity`, native-image
identity, snapshot physical-member identity, and quarantine identity with this
projection:

```text
windows_file_id_info =
O(api:C("GetFileInformationByHandleEx(FILE_ID_INFO)"),
  raw_struct_bytes_hex:S(48,48,"^[0-9a-f]{48}$"),
  volume_serial_number_hex:S(16,16,"^[0-9a-f]{16}$"),
  file_id_128_hex:S(32,32,"^[0-9a-f]{32}$"))
```

`FILE_ID_INFO` is exactly 24 initialized bytes: the first eight are the native
little-endian unsigned `ULONGLONG VolumeSerialNumber`, followed by the sixteen
`FILE_ID_128.Identifier` bytes in API-returned order.  The volume string is the
unsigned numeric value rendered most-significant hexadecimal digit first,
lowercase, and zero-padded to exactly 16 characters.  The file-ID string is the
16 identifier bytes rendered in returned order as exactly two lowercase hex
digits per byte.  For Windows objects the generic `volume_id` equals exactly
`volume_serial_number_hex` and `file_id` equals exactly `file_id_128_hex`;
there is no prefix, decimal form, JSON number, signed interpretation, GUID byte
reordering, host integer cast, alternate-width form, or case variant.

The raw bytes are independently parsed twice using unsigned integer/byte-array
operations and must produce the same projection.  Values `0000000000000000`,
`7fffffffffffffff`, `8000000000000000`, and `ffffffffffffffff`, and file IDs
with first bytes `00`, `7f`, `80`, and `ff`, are mandatory boundary fixtures.
Fixtures also round-trip through canonical JSON and prove that binary64 or
signed conversions, truncation, nibble loss, uppercase, added sign, odd width,
leading-zero loss, reversal, and 64-bit truncation of `FILE_ID_128` reject.

### 18.5 Lifecycle and scenario correction

The effective lifecycle has the exact section-17.6 13-state/17-slot ordinary
matrix plus the separate terminal `QUARANTINED` state.  The legal relation is
exactly the 12 adjacent edges in displayed order plus the 11 edges from each
pre-commit state through `COMPLETION_STAGED` to `QUARANTINED`.  The validator
enumerates all 196 ordered pairs in the 14-state universe and rejects the other
173.  Artifact validation enumerates every one of the 13 x 17 ordinary
state/slot positions, plus run-path nullability; it does not
summarize a row by a digest.  In particular, `CONTAINMENT_READY` requires the
containment instance current and spawn arm absent, while `SPAWN_ARMED` requires
both current.  Substituting either slot with the other artifact, an old opaque
containment object, or an artifact from another operation rejects.

`LRC2-46` is replaced by fixtures for all 12 adjacent edges, all 11 quarantine
edges, the full 173-pair complement, all 13 exact 17-slot rows, and explicit
containment-instance/spawn-arm substitution.  `LRC2-47` adds the exact-root,
Landlock, seccomp-verifier, policy filename/ID, native-byte/projection,
post-operation success-root, and side-object substitutions in sections
18.1-18.2.  `LRC2-50` adds cross-root and destination-metadata substitutions.
`LRC2-51` uses nonnull precedence/code fields for its final quarantine outcome
and adds vector-only/legacy-type substitution.  `LRC2-17` adds the Windows
width, sign, high-bit, ordering, and rounding substitutions.  Section 10's
canonical parsed array and every denominator/digest declaration are replaced
by the recomputed values below; no prose-only fixture counts.

```text
scenario rows / harness methods              52 / 52
ordered scenario subcases                    767
first-42 / last-10 subcases                  397 / 370
last-ten subcase counts                      [39,36,32,34,79,68,16,18,20,28]
CJ(scenarios) size bytes                     84801
CJ(scenarios) SHA-256                        2eb301a01e60847b1ce096c04b4df086869b216219714be49a70b1b4352b19c5
CONCAT(CJ(row)||LF) size bytes               84800
CONCAT(CJ(row)||LF) SHA-256                  70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99
top-level harness validations                54
amendment / implementation / source checks   25 / 22 / 8
schema registry / ordered successor inputs   25 / 39
```

The R21/V2I-18 review pair covers all section-18.1/18.2 replacements, including
the exact success-root reachability graph.  R24/V2I-21 additionally covers the
pre-genesis metadata joins and legacy/vector type boundary.  R25/V2I-22 covers
the corrected state relation, vector-only quarantine types, and nonnull final
quarantine error.  R03/V2I-05 and the independently authored native-host
validator review additionally cover the Windows `FILE_ID_INFO` byte/projection
contract.  SRV-08 covers the seccomp verifier,
UAPI mapping, ABI call projection table, and exact native-call capture source.
No check may cite its own generated output as evidence.

All new definitions remain inside the registered
`program_facts_parity_vector_capture_transaction.v2` schema and do not add a
successor input.  Reference closure must start at the 20 registered transaction
root branches, resolve the section-18 replacements, prove that
`vector_containment_observation` is unreachable, prove that legacy quarantine
roots cannot reach any `vector_*quarantine*` extension, and reject every
unresolved or multiply effective definition.  The operation-ID, policy-set-ID,
cgroup-instance-ID, call-ID, observation-ID, and post-operation-ID dependency
graph must be acyclic under the displayed preimages.  State totality is checked
against the literal 13 x 17 matrix and 169-pair relation, not inferred from
fixture labels.

Part-0 remains clean: root kinds, syscall capabilities, containment evidence,
quarantine types, metadata fields, and Windows identities are generic runtime
mechanics.  No protocol, repository, ecosystem bug answer, target path, or
finding hint is encoded.  These replacements strengthen how an already
selected vector capture is evidenced; they do not choose what security finding
an audit should discover.

R3.3 preserves every R3.2 ordering, disjoint path family, registered transport
root, headless lineage, cgroup kill/empty, zero-artifact, marker-last,
same-mount/barrier, no-scan, no-backfill, no-retry, Part-0, OS-ceiling, and
non-enabling bridge rule except the explicit replacements above.  Nothing in
this section authorizes implementation, fixture publication, spawn, adoption,
cutover, or admission.  Admission remains
`BLOCKED_PENDING_SEPARATELY_ACCEPTED_CROSSCHECK_V3_LINEAGE_BRIDGE`.

## 19. R3.5 native-roster, policy-materialization, and lifecycle closure

This section is the non-lineage R3.5 normative replacement for the R3.4 stable
draft and for the R3.3 expressions named below.  The R3.4 bytes are review
history only and confer no lineage.  This R3.5 replacement does not alter any
other nonconflicting R3.3 repair.  The prose API table in
section 18.2 is review history only: it is not an input to an implementation,
generator, renderer, or validator.  The closed constants and formulas in this
section are the sole effective native-call roster.  Likewise, the section-18.1
Landlock object is replaced in full, the uncertainty digest is completed, and
the lifecycle domain is made explicit.  No accepting OS, authority bit,
successor path, retry, scan, or audit methodology is added.

### 19.1 Exact native encoding and named layouts

Both accepted Linux ABIs use two's-complement LP64, eight-bit bytes, and little
endian scalar encoding.  `u8/s8`, `u16/s16`, `u32/s32`, and `u64/s64/pointer`
have widths 1, 2, 4, and 8 respectively.  A scalar has exactly its declared
width; it is never widened to a host language integer.  Every pointer field is
the exact eight-byte unsigned address observed at the call boundary and is
followed by its separately framed pointee region.  A null pointer has numeric
value zero and no region.  A nonnull pointer without its required region, a
region without its pointer, an inferred string length, or an overlapping region
rejects.

The exact returned-call request frame is versioned and byte closed:

```text
"PFG3NAR5" || u16le(5) || u16le(profile_code) ||
u16le(api_ordinal) || u16le(argument_count) ||
CONCAT(for each argument in increasing roster ordinal:
  u16le(argument_ordinal) || u8(direction_code) || u8(value_kind_code) ||
  u32le(value_byte_length) || value_bytes || u16le(region_count) ||
  CONCAT(for each region in increasing region_ordinal:
    u16le(region_ordinal) || u16le(recursion_depth) ||
    u16le(parent_argument_ordinal) || u16le(parent_region_ordinal_or_ffff) ||
    u32le(parent_struct_field_offset) || u8(region_direction_code) ||
    u8(initialization_code) || u16le(region_kind_code) ||
    u32le(layout_ordinal_or_ffffffff) || u64le(declared_capacity) ||
    u64le(input_initialized_length) || u64le(payload_length) || payload_bytes))
```

The exact returned-call result frame is:

```text
"PFG3NRE5" || u16le(5) || u16le(profile_code) ||
u16le(api_ordinal) || u16le(return_kind_code) || s64le(return_value) ||
u8(error_valid) || u8(0) || u16le(0) || u32le(error_code) ||
u16le(output_region_count) ||
CONCAT(for each output region in joined request-region order:
  u16le(argument_ordinal) || u16le(region_ordinal) ||
  u16le(recursion_depth) || u16le(parent_region_ordinal_or_ffff) ||
  u32le(parent_struct_field_offset) || u16le(region_kind_code) ||
  u16le(layout_ordinal_or_ffff) || u64le(declared_capacity) ||
  u64le(initialized_length) || u64le(payload_length) || payload_bytes)
```

The eight-byte magics, all reserved zeroes, field order, and little-endian
widths are literal.  `profile_code` is `0` for x86-64 and `1` for AArch64.
Direction codes are `IN=0`, `OUT=1`, `INOUT=2`; value-kind codes are
`S32=0`, `U16=1`, `U32=2`, `S64=3`, `U64=4`, `POINTER=5`; initialization codes
are `INPUT_ALL=0`, `OUTPUT_PREFIX=1`, `INPUT_THEN_OUTPUT_MEMBERS=2`; region-kind
codes are `CSTRING=0`, `OPAQUE_BYTES=1`, `STRUCT=2`, `STRUCT_ARRAY=3`, and
`S32_ARRAY=4`.  Layout ordinals are their zero-based positions in the layout
roster; the all-ones sentinel means no named layout.  A direct region has depth
zero and parent-region sentinel `ffff`; a nested region has depth one and names
its unique parent.  `payload_length == len(payload_bytes)`.  An OUT request has
input initialized length and payload length zero.  IN and INOUT request payload
lengths equal their initialized input lengths.  Every length is bounded by and
never substituted for `declared_capacity`.

For structured request payloads, bytes are the exact zero-initialized in-memory
layout, including required zero padding and reserved input fields.  Structured
result payloads are not raw structs.  They are the canonical member stream
`u16le(member_count) || CONCAT(u32le(element_ordinal) ||
u16le(field_ordinal) || u32le(field_offset) || u16le(field_size) ||
u32le(member_length) || member_bytes)` in `(element ordinal,field ordinal)`
order.  A scalar field has `member_length == field_size`; a nested named struct
has `member_bytes` equal to its recursively encoded member stream.  STRUCT uses
element ordinal zero.  STRUCT_ARRAY uses every element in increasing ordinal.
Only named initialized OUT members appear; padding, reserved members, stale
suffixes, and caller zero-fill never appear.  `initialized_length` is the sum
of authoritative leaf member widths, while `payload_length` is the framed
member-stream length.  Thus the formerly ambiguous `bytes`, `region_bytes`, and
arbitrary `named_members` spellings have no effective meaning in R3.5.

For `read`, `pread64`, and `readlinkat`, authoritative output is exactly the
first `return_value` bytes when the return is nonnegative and no bytes on `-1`.
For `poll`, every `revents` field for all `nfds` elements is authoritative only
on a nonnegative return; on `-1` there are zero authoritative output members,
while the request retains the input `fd/events` fields.  For `fstat` and
`statx`, all and only named OUT fields are authoritative on return zero; an
error has none.  For `clone3`, the four-byte signed pidfd pointee is
authoritative only on a nonnegative return with `CLONE_PIDFD` set.  Every other
roster call has zero output regions.  The total projection formula is therefore
`observed_poststate = POSTCONDITION(api,profile,request_frame,
returned_result_frame,fresh_observations)`; it never reads bytes outside the
initialized set.

The request frame is durable before entry.  A normal return has exactly one
result frame.  A process crash has no result frame at all and uses the separate
no-return envelope in section 19.9; a validator must reject a crash record that
fabricates a return value, error slot, or output byte.

The closed named-layout roster is the parsed JSON array between the following
markers.  It is normative data, not an illustrative code sample.  `fields` is
ordered by offset and each string is `name:offset:size:type:direction`; explicit
padding/reserved rows are part of the layout.

<!-- BEGIN VECTOR_NATIVE_LAYOUT_ROSTER_R3_5 -->
```json
[
  {"abi":"BOTH","align":4,"fields":["code:0:2:u16:IN","jt:2:1:u8:IN","jf:3:1:u8:IN","k:4:4:u32:IN"],"layout":"sock_filter","size":8,"uapi":"linux/filter.h@v6.16"},
  {"abi":"BOTH","align":8,"fields":["len:0:2:u16:IN","padding0:2:6:zero:IN","filter:8:8:pointer:IN"],"layout":"sock_fprog","size":16,"uapi":"linux/filter.h@v6.16"},
  {"abi":"BOTH","align":8,"fields":["flags:0:8:u64:IN","pidfd:8:8:pointer:INOUT","child_tid:16:8:pointer:IN","parent_tid:24:8:pointer:IN","exit_signal:32:8:u64:IN","stack:40:8:pointer:IN","stack_size:48:8:u64:IN","tls:56:8:u64:IN","set_tid:64:8:pointer:IN","set_tid_size:72:8:u64:IN","cgroup:80:8:u64:IN"],"layout":"clone_args_v2","size":88,"uapi":"linux/sched.h@v6.16"},
  {"abi":"BOTH","align":4,"fields":["fd:0:4:s32:IN","events:4:2:s16:IN","revents:6:2:s16:OUT"],"layout":"pollfd","size":8,"uapi":"asm-generic/poll.h@v6.16"},
  {"abi":"LINUX_X86_64_LP64_LE","align":8,"fields":["st_dev:0:8:u64:OUT","st_ino:8:8:u64:OUT","st_nlink:16:8:u64:OUT","st_mode:24:4:u32:OUT","st_uid:28:4:u32:OUT","st_gid:32:4:u32:OUT","__pad0:36:4:reserved:UNREAD","st_rdev:40:8:u64:OUT","st_size:48:8:s64:OUT","st_blksize:56:8:s64:OUT","st_blocks:64:8:s64:OUT","st_atime:72:8:u64:OUT","st_atime_nsec:80:8:u64:OUT","st_mtime:88:8:u64:OUT","st_mtime_nsec:96:8:u64:OUT","st_ctime:104:8:u64:OUT","st_ctime_nsec:112:8:u64:OUT","__unused:120:24:reserved:UNREAD"],"layout":"kernel_stat","size":144,"uapi":"arch/x86/include/uapi/asm/stat.h@v6.16"},
  {"abi":"LINUX_AARCH64_LP64_LE","align":8,"fields":["st_dev:0:8:u64:OUT","st_ino:8:8:u64:OUT","st_mode:16:4:u32:OUT","st_nlink:20:4:u32:OUT","st_uid:24:4:u32:OUT","st_gid:28:4:u32:OUT","st_rdev:32:8:u64:OUT","__pad1:40:8:reserved:UNREAD","st_size:48:8:s64:OUT","st_blksize:56:4:s32:OUT","__pad2:60:4:reserved:UNREAD","st_blocks:64:8:s64:OUT","st_atime:72:8:s64:OUT","st_atime_nsec:80:8:u64:OUT","st_mtime:88:8:s64:OUT","st_mtime_nsec:96:8:u64:OUT","st_ctime:104:8:s64:OUT","st_ctime_nsec:112:8:u64:OUT","__unused4:120:4:reserved:UNREAD","__unused5:124:4:reserved:UNREAD"],"layout":"kernel_stat","size":128,"uapi":"include/uapi/asm-generic/stat.h@v6.16"},
  {"abi":"BOTH","align":8,"fields":["tv_sec:0:8:s64:OUT","tv_nsec:8:4:u32:OUT","__reserved:12:4:reserved:UNREAD"],"layout":"statx_timestamp","size":16,"uapi":"linux/stat.h@v6.16"},
  {"abi":"BOTH","align":8,"fields":["stx_mask:0:4:u32:OUT","stx_blksize:4:4:u32:OUT","stx_attributes:8:8:u64:OUT","stx_nlink:16:4:u32:OUT","stx_uid:20:4:u32:OUT","stx_gid:24:4:u32:OUT","stx_mode:28:2:u16:OUT","__spare0:30:2:reserved:UNREAD","stx_ino:32:8:u64:OUT","stx_size:40:8:u64:OUT","stx_blocks:48:8:u64:OUT","stx_attributes_mask:56:8:u64:OUT","stx_atime:64:16:statx_timestamp:OUT","stx_btime:80:16:statx_timestamp:OUT","stx_ctime:96:16:statx_timestamp:OUT","stx_mtime:112:16:statx_timestamp:OUT","stx_rdev_major:128:4:u32:OUT","stx_rdev_minor:132:4:u32:OUT","stx_dev_major:136:4:u32:OUT","stx_dev_minor:140:4:u32:OUT","stx_mnt_id:144:8:u64:OUT","stx_dio_mem_align:152:4:u32:OUT","stx_dio_offset_align:156:4:u32:OUT","stx_subvol:160:8:u64:OUT","stx_atomic_write_unit_min:168:4:u32:OUT","stx_atomic_write_unit_max:172:4:u32:OUT","stx_atomic_write_segments_max:176:4:u32:OUT","stx_dio_read_offset_align:180:4:u32:OUT","stx_atomic_write_unit_max_opt:184:4:u32:OUT","__spare2:188:4:reserved:UNREAD","__spare3:192:64:reserved:UNREAD"],"layout":"statx","size":256,"uapi":"linux/stat.h@v6.16"},
  {"abi":"BOTH","align":8,"fields":["handled_access_fs:0:8:u64:IN","handled_access_net:8:8:u64:IN","scoped:16:8:u64:IN","quiet_access_fs:24:8:u64:IN","quiet_access_net:32:8:u64:IN","quiet_scoped:40:8:u64:IN"],"layout":"landlock_ruleset_attr","size":48,"uapi":"linux/landlock.h@2e05544060b9fef5d4d0e0172944e6956c55080f"},
  {"abi":"BOTH","align":1,"fields":["allowed_access:0:8:u64:IN","parent_fd:8:4:s32:IN"],"layout":"landlock_path_beneath_attr","size":12,"uapi":"linux/landlock.h@2e05544060b9fef5d4d0e0172944e6956c55080f"}
]
```
<!-- END VECTOR_NATIVE_LAYOUT_ROSTER_R3_5 -->

The layout row stream is `CONCAT(CJ(row)||LF)` in displayed order.  Its exact
row count, byte length, and SHA-256 are respectively `10`,
`3877`, and
`b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a`.
The canonical parsed array is 3,878 bytes with SHA-256
`b67b0b086370cf79f0a3afeb4adad6a07531f468996e6ec5e690b2cad83b7c82`.
The implementation embeds
those constants and rejects a missing, added, reordered, or substituted row.
The UAPI labels above are joined to the exact vendored-header mapping region
defined below; they are not resolved from ambient host headers.
The two Landlock layouts intentionally pin commit
`2e05544060b9fef5d4d0e0172944e6956c55080f`, whose UAPI contains the ABI-10
six-field, 48-byte ruleset attribute and the ABI-9/10 rights required by the
effective policy.  A v6.16 Landlock header has only the earlier three-field,
24-byte attribute and cannot satisfy this policy; mixing its layout with the
ABI-10 masks, or resolving a same-named ambient header, rejects.
The primary layout source is
`https://github.com/torvalds/linux/blob/2e05544060b9fef5d4d0e0172944e6956c55080f/include/uapi/linux/landlock.h`;
the vendored bytes and their independent source review, not this URL's future
availability, are the build input.

### 19.2 Closed 22-call signature roster

Each displayed kernel-declaration row has exactly `{api,args,ordinal,outputs,
prototype,return_kind,uapi_symbol}`.  Each argument has exactly
`{direction,encoding,name,pointee}`;
`pointee` is null or one of the literal expressions in the constant.  Those
expressions are part of the schema.  No implementation may use
the prototype string as a parser or substitute a libc wrapper signature.
`bound_input_size(name)` is an independently carried typed-input byte count
known before the call; it includes exactly one terminal NUL for a C string and
is never obtained with `strlen`, a sentinel search, or any memory scan.

<!-- BEGIN VECTOR_NATIVE_SIGNATURE_ROSTER_R3_5 -->
```json
[
  {"api":"mkdirat","args":[{"direction":"IN","encoding":"S32_LE","name":"dirfd","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"pathname","pointee":"CSTRING(bound_input_size(pathname),includes_one_terminal_nul)"},{"direction":"IN","encoding":"U16_LE","name":"mode","pointee":null}],"ordinal":0,"outputs":[],"prototype":"long sys_mkdirat(int dfd,const char __user *filename,umode_t mode)","return_kind":"S64_LE","uapi_symbol":"__NR_mkdirat"},
  {"api":"openat","args":[{"direction":"IN","encoding":"S32_LE","name":"dirfd","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"pathname","pointee":"CSTRING(bound_input_size(pathname),includes_one_terminal_nul)"},{"direction":"IN","encoding":"S32_LE","name":"flags","pointee":null},{"direction":"IN","encoding":"U16_LE","name":"mode","pointee":null}],"ordinal":1,"outputs":[],"prototype":"long sys_openat(int dfd,const char __user *filename,int flags,umode_t mode)","return_kind":"FD_OR_MINUS1_S64_LE","uapi_symbol":"__NR_openat"},
  {"api":"read","args":[{"direction":"IN","encoding":"U32_LE","name":"fd","pointee":null},{"direction":"OUT","encoding":"PTR_U64_LE","name":"buf","pointee":"OPAQUE_BYTES(capacity=count,initialized=max(return_value,0))"},{"direction":"IN","encoding":"U64_LE","name":"count","pointee":null}],"ordinal":2,"outputs":["buf[0:max(return_value,0)]"],"prototype":"ssize_t sys_read(unsigned int fd,char __user *buf,size_t count)","return_kind":"BYTE_COUNT_OR_MINUS1_S64_LE","uapi_symbol":"__NR_read"},
  {"api":"write","args":[{"direction":"IN","encoding":"U32_LE","name":"fd","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"buf","pointee":"OPAQUE_BYTES(length=count)"},{"direction":"IN","encoding":"U64_LE","name":"count","pointee":null}],"ordinal":3,"outputs":[],"prototype":"ssize_t sys_write(unsigned int fd,const char __user *buf,size_t count)","return_kind":"BYTE_COUNT_OR_MINUS1_S64_LE","uapi_symbol":"__NR_write"},
  {"api":"pread64","args":[{"direction":"IN","encoding":"U32_LE","name":"fd","pointee":null},{"direction":"OUT","encoding":"PTR_U64_LE","name":"buf","pointee":"OPAQUE_BYTES(capacity=count,initialized=max(return_value,0))"},{"direction":"IN","encoding":"U64_LE","name":"count","pointee":null},{"direction":"IN","encoding":"S64_LE","name":"pos","pointee":null}],"ordinal":4,"outputs":["buf[0:max(return_value,0)]"],"prototype":"ssize_t sys_pread64(unsigned int fd,char __user *buf,size_t count,loff_t pos)","return_kind":"BYTE_COUNT_OR_MINUS1_S64_LE","uapi_symbol":"__NR_pread64"},
  {"api":"readlinkat","args":[{"direction":"IN","encoding":"S32_LE","name":"dirfd","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"pathname","pointee":"CSTRING(bound_input_size(pathname),includes_one_terminal_nul)"},{"direction":"OUT","encoding":"PTR_U64_LE","name":"buf","pointee":"OPAQUE_BYTES(capacity=bufsiz,initialized=max(return_value,0))"},{"direction":"IN","encoding":"S32_LE","name":"bufsiz","pointee":null}],"ordinal":5,"outputs":["buf[0:max(return_value,0)]"],"prototype":"ssize_t sys_readlinkat(int dfd,const char __user *path,char __user *buf,int bufsiz)","return_kind":"BYTE_COUNT_OR_MINUS1_S64_LE","uapi_symbol":"__NR_readlinkat"},
  {"api":"fstat","args":[{"direction":"IN","encoding":"U32_LE","name":"fd","pointee":null},{"direction":"OUT","encoding":"PTR_U64_LE","name":"statbuf","pointee":"STRUCT(kernel_stat,selected_abi,sizeof(kernel_stat),initialized_on_success_fields_only)"}],"ordinal":6,"outputs":["statbuf.named_output_fields"],"prototype":"long sys_fstat(unsigned int fd,struct stat __user *statbuf)","return_kind":"S64_LE","uapi_symbol":"__NR_fstat"},
  {"api":"statx","args":[{"direction":"IN","encoding":"S32_LE","name":"dirfd","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"pathname","pointee":"CSTRING(bound_input_size(pathname),includes_one_terminal_nul)"},{"direction":"IN","encoding":"U32_LE","name":"flags","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"mask","pointee":null},{"direction":"OUT","encoding":"PTR_U64_LE","name":"statxbuf","pointee":"STRUCT(statx,BOTH,256,initialized_on_success_fields_only)"}],"ordinal":7,"outputs":["statxbuf.named_output_fields"],"prototype":"long sys_statx(int dfd,const char __user *filename,unsigned flags,unsigned mask,struct statx __user *buffer)","return_kind":"S64_LE","uapi_symbol":"__NR_statx"},
  {"api":"mount","args":[{"direction":"IN","encoding":"PTR_U64_LE","name":"source","pointee":"NULL_OR_CSTRING(bound_input_size(source),includes_one_terminal_nul)"},{"direction":"IN","encoding":"PTR_U64_LE","name":"target","pointee":"CSTRING(bound_input_size(target),includes_one_terminal_nul)"},{"direction":"IN","encoding":"PTR_U64_LE","name":"filesystemtype","pointee":"NULL_OR_CSTRING(bound_input_size(filesystemtype),includes_one_terminal_nul)"},{"direction":"IN","encoding":"U64_LE","name":"mountflags","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"data","pointee":"NULL_OR_CSTRING(bound_input_size(data),includes_one_terminal_nul)"}],"ordinal":8,"outputs":[],"prototype":"long sys_mount(char __user *dev_name,char __user *dir_name,char __user *type,unsigned long flags,void __user *data)","return_kind":"S64_LE","uapi_symbol":"__NR_mount"},
  {"api":"umount2","args":[{"direction":"IN","encoding":"PTR_U64_LE","name":"target","pointee":"CSTRING(bound_input_size(target),includes_one_terminal_nul)"},{"direction":"IN","encoding":"S32_LE","name":"flags","pointee":null}],"ordinal":9,"outputs":[],"prototype":"long sys_umount(char __user *name,int flags)","return_kind":"S64_LE","uapi_symbol":"__NR_umount2"},
  {"api":"pivot_root","args":[{"direction":"IN","encoding":"PTR_U64_LE","name":"new_root","pointee":"CSTRING(bound_input_size(new_root),includes_one_terminal_nul)"},{"direction":"IN","encoding":"PTR_U64_LE","name":"put_old","pointee":"CSTRING(bound_input_size(put_old),includes_one_terminal_nul)"}],"ordinal":10,"outputs":[],"prototype":"long sys_pivot_root(const char __user *new_root,const char __user *put_old)","return_kind":"S64_LE","uapi_symbol":"__NR_pivot_root"},
  {"api":"prctl","args":[{"direction":"IN","encoding":"S32_LE","name":"option","pointee":null},{"direction":"IN","encoding":"U64_LE","name":"arg2","pointee":null},{"direction":"IN","encoding":"U64_LE","name":"arg3","pointee":null},{"direction":"IN","encoding":"U64_LE","name":"arg4","pointee":null},{"direction":"IN","encoding":"U64_LE","name":"arg5","pointee":null}],"ordinal":11,"outputs":[],"prototype":"long sys_prctl(int option,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5)","return_kind":"S64_LE","uapi_symbol":"__NR_prctl"},
  {"api":"seccomp","args":[{"direction":"IN","encoding":"U32_LE","name":"operation","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"flags","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"args","pointee":"STRUCT(sock_fprog,BOTH,16);NESTED(filter@8,STRUCT_ARRAY(sock_filter,count=len,element_size=8))"}],"ordinal":12,"outputs":[],"prototype":"long sys_seccomp(unsigned int operation,unsigned int flags,void __user *args)","return_kind":"S64_LE","uapi_symbol":"__NR_seccomp"},
  {"api":"landlock_get_abi","args":[{"direction":"IN","encoding":"PTR_U64_LE_ZERO","name":"attr","pointee":null},{"direction":"IN","encoding":"U64_LE_ZERO","name":"size","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"flags","pointee":null}],"ordinal":13,"outputs":[],"prototype":"long sys_landlock_create_ruleset(const struct landlock_ruleset_attr __user *attr,size_t size,__u32 flags)","return_kind":"ABI_VERSION_OR_MINUS1_S64_LE","uapi_symbol":"__NR_landlock_create_ruleset"},
  {"api":"landlock_create_ruleset","args":[{"direction":"IN","encoding":"PTR_U64_LE","name":"attr","pointee":"STRUCT(landlock_ruleset_attr,BOTH,48)"},{"direction":"IN","encoding":"U64_LE","name":"size","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"flags","pointee":null}],"ordinal":14,"outputs":[],"prototype":"long sys_landlock_create_ruleset(const struct landlock_ruleset_attr __user *attr,size_t size,__u32 flags)","return_kind":"FD_OR_MINUS1_S64_LE","uapi_symbol":"__NR_landlock_create_ruleset"},
  {"api":"landlock_add_rule","args":[{"direction":"IN","encoding":"S32_LE","name":"ruleset_fd","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"rule_type","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"rule_attr","pointee":"STRUCT(landlock_path_beneath_attr,BOTH,12)"},{"direction":"IN","encoding":"U32_LE","name":"flags","pointee":null}],"ordinal":15,"outputs":[],"prototype":"long sys_landlock_add_rule(int ruleset_fd,enum landlock_rule_type rule_type,const void __user *rule_attr,__u32 flags)","return_kind":"S64_LE","uapi_symbol":"__NR_landlock_add_rule"},
  {"api":"landlock_restrict_self","args":[{"direction":"IN","encoding":"S32_LE","name":"ruleset_fd","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"flags","pointee":null}],"ordinal":16,"outputs":[],"prototype":"long sys_landlock_restrict_self(int ruleset_fd,__u32 flags)","return_kind":"S64_LE","uapi_symbol":"__NR_landlock_restrict_self"},
  {"api":"close_range","args":[{"direction":"IN","encoding":"U32_LE","name":"first","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"last","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"flags","pointee":null}],"ordinal":17,"outputs":[],"prototype":"long sys_close_range(unsigned int first,unsigned int last,unsigned int flags)","return_kind":"S64_LE","uapi_symbol":"__NR_close_range"},
  {"api":"clone3","args":[{"direction":"INOUT","encoding":"PTR_U64_LE","name":"uargs","pointee":"STRUCT(clone_args_v2,BOTH,size);NESTED_IF(flags&CLONE_PIDFD,pidfd@8,S32_OUTPUT_BYTES(4))"},{"direction":"IN","encoding":"U64_LE","name":"size","pointee":null}],"ordinal":18,"outputs":["uargs.pidfd_pointee_if_CLONE_PIDFD"],"prototype":"long sys_clone3(struct clone_args __user *uargs,size_t size)","return_kind":"PID_OR_MINUS1_S64_LE","uapi_symbol":"__NR_clone3"},
  {"api":"pidfd_send_signal","args":[{"direction":"IN","encoding":"S32_LE","name":"pidfd","pointee":null},{"direction":"IN","encoding":"S32_LE","name":"sig","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE_ZERO","name":"info","pointee":null},{"direction":"IN","encoding":"U32_LE","name":"flags","pointee":null}],"ordinal":19,"outputs":[],"prototype":"long sys_pidfd_send_signal(int pidfd,int sig,siginfo_t __user *info,unsigned int flags)","return_kind":"S64_LE","uapi_symbol":"__NR_pidfd_send_signal"},
  {"api":"poll","args":[{"direction":"INOUT","encoding":"PTR_U64_LE","name":"fds","pointee":"STRUCT_ARRAY(pollfd,count=nfds,element_size=8,input=fd+events,output=revents)"},{"direction":"IN","encoding":"U32_LE","name":"nfds","pointee":null},{"direction":"IN","encoding":"S32_LE","name":"timeout_msecs","pointee":null}],"ordinal":20,"outputs":["fds[0:nfds].revents"],"prototype":"long sys_poll(struct pollfd __user *fds,unsigned int nfds,int timeout_msecs)","return_kind":"READY_COUNT_OR_MINUS1_S64_LE","uapi_symbol":"__NR_poll"},
  {"api":"unlinkat","args":[{"direction":"IN","encoding":"S32_LE","name":"dirfd","pointee":null},{"direction":"IN","encoding":"PTR_U64_LE","name":"pathname","pointee":"CSTRING(bound_input_size(pathname),includes_one_terminal_nul)"},{"direction":"IN","encoding":"S32_LE","name":"flags","pointee":null}],"ordinal":21,"outputs":[],"prototype":"long sys_unlinkat(int dfd,const char __user *pathname,int flag)","return_kind":"S64_LE","uapi_symbol":"__NR_unlinkat"}
]
```
<!-- END VECTOR_NATIVE_SIGNATURE_ROSTER_R3_5 -->

The signature row stream is `CONCAT(CJ(row)||LF)` in displayed order.  Its
exact row count, byte length, and SHA-256 are respectively `22`,
`11393`, and
`ef473e2d3b6612fbfe5d060457e2d50c24f34282c09d76aa94085408891b0b97`.
The canonical parsed array is 11,394 bytes with SHA-256
`ed02085631637339759497b5a8a258e5ce86290a9cc715972fbfec1e894f0b8e`.

The invocation contract is not inferred from `prototype`.  The canonical
signature-binding roster is constructed in displayed order as:

```text
binding[i] = {
  abi_profiles:["LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"],
  call_layer:"LIBC_SYSCALL_REGISTER_WORDS_V1",
  error_convention:"LIBC_MINUS1_ERRNO_V1",
  row:signature_rows[i]}
```

Its 22-row `CONCAT(CJ(binding[i])||LF)` stream is exactly 14,913 bytes with
SHA-256 `684e168ad6a845410f88c09cf9f9c28644813045acda15d045b904484eb00273`;
its canonical parsed array is exactly 14,914 bytes with SHA-256
`f4238822c4dce3bfd3d4c0239d92d8608890373bf8484dc942313f5139775886`.
Every call joins its complete binding row, not merely the kernel prototype or
symbol.  `LIBC_SYSCALL_REGISTER_WORDS_V1` means the sole callable entry is the
pinned C-library `long syscall(long number, ...)` boundary.  Before the call,
`S32_LE` is decoded to an exact signed 32-bit value and sign-extended to the
target syscall-register word; `U16_LE` and `U32_LE` are zero-extended;
`S64_LE`, `U64_LE`, and pointer values preserve all 64 bits.  `umode_t` is
therefore unsigned 16-bit, the `read`, `write`, `pread64`, and `fstat` kernel
file-descriptor arguments are unsigned 32-bit, and `statx.flags` is unsigned
32-bit.  No host-language default integer, `size_t`, `long`, or reconstructed
`ctypes` declaration may alter those source widths or extensions.

`LIBC_MINUS1_ERRNO_V1` means the pinned C-library adapter returns `-1` and sets
the thread-local positive `errno` for a kernel error; it never exposes raw
`-errno`.  The caller sets `errno=0` immediately before entry and copies the
return word and `errno` before any allocation, formatting, logging, cleanup, or
other native/library call.  A nonnegative return requires captured `errno=0`;
`-1` requires `errno in 1..4095`; any other negative wrapper return rejects.
In the result frame, `error_valid == (return_value == -1)` and `error_code` is
exactly the captured errno when valid and zero otherwise.
The exact C-library source/binary that supplies this adapter is part of the
platform provenance and exact executed-binary join in section 19.9.

Pointer expressions use an exact acyclic two-pass evaluator.  Pass 1 decodes
and validates every scalar argument, in roster order, into an immutable map
`scalar[name]=(signedness,width,value)` and decodes every direct input struct
against its named layout.  No pointer region is dereferenced or allocated in
pass 1.  Pass 2 parses every roster expression into the closed expression AST,
resolves names against the complete immutable scalar map and the already-
decoded same-call input-layout fields, constructs the parent/child region DAG,
and evaluates it in topological `(depth,parent argument ordinal,field offset)`
order.  Unknown names, output-field dependencies, duplicate nodes, cycles,
depth greater than one, arithmetic overflow, negative lengths, or values above
16,777,216 reject before entry.  This deliberately admits the six forward
scalar dependencies `read.buf->count`, `write.buf->count`,
`pread64.buf->count`, `readlinkat.buf->bufsiz`, `clone3.uargs->size`, and
`poll.fds->nfds`; a deterministic negative fixture must add a synthetic cycle
and prove rejection without a call.

The roster ordinal is
the API ordinal in both native frames.  The `landlock_get_abi` row is explicitly
the zero-attr/zero-size `landlock_create_ruleset` syscall with flags exactly
`LANDLOCK_CREATE_RULESET_VERSION`; it is not an ambient wrapper call.  `info`
in `pidfd_send_signal` is exactly null in this revision.  `clone3.size` is
exactly 88.  A different size, a nonnull unsupported pointer field, a missing
buffer/count pair, or a call not present in this roster rejects.

### 19.3 Pinned native and seccomp implementation inputs

The following closed branches replace the three unconstrained `file_identity`
members in section 18.1.  `region_offset` and `region_size_bytes` are measured
against the exact containing source bytes and `region_sha256` covers exactly
that slice.  The source review must name the constant role, source path,
containing source identity, and slice tuple in a passing check.  The build-plan
review must join that source review.  These are named regions inside already
registered successor inputs; no new path is added.

```text
vector_seccomp_input_region =
U(O(role:C("SECCOMP_UAPI_MAPPING"),
    source_path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/build_private_runtime_v1.py"),
    source:R(file_identity),region_name:C("SECCOMP_UAPI_MAPPING_R3_5"),
    region_offset:I(0,16777215),region_size_bytes:I(1,16777216),region_sha256:HEX,
    review_path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/RUNTIME_BUILDER_V1_SOURCE_REVIEW.v1.json"),
    source_review:R(file_identity)),
  O(role:C("SECCOMP_CLASSIC_BPF_VERIFIER"),
    source_path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/capture_schema_contract_parity_evidence_v2.py"),
    source:R(file_identity),region_name:C("SECCOMP_CLASSIC_BPF_VERIFIER_R3_5"),
    region_offset:I(0,16777215),region_size_bytes:I(1,16777216),region_sha256:HEX,
    review_path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_V2_IMPLEMENTATION_REVIEW.v1.json"),
    source_review:R(file_identity)),
  O(role:C("NATIVE_CALL_FRAME_ENCODER"),
    source_path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/capture_schema_contract_parity_evidence_v2.py"),
    source:R(file_identity),region_name:C("NATIVE_CALL_FRAME_ENCODER_R3_5"),
    region_offset:I(0,16777215),region_size_bytes:I(1,16777216),region_sha256:HEX,
    review_path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_V2_IMPLEMENTATION_REVIEW.v1.json"),
    source_review:R(file_identity)))

vector_seccomp_build_inputs =
O(regions:T(
    O(role:C("SECCOMP_UAPI_MAPPING"),region:R(vector_seccomp_input_region)),
    O(role:C("SECCOMP_CLASSIC_BPF_VERIFIER"),region:R(vector_seccomp_input_region)),
    O(role:C("NATIVE_CALL_FRAME_ENCODER"),region:R(vector_seccomp_input_region))),
  runtime_build_plan_path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_RUNTIME_BUILD_PLAN_LOCK.v1.json"),
  runtime_build_plan:R(file_identity),
  runtime_build_review_path:C("review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PARITY_RUNTIME_BUILD_PLAN_LOCK_REVIEW.v1.json"),
  runtime_build_review:R(file_identity),
  native_layout_row_count:C(10),native_layout_row_stream_size:C(3877),
  native_layout_row_stream_sha256:C("b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a"),
  native_signature_row_count:C(22),native_signature_row_stream_size:C(11393),
  native_signature_row_stream_sha256:C("ef473e2d3b6612fbfe5d060457e2d50c24f34282c09d76aa94085408891b0b97"),
  native_signature_binding_row_stream_size:C(14913),
  native_signature_binding_row_stream_sha256:C("684e168ad6a845410f88c09cf9f9c28644813045acda15d045b904484eb00273"),
  inputs_sha256:HEX)
```

The three tuple positions require their matching union branch.  For every
materialized region, `source.path == source_path`, `source_review.path ==
review_path`, the review subject equals `source`, and its named check equals
`(role,region_name,region_offset,region_size_bytes,region_sha256)`.  Review
responsibility is temporal: the pre-build review validates only the plan,
builder input, declared target, and declared output paths; it cannot mention an
installed source, built binary, execution receipt, or later review.  The
post-build implementation review is the first validator allowed to bind the
installed source and named regions.  The final independent native-authority
review is the first validator allowed to join reviewed source, build receipt,
exact executed binary, oracle, fixture receipt, and disposition.  A review may
not validate its own bytes or any artifact produced after it.  The prior R3.4
claim assigning future installed-source joins to the build review is replaced.
The non-self-referential formula is:

```text
inputs_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_SECCOMP_BUILD_INPUTS_V2",
  regions,runtime_build_plan,runtime_build_review,
  native_layout_row_count,native_layout_row_stream_size,
  native_layout_row_stream_sha256,native_signature_row_count,
  native_signature_row_stream_size,native_signature_row_stream_sha256,
  native_signature_binding_row_stream_size,
  native_signature_binding_row_stream_sha256}))
```

A correct slice under a different path, role, source, review, build plan, or
build review rejects.  The reviewed UAPI region maps each allowed name and both
audit architectures to exact unsigned numbers and rejects duplicate numbers or
aliases.  The reviewed verifier consumes only that parsed mapping, the selected
architecture, and instruction bytes.  The reviewed encoder consumes only the
two pinned rosters and layouts.  None may import the target, a producer
implementation, ambient headers, libc prototype metadata, or its own review.

Header, SDK, C-library, compiler, linker, source, oracle, and executable
provenance are closed rather than inferred from a textual `v6.16` or ambient
installation:

```text
vector_native_header_input =
O(platform:E("LINUX","WINDOWS"),role:S1,logical_include_path:S1,
  provider:E("LINUX_GIT_BLOB","WINDOWS_SDK_PACKAGE"),
  upstream_repository_or_package:S1,upstream_revision_or_version:S1,
  upstream_content_sha256:HEX,vendored_path:PATH,
  vendored_file:R(file_identity),byte_equal_to_upstream:C(true))

vector_native_source_input =
O(role:S1,path:PATH,file:R(file_identity),language:E("C","CXX","PYTHON"),
  region_name:Q(S1),region_offset:Q(I(0,16777215)),
  region_size_bytes:Q(I(1,16777216)),region_sha256:Q(HEX))

vector_native_review_record =
O(review_role:E("INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW",
    "LAYOUT_ORACLE_REVIEW","IMPLEMENTATION_REVIEW","FACILITY_REVIEW",
    "RECEIPT_REVIEW","NATIVE_AUTHORITY_REVIEW"),
  review_artifact:R(file_identity),reviewer_principal:S1,
  subject_identities:A(R(file_identity),1,256,true),
  predecessor_identities:A(R(file_identity),0,256,true),
  subject_author_principals:A(S1,1,256,false),
  reviewer_distinct_from_subject_authors:C(true),self_review:C(false),
  future_subject_count:C(0),disposition:E("PASS_NONAUTHORITATIVE","REPAIR"),
  review_sha256:HEX)

vector_native_build_receipt =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  source_row_stream_sha256:HEX,header_row_stream_sha256:HEX,
  toolchain_sha256:HEX,command_frames:R(file_identity),
  stdout:R(content_identity),stderr:R(content_identity),exit_code:C(0),
  oracle_source:R(file_identity),oracle_binary:R(file_identity),
  production_source:R(file_identity),production_binary:R(file_identity),
  source_to_binary_join_sha256:HEX,receipt_sha256:HEX)

vector_native_toolchain_manifest =
O(platform:E("LINUX","WINDOWS"),target_triple:S1,
  compiler_path:PATH,compiler:R(file_identity),compiler_version:S1,
  linker_path:PATH,linker:R(file_identity),linker_version:S1,
  libc_or_crt_path:PATH,libc_or_crt:R(file_identity),
  libc_or_crt_version:S1,sdk_or_sysroot_path:PATH,
  sdk_or_sysroot_manifest:R(file_identity),
  compiler_flags:A(S1,1,128,false),linker_flags:A(S1,0,128,false),
  environment_keys:C([]),response_files:A(R(file_identity),0,16,true),
  toolchain_sha256:HEX)

vector_native_build_manifest =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  sources:A(R(vector_native_source_input),1,64,true),
  source_row_count:I(1,64),source_row_stream_size_bytes:I(1,16777216),
  source_row_stream_sha256:HEX,
  headers:A(R(vector_native_header_input),1,128,true),
  header_row_count:I(1,128),header_row_stream_size_bytes:I(1,16777216),
  header_row_stream_sha256:HEX,
  toolchain:R(vector_native_toolchain_manifest),
  review_dag:R(vector_native_review_dag),
  layout_row_stream_sha256:HEX,signature_binding_row_stream_sha256:HEX,
  oracle_source:R(file_identity),oracle_binary:R(file_identity),
  production_source:R(file_identity),production_binary:R(file_identity),
  build_receipt:R(vector_native_build_receipt),build_manifest_sha256:HEX)

vector_native_review_dag =
O(node_order:C(["INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW",
    "BUILD_RECEIPT","IMPLEMENTATION_REVIEW","HOST_EXECUTION_RECEIPT",
    "NATIVE_AUTHORITY_REVIEW"]),
  edges:C([["INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW"],
    ["BUILD_PLAN_REVIEW","BUILD_RECEIPT"],
    ["BUILD_RECEIPT","IMPLEMENTATION_REVIEW"],
    ["IMPLEMENTATION_REVIEW","HOST_EXECUTION_RECEIPT"],
    ["HOST_EXECUTION_RECEIPT","NATIVE_AUTHORITY_REVIEW"],
    ["INPUT_PROVENANCE_REVIEW","IMPLEMENTATION_REVIEW"],
    ["BUILD_RECEIPT","HOST_EXECUTION_RECEIPT"],
    ["IMPLEMENTATION_REVIEW","NATIVE_AUTHORITY_REVIEW"]]),
  acyclic:C(true),self_edges:C(0),future_subject_reviews:C(0),dag_sha256:HEX)
```

`dag_sha256 = SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_NATIVE_REVIEW_DAG_V1",node_order,edges,acyclic:true,
self_edges:0,future_subject_reviews:0}))`.  Every edge points from a strictly
smaller node ordinal to a larger one.  Each review record identifies its exact
already-materialized subjects and predecessor review/receipt identities; it
cannot contain a wildcard, future identity, its own identity, or an output it
authored.  The deferred 15-edge admission crosscheck is not a node or edge of
this evidence DAG.

`vector_native_review_record.review_sha256` excludes itself and equals
`SHA-256(CJ({domain:"PROGRAM_FACTS_G3_NATIVE_REVIEW_RECORD_V1",
review_role,review_artifact,reviewer_principal,subject_identities,
predecessor_identities,subject_author_principals,
reviewer_distinct_from_subject_authors:true,self_review:false,
future_subject_count:0,disposition}))`.  A PASS review has every complete subject
already present; REPAIR is nonauthority and cannot satisfy a required PASS.
`vector_native_build_receipt.source_to_binary_join_sha256` is
`SHA-256(CJ({domain:"PROGRAM_FACTS_G3_NATIVE_SOURCE_TO_BINARY_JOIN_V1",
profile,source_row_stream_sha256,header_row_stream_sha256,toolchain_sha256,
command_frames,oracle_source,oracle_binary,production_source,
production_binary,exit_code:0}))`; `receipt_sha256` adds stdout, stderr, and that
join under domain `PROGRAM_FACTS_G3_NATIVE_BUILD_RECEIPT_V1`, excluding only
itself.  Thus a source, header, toolchain, oracle, production output, or command
substitution necessarily changes the join.

`upstream_content_sha256` is over exact header bytes, not a Git label.  Linux
must register every consumed byte source, including the architecture syscall
number header, type declarations, `linux/types.h`, `linux/filter.h`,
`linux/sched.h`, both stat headers, `linux/landlock.h`, and all transitive macro
providers.  Windows must register exact `Windows.h`, `winbase.h`, `fileapi.h`,
`winnt.h`, their transitive defining headers, import libraries, CRT headers and
libraries, Windows SDK package/version/manifest, MSVC compiler/linker binaries,
and target flags.  Every layout-roster `uapi` label resolves one-to-one to a
registered header row and byte slice.  The build-manifest hash excludes only
itself and is `SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_NATIVE_BUILD_MANIFEST_V1",profile,sources,headers,
toolchain,review_dag,layout_row_stream_sha256,signature_binding_row_stream_sha256,
source_row_count,source_row_stream_size_bytes,source_row_stream_sha256,
header_row_count,header_row_stream_size_bytes,header_row_stream_sha256,
oracle_source,oracle_binary,production_source,production_binary,
build_receipt}))`.  No ambient include path, unregistered transitive header,
unversioned SDK, PATH-resolved tool, or source/binary substitution is allowed.
The source and header counts equal their array lengths; each size/digest is over
its exact ordinal `CONCAT(CJ(row)||LF)` stream.  Independent provenance review
must prove the header roster is the complete transitive preprocessor read set
and the source/response-file roster is the complete compiler/linker read set;
an allowlisted subset or a digest without its rows rejects.
The exact material identities are not present in this stable draft; section
19.9 therefore carries the closed `UNMATERIALIZED_PROVENANCE` nonauthority
branch instead of inventing them.

The effective seccomp preimage is the section-18.1 object with
`domain:"PROGRAM_FACTS_G3_VECTOR_SECCOMP_POLICY_V4"` and with
`uapi_mapping`, `verifier_contract`, and `verifier_contract_review` replaced
by `build_inputs:R(vector_seccomp_build_inputs)`.  Its semantic-proof preimage
likewise contains `build_inputs` exactly once in their place.  Every other
allowed-syscall, architecture-specific, instruction, and full-domain semantic
rule remains byte-for-byte effective.

### 19.4 Effective native-call types and joins

The section-18 native projection/call definitions are replaced in full:

```text
vector_native_nested_pointee_region =
O(region_ordinal:I(0,31),recursion_depth:C(1),
  parent_argument_ordinal:I(0,7),parent_region_ordinal:I(0,31),
  parent_struct_field_offset:I(0,65535),direction:E("IN","OUT","INOUT"),
  initialization:E("INPUT_ALL","OUTPUT_PREFIX","INPUT_THEN_OUTPUT_MEMBERS"),
  region_kind:E("CSTRING","OPAQUE_BYTES","STRUCT","STRUCT_ARRAY","S32_ARRAY"),
  layout_ordinal:Q(I(0,9)),declared_capacity:I(0,16777216),
  input_initialized_length:I(0,16777216),payload:R(vector_exact_native_bytes))

vector_native_pointee_region =
O(region_ordinal:I(0,31),recursion_depth:C(0),
  parent_argument_ordinal:I(0,7),parent_region_ordinal:C(null),
  parent_struct_field_offset:C(0),direction:E("IN","OUT","INOUT"),
  initialization:E("INPUT_ALL","OUTPUT_PREFIX","INPUT_THEN_OUTPUT_MEMBERS"),
  region_kind:E("CSTRING","OPAQUE_BYTES","STRUCT","STRUCT_ARRAY","S32_ARRAY"),
  layout_ordinal:Q(I(0,9)),declared_capacity:I(0,16777216),
  input_initialized_length:I(0,16777216),payload:R(vector_exact_native_bytes),
  children:A(R(vector_native_nested_pointee_region),0,32,true))

vector_native_argument_value =
O(ordinal:I(0,7),name:S1,direction:E("IN","OUT","INOUT"),
  value_kind:E("S32","U16","U32","S64","U64","POINTER"),
  value_bytes:R(vector_exact_native_bytes),
  pointees:A(R(vector_native_pointee_region),0,32,true))

vector_native_argument_projection =
O(api:E("mkdirat","openat","read","write","pread64","readlinkat","fstat",
  "statx","mount","umount2","pivot_root","prctl","seccomp",
  "landlock_get_abi","landlock_create_ruleset","landlock_add_rule",
  "landlock_restrict_self","close_range","clone3","pidfd_send_signal",
  "poll","unlinkat"),
  abi:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  signature_ordinal:I(0,21),signature_row_sha256:HEX,
  signature_roster_sha256:C("ef473e2d3b6612fbfe5d060457e2d50c24f34282c09d76aa94085408891b0b97"),
  signature_binding_roster_sha256:C("684e168ad6a845410f88c09cf9f9c28644813045acda15d045b904484eb00273"),
  call_layer:C("LIBC_SYSCALL_REGISTER_WORDS_V1"),
  error_convention:C("LIBC_MINUS1_ERRNO_V1"),
  layout_roster_sha256:C("b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a"),
  arguments:A(R(vector_native_argument_value),1,8,true))

vector_native_output_member =
O(element_ordinal:I(0,2097151),field_ordinal:I(0,127),
  field_offset:I(0,16777215),field_size:I(1,16777216),
  member_bytes:R(vector_exact_native_bytes))

vector_native_output_region =
O(argument_ordinal:I(0,7),region_ordinal:I(0,31),recursion_depth:I(0,1),
  parent_region_ordinal:Q(I(0,31)),parent_struct_field_offset:I(0,65535),
  direction:E("OUT","INOUT"),
  region_kind:E("OPAQUE_BYTES","STRUCT","STRUCT_ARRAY","S32_ARRAY"),
  layout_ordinal:Q(I(0,9)),declared_capacity:I(0,16777216),
  initialization:E("OUTPUT_PREFIX","INPUT_THEN_OUTPUT_MEMBERS"),
  initialized_length:I(0,16777216),payload:R(vector_exact_native_bytes),
  members:A(R(vector_native_output_member),0,128,true))

vector_native_result_projection =
O(return_kind:E("S64_LE","FD_OR_MINUS1_S64_LE",
  "BYTE_COUNT_OR_MINUS1_S64_LE","ABI_VERSION_OR_MINUS1_S64_LE",
  "PID_OR_MINUS1_S64_LE","READY_COUNT_OR_MINUS1_S64_LE"),
  return_value:I(-1,9007199254740991),
  error_valid:B,errno_captured_immediately:I(0,4095),
  outputs:A(R(vector_native_output_region),0,128,true))

vector_native_call =
O(ordinal:I(0,4095),call_id:S(40,40,"^pfg3vnc-[0-9a-f]{32}$"),
  arguments_bytes:R(vector_exact_native_bytes),
  arguments:R(vector_native_argument_projection),
  result_bytes:R(vector_exact_native_bytes),
  result:R(vector_native_result_projection),
  encoder_inputs:R(vector_seccomp_build_inputs),call_sha256:HEX)

vector_native_no_return_envelope =
O(completion_kind:C("NO_RETURN"),reason:C("PROCESS_CRASH"),
  api:E("mkdirat","openat","read","write","pread64","readlinkat","fstat",
    "statx","mount","umount2","pivot_root","prctl","seccomp",
    "landlock_get_abi","landlock_create_ruleset","landlock_add_rule",
    "landlock_restrict_self","close_range","clone3","pidfd_send_signal",
    "poll","unlinkat"),
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  request_frame:R(vector_exact_native_bytes),
  arguments:R(vector_native_argument_projection),result_frame:C(null),
  crash_seam:E("BEFORE_ENTRY","AFTER_REQUEST_DURABLE","DURING_CALL",
    "AFTER_EFFECT_BEFORE_RETURN","AFTER_RETURN_BEFORE_ERROR_CAPTURE",
    "AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE","DURING_POSTSTATE",
    "AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER"),
  durable_prestate:R(file_identity),fresh_poststate_observations:R(file_identity),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE"),reconciliation_sha256:HEX)
```

Each exact-native-bytes object recomputes size and digest from `bytes_hex`.
The argument projection's row hash is `SHA-256(CJ(the exact selected signature
row))`; API, ordinal, argument roster, directions, encodings, pointee
expressions, outputs, return kind, and UAPI symbol equal that row.  Every named
struct offset, width, padding, and initialized-field rule equals its selected
layout row.  Every output region joins exactly one argument pointee by API,
argument ordinal, depth, parent-field offset, region kind, selected layout, and
declared capacity; its result order is ascending argument ordinal followed by
depth-first field offset.  An output without that input-pointee join, two
outputs for one pointee, or an omitted initialized pointee rejects.  The frame
decoder must consume all bytes exactly once.

For a `STRUCT` or `STRUCT_ARRAY` output, `payload` is exactly the member stream
in section 19.1 and `members` is its unique typed decode.  `member_bytes.size`
equals `field_size`; the output region's `initialized_length` equals the sum of
leaf `field_size` values; and `payload.size` equals the complete framed stream,
so the two lengths are intentionally not aliases.  `pollfd.revents`, each
`statx_timestamp` member, and ABI-specific `kernel_stat` fields retain exact
offsets and widths without reading reserved or padding bytes.  A missing,
duplicate, or reordered member, a raw whole-output struct copy, a zero-filled
approximation of unread bytes, or a field value without its complete prefix
rejects.

```text
call_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_NATIVE_CALL_V4",ordinal,
  arguments_bytes,arguments,result_bytes,result,encoder_inputs}))
call_id = "pfg3vnc-" || call_sha256[0:32]
```

The section-18 observation and persisted-byte formulas remain effective except
that calls resolve the R3.5 `PROGRAM_FACTS_G3_VECTOR_NATIVE_CALL_V4` type.
Pointer addresses evidence the immediate call
boundary only; semantic comparison uses pointee bytes and never treats an
address as a stable cross-process identity.  Missing recursion, extra output,
combined return/errno, stale suffix bytes, an uninitialized field, or any
signature/binding/layout digest mismatch rejects.  Every reachable confirmed,
uncertain, and no-spawn post-operation instance contains both
`native_execution_authority` and
`native_execution_receipt`; the former's embedded receipt is parsed-value equal
to the latter.  Thus authority and receipt are mandatory reachable evidence,
not side declarations.  Their all-false stable-draft state can reject or
quarantine evidence but cannot enable execution.

### 19.5 Materialized three-rule Landlock policy

The section-18.1 Landlock object is replaced in full.  The effective policy
contains the three root selectors and the three path-beneath rules, rather than
only global and per-root mask prose:

```text
vector_landlock_system_rule =
O(ordinal:C(0),root_ordinal:C(0),root_kind:C("SYSTEM_RUNTIME_READ_ONLY"),
  root:R(directory_locator),root_template:C(null),
  rule_type:C("LANDLOCK_RULE_PATH_BENEATH"),rule_type_u32:C(1),
  parent_fd_role:C("SYSTEM_RUNTIME_O_PATH_FD"),
  attribute_layout:C("landlock_path_beneath_attr"),
  allowed_access_fs:C(["EXECUTE","READ_FILE","READ_DIR"]),
  allowed_access_fs_u64_hex:C("000000000000000d"))

vector_landlock_input_rule =
O(ordinal:C(1),root_ordinal:C(1),root_kind:C("INPUT_SNAPSHOT_READ_ONLY"),
  root:R(directory_locator),root_template:C(null),
  rule_type:C("LANDLOCK_RULE_PATH_BENEATH"),rule_type_u32:C(1),
  parent_fd_role:C("INPUT_SNAPSHOT_O_PATH_FD"),
  attribute_layout:C("landlock_path_beneath_attr"),
  allowed_access_fs:C(["READ_FILE","READ_DIR"]),
  allowed_access_fs_u64_hex:C("000000000000000c"))

vector_landlock_operation_rule =
O(ordinal:C(2),root_ordinal:C(2),root_kind:C("OPERATION_PRIVATE_WRITABLE"),
  root:C(null),root_template:C("STATIC_OPERATION_PRIVATE_TREE"),
  rule_type:C("LANDLOCK_RULE_PATH_BENEATH"),rule_type_u32:C(1),
  parent_fd_role:C("OPERATION_PRIVATE_O_PATH_FD"),
  attribute_layout:C("landlock_path_beneath_attr"),
  allowed_access_fs:C(["WRITE_FILE","READ_FILE","READ_DIR","REMOVE_DIR",
  "REMOVE_FILE","MAKE_DIR","MAKE_REG","REFER","TRUNCATE"]),
  allowed_access_fs_u64_hex:C("00000000000061be"))

vector_landlock_rule =
U(R(vector_landlock_system_rule),R(vector_landlock_input_rule),
  R(vector_landlock_operation_rule))

vector_landlock_policy_preimage =
O(domain:C("PROGRAM_FACTS_G3_VECTOR_LANDLOCK_POLICY_V4"),
  uapi_source_commit:C("2e05544060b9fef5d4d0e0172944e6956c55080f"),
  required_minimum_abi:C(10),
  abi_query_flags_u32_hex:C("00000001"),
  create_ruleset_flags_u32_hex:C("00000000"),
  add_rule_flags_u32_hex:C("00000000"),
  restrict_self_flags_u32_hex:C("00000008"),
  no_new_privs_required:C(true),
  handled_access_fs:C(["EXECUTE","WRITE_FILE","READ_FILE","READ_DIR",
  "REMOVE_DIR","REMOVE_FILE","MAKE_CHAR","MAKE_DIR","MAKE_REG",
  "MAKE_SOCK","MAKE_FIFO","MAKE_BLOCK","MAKE_SYM","REFER","TRUNCATE",
  "IOCTL_DEV","RESOLVE_UNIX"]),
  handled_access_fs_u64_hex:C("000000000001ffff"),
  handled_access_net:C(["BIND_TCP","CONNECT_TCP","BIND_UDP",
  "CONNECT_SEND_UDP"]),handled_access_net_u64_hex:C("000000000000000f"),
  scoped:C(["ABSTRACT_UNIX_SOCKET","SIGNAL"]),
  scoped_u64_hex:C("0000000000000003"),
  quiet_access_fs_u64_hex:C("0000000000000000"),
  quiet_access_net_u64_hex:C("0000000000000000"),
  quiet_scoped_u64_hex:C("0000000000000000"),
  roots:T(R(vector_system_runtime_root_policy),
    R(vector_input_snapshot_root_policy),R(vector_operation_private_root_policy)),
  root_row_count:C(3),root_row_stream_size_bytes:I(1,16777216),
  root_row_stream_sha256:HEX,root_policy_object_sha256:HEX,
  rules:A(R(vector_landlock_rule),3,3,true),
  rule_row_count:C(3),rule_row_stream_size_bytes:I(1,16777216),
  rule_row_stream_sha256:HEX,allowed_network_rules:C([]),no_best_effort:C(true),
  policy_preimage_sha256:HEX)
```

`vector_landlock_rule` is therefore reachable from the transaction-root graph
through each of the three rule tuple members.  The exact formulas are:

```text
root_row_stream = CONCAT(CJ(roots[i]) || LF for i in ordinal order 0,1,2)
root_row_stream_size_bytes = len(root_row_stream)
root_row_stream_sha256 = SHA-256(root_row_stream)
root_policy_object_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_ROOT_POLICY_OBJECT_V1",
  root_row_count,root_row_stream_size_bytes,root_row_stream_sha256,roots}))
rule_row_stream = CONCAT(
  CJ(rules[i]) || LF for i in ordinal order 0,1,2)
rule_row_stream_size_bytes = len(rule_row_stream)
rule_row_stream_sha256 = SHA-256(rule_row_stream)
policy_preimage_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_LANDLOCK_POLICY_PREIMAGE_V4",
  uapi_source_commit,required_minimum_abi,abi_query_flags_u32_hex,
  create_ruleset_flags_u32_hex,add_rule_flags_u32_hex,
  restrict_self_flags_u32_hex,no_new_privs_required,
  handled_access_fs,handled_access_fs_u64_hex,
  handled_access_net,handled_access_net_u64_hex,scoped,scoped_u64_hex,
  quiet_access_fs_u64_hex,quiet_access_net_u64_hex,quiet_scoped_u64_hex,
  roots,root_row_count,root_row_stream_size_bytes,root_row_stream_sha256,
  root_policy_object_sha256,rules,rule_row_count,
  rule_row_stream_size_bytes,rule_row_stream_sha256,
  allowed_network_rules,no_best_effort}))
```

Each rule's root selector is parsed-value equal to the root with the same
ordinal and kind.  At application, its `parent_fd_role` resolves to the retained
no-follow `O_PATH` handle for that one root, and the packed 12-byte attribute is
exactly `u64le(allowed_access_fs) || s32le(parent_fd)`.  The exact native call
uses signature row 15 and flags zero.  ABI discovery uses row 13 with null attr,
size zero, and `LANDLOCK_CREATE_RULESET_VERSION` (`1`); ruleset creation uses
row 14 with the exact 48-byte six-field attribute, size 48, and flags zero.
After all three rules are installed, `prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)` must
succeed before row 16 restricts with exactly `LANDLOCK_RESTRICT_SELF_TSYNC`
(`8`).  Each return, immediate errno, argument frame, and postcondition is
persisted; a partial rule set, unsupported ABI, nonzero quiet mask, flag
substitution, or failed ordering step grants no spawn.  The rule and root
rosters are complete, duplicate-free, and ordered; omission, substitution,
reordering, a root/rule mismatch, a mask disagreement, a fourth rule, or a
network rule rejects before restriction.

The effective mount policy uses the same four root fields and contains
`root_policy_object_sha256`; the ambiguous section-18 spellings
`root_roster_sha256` and the blanket statement that every mount digest is a row
stream digest are superseded.  A consumer expecting a policy-object digest may
accept only `root_policy_object_sha256`; a consumer expecting the roster stream
may accept only `root_row_stream_sha256`.  Neither value can be copied into the
other field, and the policy-object preimage explicitly joins the stream size,
stream digest, count three, and exact three roots.

### 19.6 Non-self-referential spawn-uncertainty digest

The effective `vector_spawn_uncertainty_observation` remains the section-18.3
object, but `observation_sha256` is no longer unconstrained.  It is exactly:

```text
observation_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_VECTOR_SPAWN_UNCERTAINTY_OBSERVATION_V2",
  observation:{
    classification,capture_operation_id,attempt_ordinal,spawn_arm,
    containment_instance,actual_process,pid,process_start_identity,
    pidfd_identity,clone_result,kill_requested,empty_first,empty_second,
    poll_barrier_between,child_handles_open,operation_private_tree_writers,
    journaled_status_current,journaled_authorization_current,run_paths,
    replay_allowed,post_operation}}))
```

The inner preimage object has exactly those 21 nondigest members under `CJ`.
The full observation schema has 22 fields only when its separately computed
`observation_sha256` field is included.  The preimage excludes exactly
that digest field and includes every other field, including the three
distinct native-observation wrappers and complete uncertain post-operation
object.  It contains no observation ID, quarantine ID, path derived from either
ID, or review output.  A copied hash, wrong domain, omitted member, substituted
wrapper, or attempted self-inclusion rejects.  `post_operation` remains parsed-
value equal to the process-basis member, so the formula cannot be satisfied
with a different cleanup branch.
The exact preimage key set, sorted as Unicode code points by `CJ`, is
`[actual_process,attempt_ordinal,capture_operation_id,child_handles_open,
classification,clone_result,containment_instance,empty_first,empty_second,
journaled_authorization_current,journaled_status_current,kill_requested,
operation_private_tree_writers,pid,pidfd_identity,poll_barrier_between,
post_operation,process_start_identity,replay_allowed,run_paths,spawn_arm]`.
The embedded self-check in section 19.10 compares this 21-member set and
rejects an addition, omission, digest self-inclusion, or alternative ordering.

### 19.7 Closed 14-state lifecycle universe

The lifecycle transition universe is exactly these 14 states in order:

```text
[INTENT_DURABLE,ATTEMPT_PREPARED,CONTAINMENT_READY,SPAWN_ARMED,STATUS_BOUND,
 CHILD_OBSERVED,CANDIDATE_STAGED,CANDIDATE_PUBLISHED,RECEIPT_STAGED,
 RECEIPT_PUBLISHED,COMPLETION_STAGED,COMMITTED,ADOPTED,QUARANTINED]
```

The ordinary artifact-state matrix remains exactly the 13 section-17.6 rows
from `INTENT_DURABLE` through `ADOPTED`, each with 17 slots.  `QUARANTINED` is a
separate terminal artifact family represented by the 11 exact source-prefix
branches for the pre-commit states `INTENT_DURABLE` through
`COMPLETION_STAGED`; it has no ordinary 17-slot row and no outgoing edge.
Transition validation nevertheless enumerates the full 14 x 14 ordered-pair
universe.  The legal relation is exactly 12 adjacent ordinary edges plus those
11 source-to-`QUARANTINED` edges, 23 total.  The rejected complement is exactly
`196 - 23 = 173` pairs.  No state is simultaneously inside and outside the
enumerated domain, and an absent artifact row cannot make an otherwise illegal
transition disappear.

Accordingly, every effective occurrence of `13-by-13`, `169 ordered pairs`, or
`146-pair complement` in section 18.5 and LRC2-46 is replaced by `14-by-14`,
`196 ordered pairs`, and `173-pair complement`.  References to the 13 x 17
ordinary artifact matrix remain unchanged.  The validator separately proves
the 14-state transition enumeration, 13 ordinary matrix rows, 11 quarantine
prefixes, terminal no-outgoing-edge property, and their exact joins.

### 19.8 Windows process-crash rename-buffer closure

The non-authoritative Windows process-crash branch is further narrowed to
`WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2`.  This is not a power-loss or
accepting profile.  Its variable-length `FILE_RENAME_INFO` allocation is exact:

```text
flags_offset                 = 0;  flags_size = 4; flags = 0
alignment_padding_offset     = 4;  alignment_padding_size = 4; bytes = 00*4
RootDirectory_offset         = 8;  RootDirectory_size = 8; value = NULL; bytes = 00*8
FileNameLength_offset        = 16; FileNameLength_size = 4
FileName_offset              = 20
FileNameLength               = destination_full_absolute_utf16le.size_bytes
terminator_offset            = 20 + FileNameLength
terminator_size              = 2;  terminator_bytes = 0000
allocation_alignment         = 8
allocation_size              = ALIGN_UP(20 + FileNameLength + 2, 8)
tail_zero_length             = allocation_size - (20 + FileNameLength + 2)
information_class            = FileRenameInfoEx
information_class_u32        = 22
```

The whole `allocation_size` buffer is zero-initialized before fields are set.
`FileNameLength` excludes the terminator.  `destination_full_absolute_utf16le`
is the exact pre-bound full absolute extended-length volume path, beginning
with the UTF-16 spelling `\\?\Volume{<lowercase-guid>}\`, ending in the exact
bound destination leaf, and containing no NUL, forward slash, `.` or `..`
component, alternate data-stream colon, trailing dot/space component, DOS 8.3
alias, or unbound case/normalization variant.  The retained destination-parent
handle and its canonical `FILE_ID_INFO` are still evidence inputs, but they are
not placed in the rename buffer.  The path prefix's volume GUID must resolve to
that parent handle's volume and the parent prefix must reopen to its exact file
ID before the call.  Bytes `[20,20+FileNameLength)` are exactly the full path,
the next two bytes are zero, and every alignment-tail byte is zero.  Any
relative leaf, non-NULL `RootDirectory`, allocation of only
`20+FileNameLength`, `sizeof(FILE_RENAME_INFO)+FileNameLength`, missing explicit
terminator/tail, nonzero flag/padding/tail, or different full path rejects
before `SetFileInformationByHandle(FileRenameInfoEx,...)`.

The exact typed request and the two disjoint outcome envelopes are:

```text
vector_windows_rename_request =
O(profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  information_class:C("FileRenameInfoEx"),information_class_u32:C(22),
  source_handle:R(handle_identity),source_file_id:R(windows_file_identity),
  source_full_absolute_utf16le:R(vector_exact_native_bytes),
  destination_parent_handle:R(handle_identity),
  destination_parent_file_id:R(windows_file_identity),
  destination_full_absolute_utf16le:R(vector_exact_native_bytes),
  destination_leaf_utf16le:R(vector_exact_native_bytes),
  root_directory_u64:C(0),file_name_length_u32:I(2,16777216),
  allocation_size:I(24,16777216),input_buffer:R(vector_exact_native_bytes),
  request_sha256:HEX)

vector_windows_rename_returned =
O(completion_kind:C("RETURNED"),request:R(vector_windows_rename_request),
  bool_return:E(0,1),error_valid:B,last_error_captured_immediately:I(0,4294967295),
  retained_source_handle_file_id_after:R(windows_file_identity),
  source_name_observation:R(vector_native_observation_record),
  source_name_absent:B,destination_reopen_observation:R(vector_native_observation_record),
  destination_reopened_file_id:Q(R(windows_file_identity)),
  destination_parent_file_id_after:R(windows_file_identity),
  poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  postcondition_sha256:HEX)

vector_windows_rename_no_return =
O(completion_kind:C("NO_RETURN"),reason:C("PROCESS_CRASH"),
  request:R(vector_windows_rename_request),result_frame:C(null),
  crash_seam:E("BEFORE_ENTRY","DURING_CALL","AFTER_EFFECT_BEFORE_RETURN",
    "AFTER_RETURN_BEFORE_ERROR_CAPTURE","DURING_POSTSTATE",
    "AFTER_POSTSTATE_BEFORE_JOURNAL"),
  fresh_source_name_observation:R(vector_native_observation_record),
  fresh_destination_observation:R(vector_native_observation_record),
  poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  reconciliation_sha256:HEX)
```

For `bool_return=0`, `error_valid=true` and `GetLastError` is copied immediately;
for `bool_return=1`, `error_valid=false` and the raw slot is recorded but never
interpreted as failure.  `SetLastError(ERROR_SUCCESS)` occurs immediately before
entry.  A no-return envelope contains no BOOL, last-error interpretation, or
output buffer.  Every hash above uses `SHA-256(CJ({domain:<the matching R3.5
domain>,all preceding members except the hash}))`; the exact domain strings are
`PROGRAM_FACTS_G3_WINDOWS_RENAME_REQUEST_V2`,
`PROGRAM_FACTS_G3_WINDOWS_RENAME_POSTCONDITION_V2`, and
`PROGRAM_FACTS_G3_WINDOWS_RENAME_RECONCILIATION_V2`.

The BOOL return is never sufficient proof of the move.  On reported success,
the supervisor reopens the exact full absolute destination without following
reparse points, captures `FILE_ID_INFO`, and requires it and the still-retained
source handle identity to equal the pre-call source volume/file ID.  It also
proves the exact source name absent, the destination parent identity unchanged,
and the destination leaf equal to the bound leaf.  These are conjuncts of
`EXPECTED_EFFECT`; source present plus destination absent is `NO_EFFECT`; any
other reachable identity/name combination is `WRONG_EFFECT`; inability to
complete either observation is `UNOBSERVABLE`.  Success that consumed adjacent
bytes, created another name, left the expected leaf absent, or returned a
different identity is `WINDOWS_RENAME_POSTCONDITION_MISMATCH`.  It cannot
publish progress or completion and enters repair-then-degrade quarantine.

This Windows profile proves process-crash reconciliation only.  It supplies no
ordinary-user parent-directory namespace flush, protected-root volume flush,
or power-loss barrier.  `FlushFileBuffers` on the payload, a successful rename,
MoveFileEx/ReplaceFileW flags, an administrator-only volume handle, a stress
run, or any receipt boolean cannot manufacture durability.  Therefore Windows
`durability_authority`, `can_publish_move_durable`, and `accepting_authority`
remain false.  macOS remains `UNAVAILABLE`; only the separately materialized
Linux same-mount retained-directory-handle barrier profile may ever carry
power-loss authority, still below the all-false stable-draft ceiling here.

### 19.9 Native-FFI execution authority and total outcomes

The R3.4 `GOVERNED_EXECUTION` branch with
`production_execution_allowed:true` is deleted.  Header/layout evidence,
ordinary host semantics, governed instrumentation, and stress evidence are four
disjoint classes; none is an execution or durability capability in this stable
draft:

```text
vector_native_static_layout_evidence =
O(evidence_class:C("STATIC_LAYOUT"),build_manifest:R(vector_native_build_manifest),
  layout_oracle:R(file_identity),layout_oracle_binary:R(file_identity),
  layout_oracle_review:R(vector_native_review_record),compile_receipt:R(file_identity),
  static_assertion_roster_sha256:HEX,host_semantics_proved:C(false),
  crash_timing_proved:C(false),durability_proved:C(false),authoritative:C(false))

vector_native_host_semantics_evidence =
O(evidence_class:C("HOST_SEMANTICS"),fixture_source:R(file_identity),
  fixture_binary:R(file_identity),executed_production_binary:R(file_identity),
  platform_host_identity:R(file_identity),ordinary_call_results:R(file_identity),
  ordinary_result_roster_sha256:HEX,layout_only:C(false),
  crash_timing_proved:C(false),durability_proved:C(false),authoritative:C(false))

vector_native_governed_instrumentation_evidence =
O(evidence_class:C("GOVERNED_INSTRUMENTATION"),facility_kind:E(
    "LINUX_FAULT_INJECTION_PROFILE","WINDOWS_DEBUGGER_SUSPEND_PROFILE"),
  facility_source:R(file_identity),facility_binary:R(file_identity),
  facility_configuration:R(file_identity),facility_review:R(vector_native_review_record),
  platform_host_identity:R(file_identity),
  seam_roster_sha256:HEX,seam_results:R(file_identity),
  executed_production_binary:R(file_identity),stress_only:C(false),
  durability_proved:C(false),authoritative:C(false))

vector_native_stress_evidence =
O(evidence_class:C("STRESS_NONAUTHORITATIVE"),runner:R(file_identity),
  iterations:I(1,9007199254740991),results:R(file_identity),
  completeness_claim:C(false),timing_authority:C(false),
  durability_proved:C(false),authoritative:C(false))
```

Static assertions and SDK/header presence prove layout only.  Ordinary host
calls prove only the observed semantics of those calls.  A crash seam is
evidenced only by an exact governed instrumentation profile; if no reviewed
facility can deterministically stop that seam, its matrix row is retained as
`UNAVAILABLE_WITH_REASON`, not simulated or satisfied by stress.  Stress may
discover defects but can never close a cell.  No class may be substituted for
another or combined to infer a stronger class.

The exact receipt is reachable through the authority object carried by every
`vector_native_call`:

```text
vector_native_semantic_projection =
O(projection_kind:E("CALL_LOCAL_OUTPUT","FILESYSTEM_NAMESPACE",
    "FILE_CONTENT_AND_OFFSET","MOUNT_GRAPH","PROCESS_ATTRIBUTE",
    "FILTER_OR_RULESET_STATE","DESCRIPTOR_SET","PROCESS_TREE",
    "SIGNAL_STATE","WINDOWS_RENAME_IDENTITY"),
  typed_projection:R(file_identity),canonical_bytes:R(content_identity),
  complete:B,projection_sha256:HEX)

vector_native_semantic_case =
O(api:S1,profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  postcondition_id:S1,request_template:R(file_identity),
  durable_prestate:R(vector_native_semantic_projection),
  expected_effect:R(vector_native_semantic_projection),
  no_effect:R(vector_native_semantic_projection),
  expected_and_no_effect_disjoint:C(true),
  derivation_oracle:R(file_identity),
  derivation_oracle_review:R(vector_native_review_record),case_sha256:HEX)

vector_native_platform_outcome_envelope =
U(R(vector_native_call),R(vector_native_no_return_envelope),
  R(vector_windows_rename_returned),R(vector_windows_rename_no_return))

vector_native_outcome_result =
O(matrix_ordinal:I(0,719),api_profile_ordinal:I(0,44),cell_ordinal:I(0,15),
  api:S1,profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  semantic_case:R(vector_native_semantic_case),
  availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  evidence_class:Q(E("HOST_SEMANTICS","GOVERNED_INSTRUMENTATION")),
  evidence:Q(R(file_identity)),typed_outcome:Q(R(vector_native_platform_outcome_envelope)),
  unavailable_reason:Q(S1),
  classification:E("API_SEMANTIC_SUCCESS","API_FAILURE_NO_RETRY",
    "RESUME_FROM_EFFECT_NO_REPLAY","RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),result_sha256:HEX)

vector_native_execution_receipt =
U(O(state:C("UNMATERIALIZED_STABLE_DRAFT"),subject:R(file_identity),
    platform:C(null),profile:C(null),platform_identity:C(null),provenance:C(null),
    static_layout:C(null),host_semantics:C(null),
    governed_instrumentation:C(null),stress:C(null),
    outcome_results:C(null),outcome_result_roster_sha256:C(null),
    atomic_contract_evidence:C(null),
    receipt_sha256:C(null),receipt_review:C(null),
    disposition:C("STABLE_DRAFT_NONAUTHORITATIVE"),authoritative:C(false),
    production_execution_allowed:C(false),spawn_allowed:C(false),
    durability_authority:C(false)),
  O(state:C("MATERIALIZED_NONAUTHORITATIVE"),subject:R(file_identity),
    platform:E("LINUX","WINDOWS"),profile:E("LINUX_X86_64_LP64_LE",
      "LINUX_AARCH64_LP64_LE","WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
    platform_identity:R(file_identity),provenance:R(vector_native_build_manifest),
    static_layout:R(vector_native_static_layout_evidence),
    host_semantics:Q(R(vector_native_host_semantics_evidence)),
    governed_instrumentation:Q(R(vector_native_governed_instrumentation_evidence)),
    stress:Q(R(vector_native_stress_evidence)),
    outcome_results:A(R(vector_native_outcome_result),720,720,true),
    outcome_result_roster_sha256:HEX,
    atomic_contract_evidence:R(vector_r3_5_atomic_evidence_bundle),
    receipt_sha256:HEX,
    receipt_review:R(vector_native_review_record),
    disposition:C("MATERIALIZED_EVIDENCE_NONAUTHORITATIVE"),authoritative:C(false),
    production_execution_allowed:C(false),spawn_allowed:C(false),
    durability_authority:C(false)))

vector_native_ffi_authority =
U(O(state:C("UNMATERIALIZED_PROVENANCE"),subject:R(file_identity),
    platform:C(null),profile:C(null),platform_identity:C(null),build_manifest:C(null),
    execution_receipt:R(vector_native_execution_receipt),
    oracle_review:C(null),implementation_review:C(null),
    independent_native_review:C(null),authority_join_sha256:C(null),
    disposition:C("STABLE_DRAFT_NONAUTHORITATIVE"),
    evidence_authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),publication_allowed:C(false),
    cutover_allowed:C(false),durability_authority:C(false)),
  O(state:C("MATERIALIZED_REVIEWED_NONAUTHORITATIVE"),
    subject:R(file_identity),platform:E("LINUX","WINDOWS"),
    profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
      "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
    platform_identity:R(file_identity),build_manifest:R(vector_native_build_manifest),
    execution_receipt:R(vector_native_execution_receipt),
    oracle_review:R(vector_native_review_record),
    implementation_review:R(vector_native_review_record),
    independent_native_review:R(vector_native_review_record),authority_join_sha256:HEX,
    disposition:C("MATERIALIZED_REVIEWED_NONAUTHORITATIVE"),
    evidence_authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),publication_allowed:C(false),
    cutover_allowed:C(false),durability_authority:C(false)))
```

The unmaterialized branch is the only branch this R3.5 stable draft can occupy:
its receipt state is also `UNMATERIALIZED_STABLE_DRAFT` and all nulls/false
values are literal.  The materialized branch is a future evidence shape, not an
enabled state.  Its profile equals the build manifest and receipt; its subject
is this exact draft; its platform identity is parsed-value equal across the
authority, receipt, host evidence, governed evidence when present, and the
review subjects; the manifest's production binary is parsed-value equal to
the receipt's executed production binary in every evidence class; the oracle
source/binary equal the oracle review subjects; the implementation review binds
the exact installed production source and binary; and the independent native
review binds the already complete receipt.  Oracle author, oracle reviewer,
production implementer, fixture author, instrumentation author, receipt author,
and independent native reviewer are pairwise distinct where their roles can
affect the same claim.  No review or receipt may review itself.

The two non-self joins are exact:

```text
outcome_result.result_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_NATIVE_OUTCOME_RESULT_V1",matrix_ordinal,
  api_profile_ordinal,cell_ordinal,api,profile,semantic_case,availability,
  evidence_class,evidence,typed_outcome,unavailable_reason,classification,
  retry_allowed:false}))
outcome_result_roster_sha256 = SHA-256(CONCAT(
  CJ(outcome_results[i]) || LF for i in matrix_ordinal order 0..719))

receipt_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_NATIVE_EXECUTION_RECEIPT_V1",subject,platform,
  profile,platform_identity,provenance,static_layout,host_semantics,governed_instrumentation,
  stress,outcome_results,outcome_result_roster_sha256,atomic_contract_evidence,
  disposition,
  authoritative:false,production_execution_allowed:false,spawn_allowed:false,
  durability_authority:false}))

authority_join_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_NATIVE_FFI_AUTHORITY_JOIN_V1",subject,platform,
  profile,platform_identity,build_manifest,execution_receipt,oracle_review,
  implementation_review,independent_native_review,
  disposition,
  evidence_authoritative:false,production_execution_allowed:false,
  spawn_allowed:false,publication_allowed:false,cutover_allowed:false,
  durability_authority:false}))
```

The receipt hash excludes `receipt_sha256` and `receipt_review`; the authority
hash excludes only `authority_join_sha256`.  A copied join, different platform
or profile, source-to-binary mismatch, oracle-to-binary mismatch, executed-
binary mismatch, reviewer reuse, or any true authority/enabling flag rejects.
A receipt records evidence; it cannot manufacture execution permission,
postcondition truth, a filesystem barrier, or durability.

The typed outcome taxonomy has 16 cells, not a crash folded into a returned
status:

```text
completion_kind RETURNED:
  return_status = [SUCCESS,FAILURE,INTERRUPTED]
  observed_poststate = [EXPECTED_EFFECT,NO_EFFECT,WRONG_EFFECT,UNOBSERVABLE]
  cell_ordinal = 4 * return_status_ordinal + poststate_ordinal       # 0..11
completion_kind NO_RETURN:
  no_return_reason = PROCESS_CRASH
  observed_poststate = [EXPECTED_EFFECT,NO_EFFECT,WRONG_EFFECT,UNOBSERVABLE]
  cell_ordinal = 12 + poststate_ordinal                              # 12..15
```

Every one of the 22 signature APIs expands over both Linux profiles, followed
by the Windows rename API, producing exactly 45 API/profile rows and 720 matrix
rows.  Each API/profile row names all 12 returned cells, all four no-return
cells, its semantic postcondition, and the required evidence class.  The closed
postcondition map is:

<!-- BEGIN VECTOR_NATIVE_POSTCONDITION_MAP_R3_5 -->
```json
[
{"api":"mkdirat","postcondition":"EXACT_DIRECTORY_LEAF_IDENTITY"},
{"api":"openat","postcondition":"EXACT_NOFOLLOW_HANDLE_IDENTITY_AND_FLAGS"},
{"api":"read","postcondition":"RETURN_COUNT_AND_INITIALIZED_PREFIX"},
{"api":"write","postcondition":"RETURN_COUNT_AND_TARGET_PREFIX_EFFECT"},
{"api":"pread64","postcondition":"RETURN_COUNT_INITIALIZED_PREFIX_AND_OFFSET_UNCHANGED"},
{"api":"readlinkat","postcondition":"RETURN_COUNT_AND_LINK_BYTES"},
{"api":"fstat","postcondition":"NAMED_KERNEL_STAT_FIELDS"},
{"api":"statx","postcondition":"NAMED_STATX_FIELDS_AND_REQUESTED_MASK"},
{"api":"mount","postcondition":"EXACT_MOUNT_GRAPH_EDGE_AND_FLAGS"},
{"api":"umount2","postcondition":"EXACT_MOUNT_GRAPH_EDGE_ABSENT"},
{"api":"pivot_root","postcondition":"EXACT_ROOT_AND_PUT_OLD_MOUNT_GRAPH"},
{"api":"prctl","postcondition":"EXACT_PROCESS_ATTRIBUTE"},
{"api":"seccomp","postcondition":"EXACT_FILTER_INSTALLED_FOR_CALLING_THREAD_SET"},
{"api":"landlock_get_abi","postcondition":"ABI_VERSION_RETURN_ONLY"},
{"api":"landlock_create_ruleset","postcondition":"RULESET_FD_AND_HANDLED_MASKS"},
{"api":"landlock_add_rule","postcondition":"EXACT_RULE_ADDED_TO_RULESET"},
{"api":"landlock_restrict_self","postcondition":"EXACT_RULESET_ENFORCED"},
{"api":"close_range","postcondition":"EXACT_DESCRIPTOR_RANGE_STATE"},
{"api":"clone3","postcondition":"EXACT_CHILD_PID_PIDFD_AND_NAMESPACE_STATE"},
{"api":"pidfd_send_signal","postcondition":"EXACT_TARGET_PROCESS_SIGNAL_STATE"},
{"api":"poll","postcondition":"RETURN_COUNT_AND_ALL_REVENTS_FIELDS"},
{"api":"unlinkat","postcondition":"EXACT_SOURCE_LEAF_ABSENT"},
{"api":"SetFileInformationByHandle.FileRenameInfoEx","postcondition":"WINDOWS_SOURCE_ABSENT_DESTINATION_FILE_ID_CONTINUITY"}
]
```
<!-- END VECTOR_NATIVE_POSTCONDITION_MAP_R3_5 -->

The postcondition IDs are executable selectors, not labels.  A semantic case's
derivation oracle is exact reviewed source independent of the production FFI
and constructs both expected projections from the durable prestate and request.
The required typed projection members for each selector are:

| selector | exact projection members |
|---|---|
| `EXACT_DIRECTORY_LEAF_IDENTITY` | parent file ID, leaf bytes, pre/post entry presence, directory type, new file ID, requested mode under controlled zero umask |
| `EXACT_NOFOLLOW_HANDLE_IDENTITY_AND_FLAGS` | path parent/leaf, pre/post namespace row, returned-FD presence, target device/inode, access/status/descriptor flags |
| `RETURN_COUNT_AND_INITIALIZED_PREFIX` | return count, exact initialized bytes, requested capacity, FD offset before/after |
| `RETURN_COUNT_AND_TARGET_PREFIX_EFFECT` | return count, exact input prefix, target device/inode, offset before/after, size and affected content range |
| `RETURN_COUNT_INITIALIZED_PREFIX_AND_OFFSET_UNCHANGED` | return count, exact initialized bytes, requested position, FD offset before/after equal |
| `RETURN_COUNT_AND_LINK_BYTES` | link parent/leaf identity, requested capacity, return count, exact non-NUL-extended link bytes |
| `NAMED_KERNEL_STAT_FIELDS` | selected ABI/layout plus every named initialized kernel-stat field in roster order |
| `NAMED_STATX_FIELDS_AND_REQUESTED_MASK` | flags/mask, returned `stx_mask`, and every named initialized statx field in roster order |
| `EXACT_MOUNT_GRAPH_EDGE_AND_FLAGS` | before/after mountinfo rows, source/target/fstype, mount ID, parent ID, propagation and exact flags |
| `EXACT_MOUNT_GRAPH_EDGE_ABSENT` | before/after mountinfo rows, target mount ID and exact absence after return |
| `EXACT_ROOT_AND_PUT_OLD_MOUNT_GRAPH` | before/after root mount ID, put-old mount ID, cwd/root handles, and full private mount graph |
| `EXACT_PROCESS_ATTRIBUTE` | prctl option/arguments and option-specific before/after process attribute bytes |
| `EXACT_FILTER_INSTALLED_FOR_CALLING_THREAD_SET` | BPF instruction identity, no-new-privs state, selected audit arch, affected thread IDs and filter identity |
| `ABI_VERSION_RETURN_ONLY` | zero attr/size, exact version flag, returned ABI integer, and no pointee output |
| `RULESET_FD_AND_HANDLED_MASKS` | returned-FD presence/identity and exact six-field handled/quiet/scoped input projection |
| `EXACT_RULE_ADDED_TO_RULESET` | ruleset FD identity, rule ordinal/type, parent FD identity, allowed mask, and resulting ordered rule-set projection |
| `EXACT_RULESET_ENFORCED` | ruleset FD identity, calling thread set, exact effective Landlock policy identity and enforcement probe projection |
| `EXACT_DESCRIPTOR_RANGE_STATE` | complete open-FD roster before/after, first/last/flags, and exact closed-or-CLOEXEC range result |
| `EXACT_CHILD_PID_PIDFD_AND_NAMESPACE_STATE` | clone request bytes, child PID/start identity, pidfd identity, cgroup and seven namespace identities, gate state |
| `EXACT_TARGET_PROCESS_SIGNAL_STATE` | pidfd identity, signal, target start identity, liveness/reap state before/after |
| `RETURN_COUNT_AND_ALL_REVENTS_FIELDS` | nfds/timeout, every input fd/events pair, every authoritative revents field, and ready-count equality |
| `EXACT_SOURCE_LEAF_ABSENT` | parent/leaf identity and no-follow source presence before/after with unrelated entries unchanged |
| `WINDOWS_SOURCE_ABSENT_DESTINATION_FILE_ID_CONTINUITY` | the complete section-19.8 source/destination name, parent, retained-handle, and `FILE_ID_INFO` conjunction |

`projection_sha256 = SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_NATIVE_SEMANTIC_PROJECTION_V1",projection_kind,
typed_projection,canonical_bytes,complete}))`; the typed projection must decode
exactly from `canonical_bytes`.  `case_sha256` uses domain
`PROGRAM_FACTS_G3_NATIVE_SEMANTIC_CASE_V1` and all preceding case members.
For each call, a fresh observation is encoded by the same selector.  It is
`UNOBSERVABLE` iff `complete=false`; otherwise it is `EXPECTED_EFFECT` iff
parsed-value equal to `expected_effect`, `NO_EFFECT` iff equal to `no_effect`,
and `WRONG_EFFECT` otherwise.  The two expected projections are required
disjoint.  The derivation review must reject a case that hides a required field,
allows the production implementation to choose expected bytes, or uses an
uncontrolled precondition.  These predicates make the matrix mutually
exclusive and per-API/profile rather than a global label checklist.

For every matrix row, `WRONG_EFFECT` has disposition `QUARANTINE`, as does
`RETURNED/SUCCESS/NO_EFFECT`.  `UNOBSERVABLE` has
`RECONCILE_NO_REPLAY`.  `NO_RETURN` has `RECONCILE_NO_REPLAY` unless fresh
poststate is `WRONG_EFFECT`, which quarantines.  `RETURNED/SUCCESS/
EXPECTED_EFFECT` is `API_SEMANTIC_SUCCESS` but may advance only after the
separate platform-required barriers.  `RETURNED/FAILURE/NO_EFFECT` is
`API_FAILURE_NO_RETRY`.  FAILURE or INTERRUPTED with EXPECTED_EFFECT is
`RESUME_FROM_EFFECT_NO_REPLAY`; INTERRUPTED with NO_EFFECT is
`RECONCILE_NO_REPLAY`.  No classification permits retry.  Mutually exclusive
completion envelopes, error-sentinel rules, postcondition predicates, and this
precedence make the table total.  An unavailable cell remains present with a
closed reason, null `evidence_class/evidence/typed_outcome`, and grants no
authority.  An evidenced row has null `unavailable_reason`, its required
evidence class, a nonnull evidence identity, and exactly one typed outcome whose
API, profile, completion kind, cell, poststate, return/error presence, and
classification equal the matrix row.  A returned Linux outcome selects
`vector_native_call`; Linux process crash selects
`vector_native_no_return_envelope`; the Windows branches select their matching
section-19.8 envelopes.  A branch substitution or a fabricated returned frame
in a no-return row rejects.

Linux clears `errno` and Windows clears last-error immediately before entry and
captures it immediately on a returned envelope, as defined in sections 19.2
and 19.8.  Crash seams are `BEFORE_ENTRY`, `AFTER_REQUEST_DURABLE`,
`DURING_CALL`, `AFTER_EFFECT_BEFORE_RETURN`,
`AFTER_RETURN_BEFORE_ERROR_CAPTURE`, `AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE`,
`DURING_POSTSTATE`, and `AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER`.  A seam
not deterministically available under reviewed governed instrumentation is
marked unavailable.  Recovery uses durable prestate and fresh exact poststate;
it never invents a return, error, initialized byte, effect, barrier, or retry.

### 19.10 Atomic evidence, diagnostic subcodes, and deterministic self-check

The 52-row/767-subcase scenario roster remains a compatibility index, not an
exhaustiveness proof.  R3.5 binds the following generated atomic rosters.  Each
is `CONCAT(CJ(row)||LF)` in increasing ordinal order and also has the listed
canonical parsed-array identity:

| roster | rows | row-stream bytes / SHA-256 | array bytes / SHA-256 |
|---|---:|---|---|
| API/profile map | 45 | 14,691 / `de8cee28aeef8f42c8edc0b2dfc7093becc464317b74cf42f2c2cbec9826f732` | 14,692 / `b22f5e0c88bc72e91c17e61b733b95811ac2453f25fc226c3378477840cc13af` |
| outcome cells | 16 | 3,145 / `c41c525c23c5cc787adc1267e941b44a6f6e9a9cece21306c3b7b6167420418e` | 3,146 / `b50bc11fed307d331ee5a23092d70b12b06fa5fdfdfbe6a16c8bfecf0e49a72b` |
| per-API/profile outcome matrix | 720 | 197,731 / `f36d9f26538a425f6e208ce75200a7c724816dfc8d2e0ed5829004f976f922ef` | 197,732 / `d3d2c11308906280de42755430c5ce173e056063495c20a61c5baf3f21711627` |
| lifecycle ordered pairs | 196 | 22,339 / `f84e0f7f0b5b2055caeff49ee2c22109ecc33577aba40d561270b6d9c89cc956` | 22,340 / `bfdebe94d5205f233f8dd2b3aefaee8167a931359404c8370651859c77dc2239` |
| ordinary matrix members | 221 | 37,632 / `0de0d1ba4c43c09c4b21b5c2b29f8e9334c5ef2a01bebf55afa7c1abee01af8c` | 37,633 / `ec570a6c6ee90578e690f8b038fd1d98889928def2d3dd21502640610ef79343` |
| ordinary member mutations | 442 | 60,014 / `e8f315ae8b02f699cf0692d11491d507f595233b5e664babe286d1bad6ab2098` | 60,015 / `82446634fbb0bd5ab8a1079ea94a0cfb45c42110314a1081173495c1ca899e1c` |
| quarantine-prefix members | 187 | 34,624 / `6f92d0cfe189061de6b59140a5f4b16f9936576602fbc7ebe083125fb670dabb` | 34,625 / `ea82442fa0eb5850cc92a6cd83d0bd48531f265ee09d0a075dff06f218f564ad` |
| quarantine member mutations | 374 | 53,743 / `609ad22c8bbea2c32566d847289da0f76d444c3514590fd88860168ee274b867` | 53,744 / `d4d7877eb11f2d80772298b55cdf4814aca6d96dca8f3f0fbe3ecc377df52c1b` |
| LRC2-47 diagnostic atoms | 68 | 14,684 / `ae6bffd1a2cea807ec7a6c00a9e1e72db4c786772867a019a7f7e78d9480b056` | 14,685 / `530955382e768bf8381a43ab5f7b94f6b7da2eec7a9e39261e2733fb19c1249c` |
| signature/dependency negative atoms | 13 | 2,008 / `59cb04f236a1aee4a0d051fc944d326e9c1bf5003345a3446a03aadfe232b171` | 2,009 / `e037d8a852310b0ed66c922d96a0f862b203bf3983ed5610309c23863d597192` |
| Windows rename negative atoms | 10 | 1,507 / `97fcbad018aa862f7c5916826b8aebec53c8f27f10fc7be902bdda3359f2f800` | 1,508 / `af923df3da9d56575cfcbf067cf20dcee1ad011cac6fc1acf70a28c73df20d92` |

The lifecycle roster contains all 196 ordered pairs, not just one umbrella
negative: 12 are `LEGAL_ADJACENT`, 11 are `LEGAL_QUARANTINE`, and 173 are
`REJECT_STATE_EDGE_ILLEGAL`.  The ordinary member roster covers 13 x 17 exact
members; its mutation roster tries each of the other two slot values, 442
atoms.  The quarantine roster covers 11 x 17 exact source-prefix members and
its 374 alternative values.  Each result joins one ordinal and exact roster-row
hash.  Reporting an umbrella LRC2-46 label without every joined nested result
rejects.

LRC2-47 retains `CONTAINMENT_POLICY_IDENTITY` as its compatibility error code,
but its 68 atoms require these closed subcodes after all earlier-precedence
checks are held valid: `0..2 POLICY_ARTIFACT_BYTES`, `3..5
ROOT_AND_HANDLE_ROSTER`, `6..9 POLICY_SEMANTICS`, `10..17
CGROUP_AND_NATIVE_OBSERVATION`, `18..22 SUCCESS_ROOT_JOIN`, `23..26
MOUNT_ROOT_POLICY`, `27..32 LANDLOCK_SEMANTICS`, `33..37
SECCOMP_SEMANTICS`, `38..39 POLICY_MATERIALIZATION`, `40..43
NATIVE_FRAME_AND_IDENTITY`, `44..47 POST_OPERATION_JOIN`, `48..54
NATIVE_ABI_FRAME_PROVENANCE`, `55..59 LANDLOCK_RULE_ROSTER`, `60..63
FFI_AUTHORITY_PROVENANCE`, `64 OUTCOME_MATRIX_TOTALITY`, `65
IMMEDIATE_ERROR_CAPTURE`, `66 NO_RETRY_RECONCILIATION`, and `67
CRASH_SEAM_EVIDENCE`.  A generic rejection without the expected subcode fails.
Within that immutable compatibility row, mutation 60's old state names mean any
true authority/enabling field in either R3.5 authority or receipt branch;
mutation 64's phrase "twelve cells" means the 12 returned-call taxonomy rows
and does not omit the four separately required no-return rows.  The 720-row
nested roster is controlling.  LRC2-44's Windows rename umbrellas bind all ten
Windows negative atoms, including relative `FileName` and non-NULL
`RootDirectory`; exercising only its older flag/allocation wording cannot pass.

The exact nested result denominator is 1,823: 720 outcome, 196 lifecycle, 442
ordinary-matrix mutation, 374 quarantine-prefix mutation, 68 diagnostic, 13
signature/dependency negative, and 10 Windows negative results.  Expected-value
rosters (221 ordinary and 187 quarantine members) are contract inputs and are
not double-counted as executed mutations.

```text
vector_r3_5_atomic_result =
O(roster_kind:E("OUTCOME_MATRIX","LIFECYCLE_PAIR","ORDINARY_MEMBER_MUTATION",
    "QUARANTINE_MEMBER_MUTATION","LRC2_47_DIAGNOSTIC",
    "SIGNATURE_DEPENDENCY_NEGATIVE","WINDOWS_RENAME_NEGATIVE"),
  roster_ordinal:I(0,719),roster_row_sha256:HEX,
  result:E("PASS_EXPECTED_ACCEPTANCE","PASS_EXPECTED_REJECTION",
    "UNAVAILABLE_WITH_REASON"),diagnostic_code:Q(S1),
  diagnostic_subcode:Q(S1),evidence:Q(R(file_identity)),
  unavailable_reason:Q(S1),result_sha256:HEX)

vector_r3_5_atomic_evidence_bundle =
O(contract_subject:R(file_identity),scenario_row_stream_sha256:HEX,
  outcome_matrix_sha256:HEX,lifecycle_pair_sha256:HEX,
  ordinary_member_mutation_sha256:HEX,quarantine_member_mutation_sha256:HEX,
  diagnostic_atom_sha256:HEX,signature_negative_sha256:HEX,
  windows_negative_sha256:HEX,
  results:A(R(vector_r3_5_atomic_result),1823,1823,true),
  result_roster_sha256:HEX,bundle_sha256:HEX)
```

The bundle's roster digests equal the constants above; each `(roster_kind,
roster_ordinal)` occurs exactly once; each `roster_row_sha256` is the hash of its
exact generated row; and the 720 OUTCOME_MATRIX results are parsed-value equal
to the execution receipt's outcome results by ordinals, availability,
classification, and evidence.  `bundle_sha256` excludes itself and is the hash
of the domain `PROGRAM_FACTS_G3_R3_5_ATOMIC_EVIDENCE_BUNDLE_V1` plus all prior
members.  An unavailable result must carry a reason and null evidence; a passed
result must carry evidence and null reason.  No top-level scenario pass can
stand in for a missing atom.

The following bounded self-check is normative deterministic material embedded
in this draft.  It reads only the subject path supplied as its single argument,
executes no launcher or native call, and writes no file:

<!-- BEGIN R3_5_DETERMINISTIC_SELF_CHECK -->
```python
import collections, hashlib, json, re, sys
from pathlib import Path

subject = Path(sys.argv[1])
raw = subject.read_bytes()
assert b"\r" not in raw
text = raw.decode("utf-8")

def extract(name):
    match = re.search(
        rf"<!-- BEGIN {name} -->\n```json\n(.*?)\n```\n<!-- END {name} -->",
        text, re.S)
    assert match, name
    return json.loads(match.group(1))

def cj(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)

def identity(rows):
    stream = "".join(cj(row) + "\n" for row in rows).encode()
    array = cj(rows).encode()
    return (len(rows), len(stream), hashlib.sha256(stream).hexdigest(),
            len(array), hashlib.sha256(array).hexdigest())

signatures = extract("VECTOR_NATIVE_SIGNATURE_ROSTER_R3_5")
layouts = extract("VECTOR_NATIVE_LAYOUT_ROSTER_R3_5")
scenarios = extract("PARITY_SCENARIO_ROSTER_R3_5")
postconditions = extract("VECTOR_NATIVE_POSTCONDITION_MAP_R3_5")
bindings = [{"abi_profiles":["LINUX_X86_64_LP64_LE",
                              "LINUX_AARCH64_LP64_LE"],
             "call_layer":"LIBC_SYSCALL_REGISTER_WORDS_V1",
             "error_convention":"LIBC_MINUS1_ERRNO_V1","row":row}
            for row in signatures]

expected_encodings = {
    ("mkdirat","mode"):"U16_LE", ("openat","mode"):"U16_LE",
    ("read","fd"):"U32_LE", ("write","fd"):"U32_LE",
    ("pread64","fd"):"U32_LE", ("fstat","fd"):"U32_LE",
    ("statx","flags"):"U32_LE"}
actual_encodings = {(row["api"], arg["name"]):arg["encoding"]
                    for row in signatures for arg in row["args"]}
assert all(actual_encodings[key] == value
           for key, value in expected_encodings.items())

postcondition_by_api = {row["api"]:row["postcondition"]
                        for row in postconditions}
profiles = []
for signature in signatures:
    for profile in ["LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"]:
        profiles.append({"api":signature["api"],
          "api_profile_ordinal":len(profiles),
          "no_return_cells":[12,13,14,15],
          "postcondition":postcondition_by_api[signature["api"]],
          "profile":profile,
          "required_evidence":{"no_return":"GOVERNED_INSTRUMENTATION",
                               "returned":"HOST_SEMANTICS"},
          "returned_cells":list(range(12)),"stress_authoritative":False})
windows_api = "SetFileInformationByHandle.FileRenameInfoEx"
profiles.append({"api":windows_api,"api_profile_ordinal":44,
  "no_return_cells":[12,13,14,15],
  "postcondition":postcondition_by_api[windows_api],
  "profile":"WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2",
  "required_evidence":{"no_return":"GOVERNED_INSTRUMENTATION",
                       "returned":"HOST_SEMANTICS"},
  "returned_cells":list(range(12)),"stress_authoritative":False})

poststates = ["EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"]
statuses = ["SUCCESS","FAILURE","INTERRUPTED"]
def classification(kind, status, poststate):
    if poststate == "WRONG_EFFECT": return "QUARANTINE"
    if kind == "RETURNED" and status == "SUCCESS" and poststate == "NO_EFFECT":
        return "QUARANTINE"
    if poststate == "UNOBSERVABLE" or kind == "NO_RETURN":
        return "RECONCILE_NO_REPLAY"
    if status == "SUCCESS": return "API_SEMANTIC_SUCCESS"
    if status == "FAILURE" and poststate == "NO_EFFECT":
        return "API_FAILURE_NO_RETRY"
    if poststate == "EXPECTED_EFFECT": return "RESUME_FROM_EFFECT_NO_REPLAY"
    return "RECONCILE_NO_REPLAY"

cells = []
for status in statuses:
    for poststate in poststates:
        cells.append({"cell_ordinal":len(cells),
          "classification":classification("RETURNED",status,poststate),
          "completion_kind":"RETURNED","no_return_reason":None,
          "observed_poststate":poststate,"retry_allowed":False,
          "return_status":status})
for poststate in poststates:
    cells.append({"cell_ordinal":len(cells),
      "classification":classification("NO_RETURN",None,poststate),
      "completion_kind":"NO_RETURN","no_return_reason":"PROCESS_CRASH",
      "observed_poststate":poststate,"retry_allowed":False,
      "return_status":None})

outcomes = []
for profile in profiles:
    for cell in cells:
        outcomes.append({"api":profile["api"],
          "api_profile_ordinal":profile["api_profile_ordinal"],
          "cell_ordinal":cell["cell_ordinal"],
          "classification":cell["classification"],
          "evidence_class_required":("HOST_SEMANTICS" if
             cell["completion_kind"] == "RETURNED" else
             "GOVERNED_INSTRUMENTATION"),
          "matrix_ordinal":len(outcomes),
          "postcondition":profile["postcondition"],
          "profile":profile["profile"],"retry_allowed":False})

states = ["INTENT_DURABLE","ATTEMPT_PREPARED","CONTAINMENT_READY",
 "SPAWN_ARMED","STATUS_BOUND","CHILD_OBSERVED","CANDIDATE_STAGED",
 "CANDIDATE_PUBLISHED","RECEIPT_STAGED","RECEIPT_PUBLISHED",
 "COMPLETION_STAGED","COMMITTED","ADOPTED","QUARANTINED"]
pairs = []
for source_ordinal, source in enumerate(states):
    for target_ordinal, target in enumerate(states):
        disposition = ("LEGAL_ADJACENT" if source_ordinal < 12 and
                       target_ordinal == source_ordinal + 1 else
                       "LEGAL_QUARANTINE" if source_ordinal <= 10 and
                       target_ordinal == 13 else "REJECT_STATE_EDGE_ILLEGAL")
        pairs.append({"disposition":disposition,"from_state":source,
                      "ordinal":len(pairs),"to_state":target})

slots = ["intent","attempt","containment_instance","spawn_arm",
 "control_record","status_record","authorization_record","observation",
 "stdout_spool","stderr_spool","candidate_stage","candidate_final",
 "receipt_stage","receipt_final","completion_stage","completion_final",
 "quarantine"]
matrix = ["C"+"A"*16,"CC"+"A"*15,"CCC"+"A"*14,"CCCC"+"A"*13,
 "C"*7+"A"*10,"C"*10+"A"*7,"C"*11+"A"*6,
 "C"*10+"PC"+"A"*5,"C"*10+"PCC"+"A"*4,
 "C"*10+"PCPC"+"A"*3,"C"*10+"PCPCC"+"A"*2,
 "C"*10+"PCPCPCA","C"*10+"PCPCPCA"]
decode = {"A":"ABSENT","C":"CURRENT","P":"PREDECESSOR"}
universe = ["ABSENT","CURRENT","PREDECESSOR"]
members, member_mutations = [], []
for state_ordinal, row in enumerate(matrix):
    assert len(row) == 17
    for slot_ordinal, token in enumerate(row):
        expected = decode[token]
        member = {"expected":expected,"member_ordinal":len(members),
          "negative_values":[value for value in universe if value != expected],
          "slot":slots[slot_ordinal],"slot_ordinal":slot_ordinal,
          "state":states[state_ordinal],"state_ordinal":state_ordinal}
        members.append(member)
        for mutated in member["negative_values"]:
            member_mutations.append({"expected":expected,
              "member_ordinal":member["member_ordinal"],
              "mutation_ordinal":len(member_mutations),"mutated":mutated,
              "slot":member["slot"],"state":member["state"]})

quarantine_members, quarantine_mutations = [], []
for state_ordinal in range(11):
    for slot_ordinal, token in enumerate(matrix[state_ordinal]):
        expected = ("CURRENT" if slot_ordinal == 16 else
                    "ABSENT" if slot_ordinal == 15 else decode[token])
        member = {"expected":expected,
          "member_ordinal":len(quarantine_members),
          "negative_values":[value for value in universe if value != expected],
          "slot":slots[slot_ordinal],"slot_ordinal":slot_ordinal,
          "source_state":states[state_ordinal],
          "source_state_ordinal":state_ordinal}
        quarantine_members.append(member)
        for mutated in member["negative_values"]:
            quarantine_mutations.append({"expected":expected,
              "member_ordinal":member["member_ordinal"],
              "mutation_ordinal":len(quarantine_mutations),"mutated":mutated,
              "slot":member["slot"],"source_state":member["source_state"]})

subcode_ranges = [(0,2,"POLICY_ARTIFACT_BYTES"),(3,5,"ROOT_AND_HANDLE_ROSTER"),
 (6,9,"POLICY_SEMANTICS"),(10,17,"CGROUP_AND_NATIVE_OBSERVATION"),
 (18,22,"SUCCESS_ROOT_JOIN"),(23,26,"MOUNT_ROOT_POLICY"),
 (27,32,"LANDLOCK_SEMANTICS"),(33,37,"SECCOMP_SEMANTICS"),
 (38,39,"POLICY_MATERIALIZATION"),(40,43,"NATIVE_FRAME_AND_IDENTITY"),
 (44,47,"POST_OPERATION_JOIN"),(48,54,"NATIVE_ABI_FRAME_PROVENANCE"),
 (55,59,"LANDLOCK_RULE_ROSTER"),(60,63,"FFI_AUTHORITY_PROVENANCE"),
 (64,64,"OUTCOME_MATRIX_TOTALITY"),(65,65,"IMMEDIATE_ERROR_CAPTURE"),
 (66,66,"NO_RETRY_RECONCILIATION"),(67,67,"CRASH_SEAM_EVIDENCE")]
diagnostics = []
for ordinal, label in enumerate(scenarios[47]["mutation"]["values"]):
    subcode = next(name for first, last, name in subcode_ranges
                   if first <= ordinal <= last)
    diagnostics.append({"diagnostic_subcode":subcode,
      "error_code":"CONTAINMENT_POLICY_IDENTITY","label":label,
      "mutation_ordinal":ordinal,"scenario_id":"LRC2-47"})

signature_negative_source = [
 ("mkdirat.args.mode.encoding","U16_LE","U32_LE","SIGNATURE_WIDTH_SIGN"),
 ("openat.args.mode.encoding","U16_LE","U32_LE","SIGNATURE_WIDTH_SIGN"),
 ("read.args.fd.encoding","U32_LE","S32_LE","SIGNATURE_WIDTH_SIGN"),
 ("write.args.fd.encoding","U32_LE","S32_LE","SIGNATURE_WIDTH_SIGN"),
 ("pread64.args.fd.encoding","U32_LE","S32_LE","SIGNATURE_WIDTH_SIGN"),
 ("fstat.args.fd.encoding","U32_LE","S32_LE","SIGNATURE_WIDTH_SIGN"),
 ("statx.args.flags.encoding","U32_LE","S32_LE","SIGNATURE_WIDTH_SIGN"),
 ("binding[0].call_layer","LIBC_SYSCALL_REGISTER_WORDS_V1",
  "RAW_SYSCALL_NEGATIVE_ERRNO","CALL_LAYER_MISMATCH"),
 ("binding[0].error_convention","LIBC_MINUS1_ERRNO_V1",
  "RAW_NEGATIVE_ERRNO","ERROR_CONVENTION_MISMATCH"),
 ("binding[0].abi_profiles","BOTH_EXACT_PROFILES","OMIT_AARCH64",
  "PROFILE_BINDING_MISMATCH"),
 ("signature_binding_roster","22_ROWS_ORDERED","DELETE_ONE",
  "SIGNATURE_BINDING_ROSTER"),
 ("signature_binding_roster","ORDINAL_ORDER","SWAP_0_1",
  "SIGNATURE_BINDING_ROSTER"),
 ("pointee_dependency_graph","ACYCLIC_TWO_PASS",
  "SYNTHETIC_COUNT_TO_BUF_CYCLE","POINTEE_DEPENDENCY_CYCLE")]
signature_negatives = [{"diagnostic_subcode":entry[3],"expected":entry[1],
 "mutated":entry[2],"mutation_ordinal":ordinal,"target":entry[0]}
 for ordinal, entry in enumerate(signature_negative_source)]

windows_negative_source = [
 ("RootDirectory","NULL","NON_NULL","WINDOWS_RENAME_ROOT_DIRECTORY"),
 ("FileName","FULL_ABSOLUTE_UTF16LE","RELATIVE_LEAF","WINDOWS_RENAME_FULL_PATH"),
 ("FileNameLength","EXCLUDES_TERMINATOR","INCLUDES_TERMINATOR","WINDOWS_RENAME_LENGTH"),
 ("Flags","0","NONZERO","WINDOWS_RENAME_FLAGS"),
 ("allocation","ALIGNED_ZERO_TERMINATOR_TAIL","OFFSET_PLUS_LENGTH_ONLY","WINDOWS_RENAME_ALLOCATION"),
 ("information_class","FileRenameInfoEx_22","SUBSTITUTE","WINDOWS_RENAME_INFO_CLASS"),
 ("postcondition","FULL_CONJUNCTION","BOOL_ONLY","WINDOWS_RENAME_POSTCONDITION"),
 ("source_name_absent","TRUE","UNOBSERVED","WINDOWS_RENAME_POSTCONDITION"),
 ("destination_file_id","EQUAL_SOURCE_FILE_ID","MISMATCH","WINDOWS_RENAME_IDENTITY"),
 ("durability_authority","FALSE","TRUE_FROM_RECEIPT","WINDOWS_DURABILITY_CEILING")]
windows_negatives = [{"diagnostic_subcode":entry[3],"expected":entry[1],
 "mutated":entry[2],"mutation_ordinal":ordinal,"target":entry[0]}
 for ordinal, entry in enumerate(windows_negative_source)]

expected = {
 "signatures":(22,11393,"ef473e2d3b6612fbfe5d060457e2d50c24f34282c09d76aa94085408891b0b97",11394,"ed02085631637339759497b5a8a258e5ce86290a9cc715972fbfec1e894f0b8e"),
 "bindings":(22,14913,"684e168ad6a845410f88c09cf9f9c28644813045acda15d045b904484eb00273",14914,"f4238822c4dce3bfd3d4c0239d92d8608890373bf8484dc942313f5139775886"),
 "layouts":(10,3877,"b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a",3878,"b67b0b086370cf79f0a3afeb4adad6a07531f468996e6ec5e690b2cad83b7c82"),
 "scenarios":(52,84800,"70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99",84801,"2eb301a01e60847b1ce096c04b4df086869b216219714be49a70b1b4352b19c5"),
 "postconditions":(23,1697,"0a4f0466e864271afd798a1310fe06693adcd100881614c0cd04fe9cf9c37ad8",1698,"fd35155f94e87b37c28371aaf6a4212d9da14c27c37d5fd4ec796dc993f17c8e"),
 "profiles":(45,14691,"de8cee28aeef8f42c8edc0b2dfc7093becc464317b74cf42f2c2cbec9826f732",14692,"b22f5e0c88bc72e91c17e61b733b95811ac2453f25fc226c3378477840cc13af"),
 "cells":(16,3145,"c41c525c23c5cc787adc1267e941b44a6f6e9a9cece21306c3b7b6167420418e",3146,"b50bc11fed307d331ee5a23092d70b12b06fa5fdfdfbe6a16c8bfecf0e49a72b"),
 "outcomes":(720,197731,"f36d9f26538a425f6e208ce75200a7c724816dfc8d2e0ed5829004f976f922ef",197732,"d3d2c11308906280de42755430c5ce173e056063495c20a61c5baf3f21711627"),
 "pairs":(196,22339,"f84e0f7f0b5b2055caeff49ee2c22109ecc33577aba40d561270b6d9c89cc956",22340,"bfdebe94d5205f233f8dd2b3aefaee8167a931359404c8370651859c77dc2239"),
 "members":(221,37632,"0de0d1ba4c43c09c4b21b5c2b29f8e9334c5ef2a01bebf55afa7c1abee01af8c",37633,"ec570a6c6ee90578e690f8b038fd1d98889928def2d3dd21502640610ef79343"),
 "member_mutations":(442,60014,"e8f315ae8b02f699cf0692d11491d507f595233b5e664babe286d1bad6ab2098",60015,"82446634fbb0bd5ab8a1079ea94a0cfb45c42110314a1081173495c1ca899e1c"),
 "quarantine_members":(187,34624,"6f92d0cfe189061de6b59140a5f4b16f9936576602fbc7ebe083125fb670dabb",34625,"ea82442fa0eb5850cc92a6cd83d0bd48531f265ee09d0a075dff06f218f564ad"),
 "quarantine_mutations":(374,53743,"609ad22c8bbea2c32566d847289da0f76d444c3514590fd88860168ee274b867",53744,"d4d7877eb11f2d80772298b55cdf4814aca6d96dca8f3f0fbe3ecc377df52c1b"),
 "diagnostics":(68,14684,"ae6bffd1a2cea807ec7a6c00a9e1e72db4c786772867a019a7f7e78d9480b056",14685,"530955382e768bf8381a43ab5f7b94f6b7da2eec7a9e39261e2733fb19c1249c"),
 "signature_negatives":(13,2008,"59cb04f236a1aee4a0d051fc944d326e9c1bf5003345a3446a03aadfe232b171",2009,"e037d8a852310b0ed66c922d96a0f862b203bf3983ed5610309c23863d597192"),
 "windows_negatives":(10,1507,"97fcbad018aa862f7c5916826b8aebec53c8f27f10fc7be902bdda3359f2f800",1508,"af923df3da9d56575cfcbf067cf20dcee1ad011cac6fc1acf70a28c73df20d92")}
actual = {"signatures":signatures,"bindings":bindings,"layouts":layouts,
 "scenarios":scenarios,"postconditions":postconditions,"profiles":profiles,
 "cells":cells,"outcomes":outcomes,"pairs":pairs,"members":members,
 "member_mutations":member_mutations,"quarantine_members":quarantine_members,
 "quarantine_mutations":quarantine_mutations,"diagnostics":diagnostics,
 "signature_negatives":signature_negatives,"windows_negatives":windows_negatives}
for name, rows in actual.items():
    assert identity(rows) == expected[name], (name, identity(rows), expected[name])
subcases = sum(1 if row["mutation"]["kind"] == "SINGLE" else
               len(row["mutation"]["values"]) for row in scenarios)
assert subcases == 767
assert [len(row["mutation"]["values"]) for row in scenarios[-10:]] == \
       [39,36,32,34,79,68,16,18,20,28]
assert sum(row["disposition"] == "LEGAL_ADJACENT" for row in pairs) == 12
assert sum(row["disposition"] == "LEGAL_QUARANTINE" for row in pairs) == 11
assert sum(row["disposition"] == "REJECT_STATE_EDGE_ILLEGAL" for row in pairs) == 173
assert 720 + 196 + 442 + 374 + 68 + 13 + 10 == 1823

section19 = text[text.index("## 19."):]
type_blocks = re.findall(r"```text\n(.*?)\n```", section19, re.S)
definitions = {}
for block in type_blocks:
    matches = list(re.finditer(r"(?m)^(vector_[a-z0-9_]+)\s*=\s*$", block))
    for ordinal, match in enumerate(matches):
        definitions[match.group(1)] = block[match.end():
            matches[ordinal + 1].start() if ordinal + 1 < len(matches) else len(block)]
local_names = set(definitions)
graph = {name:{ref for ref in re.findall(r"R\((vector_[a-z0-9_]+)\)", body)
               if ref in local_names} for name, body in definitions.items()}
indegree = {name:0 for name in local_names}
for refs in graph.values():
    for ref in refs: indegree[ref] += 1
queue = collections.deque(name for name, degree in indegree.items() if degree == 0)
visited_count = 0
while queue:
    name = queue.popleft(); visited_count += 1
    for ref in graph[name]:
        indegree[ref] -= 1
        if indegree[ref] == 0: queue.append(ref)
assert len(local_names) == 38 and visited_count == 38
reachable, stack = set(), ["vector_native_ffi_authority",
                           "vector_landlock_policy_preimage"]
while stack:
    name = stack.pop()
    if name in reachable: continue
    reachable.add(name); stack.extend(graph.get(name, ()))
assert local_names <= reachable

uncertainty = section19[section19.index("### 19.6"):
                        section19.index("### 19.7")]
inner = re.search(r"observation:\{\n(.*?)\}\}\)\)", uncertainty, re.S)
assert inner
uncertainty_keys = re.findall(r"[a-z][a-z0-9_]*", inner.group(1))
assert uncertainty_keys == ["classification","capture_operation_id",
 "attempt_ordinal","spawn_arm","containment_instance","actual_process","pid",
 "process_start_identity","pidfd_identity","clone_result","kill_requested",
 "empty_first","empty_second","poll_barrier_between","child_handles_open",
 "operation_private_tree_writers","journaled_status_current",
 "journaled_authorization_current","run_paths","replay_allowed","post_operation"]
assert "root_row_stream_sha256" in section19 and "root_policy_object_sha256" in section19
assert "RootDirectory_size = 8; value = NULL" in section19
assert not re.search(r"(?:authority|production_execution_allowed|spawn_allowed|"
                     r"publication_allowed|cutover_allowed|durability_authority|"
                     r"can_publish)[a-z_]*:C\(true\)", text)
print(json.dumps({"status":"PASS_R3_5_INTERNAL_CONSISTENCY",
 "subject_bytes":len(raw),"subject_lines":raw.count(b"\n"),
 "subject_sha256":hashlib.sha256(raw).hexdigest(),
 "scenario_rows":52,"scenario_subcases":767,"nested_results":1823,
 "local_types":38,"local_cycles":0,"local_unreachable":0},
 sort_keys=True, separators=(",", ":")))
```
<!-- END R3_5_DETERMINISTIC_SELF_CHECK -->

### 19.11 Stable-draft denominator and late-bound admission boundary

The non-lineage R3.5 repair denominator at this stable-draft boundary is exact:

```text
scenario rows / harness methods              52 / 52
ordered scenario subcases                    767
first-42 / last-10 subcases                  397 / 370
last-ten subcase counts                      [39,36,32,34,79,68,16,18,20,28]
CJ(scenarios) bytes / SHA-256                84801 / 2eb301a01e60847b1ce096c04b4df086869b216219714be49a70b1b4352b19c5
CONCAT(CJ(row)||LF) bytes / SHA-256           84800 / 70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99
native layout rows / row-stream bytes        10 / 3877
native layout row-stream SHA-256             b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a
native layout parsed-array bytes / SHA-256   3878 / b67b0b086370cf79f0a3afeb4adad6a07531f468996e6ec5e690b2cad83b7c82
native signature rows / row-stream bytes     22 / 11393
native signature row-stream SHA-256          ef473e2d3b6612fbfe5d060457e2d50c24f34282c09d76aa94085408891b0b97
native signature parsed-array bytes / SHA-256 11394 / ed02085631637339759497b5a8a258e5ce86290a9cc715972fbfec1e894f0b8e
signature binding rows / row-stream bytes    22 / 14913
signature binding row-stream SHA-256         684e168ad6a845410f88c09cf9f9c28644813045acda15d045b904484eb00273
signature binding array bytes / SHA-256      14914 / f4238822c4dce3bfd3d4c0239d92d8608890373bf8484dc942313f5139775886
postcondition-map rows / stream / array      23 / 1697 / 1698
postcondition stream / array SHA-256         0a4f0466e864271afd798a1310fe06693adcd100881614c0cd04fe9cf9c37ad8 / fd35155f94e87b37c28371aaf6a4212d9da14c27c37d5fd4ec796dc993f17c8e
API-profile rows / outcome cells / matrix    45 / 16 / 720
nested atomic execution-result denominator   1823
lifecycle states / pairs / legal / rejected  14 / 196 / 23 / 173
ordinary matrix members / mutations          221 / 442
quarantine prefix members / mutations        187 / 374
local replacement schema types / cycles      38 / 0
```

These values close only the non-lineage contract repairs.  This document is a
stable draft, not a frozen or independently accepted launcher.  It grants no
spawn, native-host, publication, cutover, or audit-execution authority.  The
v2 source, review, receipt, and marker references retained above are historical
inputs only; they MUST NOT be treated as current accepted lineage.

The platform ceiling is unchanged and is not inferable from a receipt: only the
Linux retained-handle same-mount barrier profile can ever become power-loss
authoritative after later materialization and review; macOS is unavailable;
Windows remains ordinary-user protected-root, process-crash-only nonauthority.
Every R3.5 evidence-authority, production-execution, spawn, publication,
cutover, and durability-enabling flag is false.

The late-bound 15-edge crosscheck bridge remains explicitly deferred and is not
implemented, materialized, reviewed, or evaluated here.  Admission remains
blocked until a separately accepted late-bound bridge first crosschecks all 15
governed lineage edges and the canonical source, review,
receipt, and marker identities.  Only after that crosscheck is accepted may a
separate admission-lineage amendment be reviewed, followed by an independently
reviewed v2 bridge reference.  The launcher must then be rebound to those exact
accepted inputs, all affected identities and denominators must be recomputed,
and the resulting bytes must receive two fresh independent reviews before any
freeze or PASS claim.  A review of this stable draft cannot be carried forward
across that rebind as acceptance of the final launcher.

## 20. R3.6 executable-join and evidence-shape closure

This section is the sole R3.6 normative replacement for every conflicting
R3.5 native declaration, frame, pointee, output, semantic-case, outcome,
crash-seam, receipt, authority, provenance, review, Windows-observation,
atomic-result, or self-check expression.  Section 19 remains review history.
The unchanged R3.5 layout, scenario, postcondition-selector, API/profile,
16-cell, lifecycle, ordinary-member, quarantine-member, and LRC2-47 roster
bytes are retained only where this section explicitly rejoins them.  No R3.5
claim that is contradicted by either R3.5 stable-draft review survives by
silence.

The exact reviewed predecessor is 736,932 bytes, 10,935 LF-only lines, and
SHA-256 `800b2d886ea5affa087cf8d5ce4bfff460a79b8736accbda0d0b5e8a2604668b`.
The complete native review is 25,779 bytes with SHA-256
`9e8fb11548e61eb2b3634541aa057a525210ce8d0ad4b7fc3653db1822d9eec6`;
the complete state review is 24,271 bytes with SHA-256
`79cae827cf492bf3e240145f13a55548cd271c0b37e27cea9ece5d5bd44b2736`.
They are repair inputs, not PASS lineage.  Their identities are carried by the
future outer review-artifact bindings below and cannot self-certify this draft.

The only current branch is unmaterialized and nonauthoritative.  No native
fixture, actual call, crash facility, build, source slice, binary, host result,
or review record is fabricated here.  A value absent at this boundary remains
absent rather than being replaced by a plausible digest.

### 20.1 Exact declarations and the libc-call binding

The R3.5 signature array is transformed before use by deleting its documentary
`prototype` member.  The resulting six-member row
`{api,args,ordinal,outputs,return_kind,uapi_symbol}` is the R3.6 signature-core
row.  It is joined one-to-one by `(ordinal,api,uapi_symbol)` to the declaration
roster below.  No R3.5 prototype string participates in an R3.6 hash or review.

<!-- BEGIN VECTOR_NATIVE_DECLARATION_ROSTER_R3_6 -->
```json
[
{"api":"mkdirat","declaration":"asmlinkage long sys_mkdirat(int dfd,const char __user *pathname,umode_t mode);","declaration_name":"sys_mkdirat","ordinal":0,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_mkdirat"},
{"api":"openat","declaration":"asmlinkage long sys_openat(int dfd,const char __user *filename,int flags,umode_t mode);","declaration_name":"sys_openat","ordinal":1,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_openat"},
{"api":"read","declaration":"asmlinkage long sys_read(unsigned int fd,char __user *buf,size_t count);","declaration_name":"sys_read","ordinal":2,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_read"},
{"api":"write","declaration":"asmlinkage long sys_write(unsigned int fd,const char __user *buf,size_t count);","declaration_name":"sys_write","ordinal":3,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_write"},
{"api":"pread64","declaration":"asmlinkage long sys_pread64(unsigned int fd,char __user *buf,size_t count,loff_t pos);","declaration_name":"sys_pread64","ordinal":4,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_pread64"},
{"api":"readlinkat","declaration":"asmlinkage long sys_readlinkat(int dfd,const char __user *path,char __user *buf,int bufsiz);","declaration_name":"sys_readlinkat","ordinal":5,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_readlinkat"},
{"api":"fstat","declaration":"asmlinkage long sys_newfstat(unsigned int fd,struct stat __user *statbuf);","declaration_name":"sys_newfstat","ordinal":6,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":"struct stat","uapi_symbol":"__NR_fstat"},
{"api":"statx","declaration":"asmlinkage long sys_statx(int dfd,const char __user *path,unsigned flags,unsigned mask,struct statx __user *buffer);","declaration_name":"sys_statx","ordinal":7,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":"struct statx","uapi_symbol":"__NR_statx"},
{"api":"mount","declaration":"asmlinkage long sys_mount(char __user *dev_name,char __user *dir_name,char __user *type,unsigned long flags,void __user *data);","declaration_name":"sys_mount","ordinal":8,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_mount"},
{"api":"umount2","declaration":"asmlinkage long sys_umount(char __user *name,int flags);","declaration_name":"sys_umount","ordinal":9,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_umount2"},
{"api":"pivot_root","declaration":"asmlinkage long sys_pivot_root(const char __user *new_root,const char __user *put_old);","declaration_name":"sys_pivot_root","ordinal":10,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_pivot_root"},
{"api":"prctl","declaration":"asmlinkage long sys_prctl(int option,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5);","declaration_name":"sys_prctl","ordinal":11,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_prctl"},
{"api":"seccomp","declaration":"asmlinkage long sys_seccomp(unsigned int op,unsigned int flags,void __user *uargs);","declaration_name":"sys_seccomp","ordinal":12,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_seccomp"},
{"api":"landlock_get_abi","declaration":"asmlinkage long sys_landlock_create_ruleset(const struct landlock_ruleset_attr __user *attr,size_t size,__u32 flags);","declaration_name":"sys_landlock_create_ruleset","ordinal":13,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":"struct landlock_ruleset_attr","uapi_symbol":"__NR_landlock_create_ruleset"},
{"api":"landlock_create_ruleset","declaration":"asmlinkage long sys_landlock_create_ruleset(const struct landlock_ruleset_attr __user *attr,size_t size,__u32 flags);","declaration_name":"sys_landlock_create_ruleset","ordinal":14,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":"struct landlock_ruleset_attr","uapi_symbol":"__NR_landlock_create_ruleset"},
{"api":"landlock_add_rule","declaration":"asmlinkage long sys_landlock_add_rule(int ruleset_fd,enum landlock_rule_type rule_type,const void __user *rule_attr,__u32 flags);","declaration_name":"sys_landlock_add_rule","ordinal":15,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":"enum landlock_rule_type","uapi_symbol":"__NR_landlock_add_rule"},
{"api":"landlock_restrict_self","declaration":"asmlinkage long sys_landlock_restrict_self(int ruleset_fd,__u32 flags);","declaration_name":"sys_landlock_restrict_self","ordinal":16,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_landlock_restrict_self"},
{"api":"close_range","declaration":"asmlinkage long sys_close_range(unsigned int fd,unsigned int max_fd,unsigned int flags);","declaration_name":"sys_close_range","ordinal":17,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_close_range"},
{"api":"clone3","declaration":"asmlinkage long sys_clone3(struct clone_args __user *uargs,size_t size);","declaration_name":"sys_clone3","ordinal":18,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":"struct clone_args","uapi_symbol":"__NR_clone3"},
{"api":"pidfd_send_signal","declaration":"asmlinkage long sys_pidfd_send_signal(int pidfd,int sig,siginfo_t __user *info,unsigned int flags);","declaration_name":"sys_pidfd_send_signal","ordinal":19,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":"siginfo_t","uapi_symbol":"__NR_pidfd_send_signal"},
{"api":"poll","declaration":"asmlinkage long sys_poll(struct pollfd __user *ufds,unsigned int nfds,int timeout);","declaration_name":"sys_poll","ordinal":20,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":"struct pollfd","uapi_symbol":"__NR_poll"},
{"api":"unlinkat","declaration":"asmlinkage long sys_unlinkat(int dfd,const char __user *pathname,int flag);","declaration_name":"sys_unlinkat","ordinal":21,"return_type":"long","source":"include/linux/syscalls.h@v6.16","struct_target":null,"uapi_symbol":"__NR_unlinkat"}
]
```
<!-- END VECTOR_NATIVE_DECLARATION_ROSTER_R3_6 -->

Every declaration row is obtained by lexing the exact pinned source slice and
serializing token spellings with one ASCII space only between two adjacent
identifier/keyword tokens and no space adjacent to punctuation; its token
sequence must equal the source slice's token sequence.  The
materialized declaration binding carries the header-row ordinal, byte offset,
byte length, raw-slice SHA-256, architecture syscall-table row/number, and UAPI
number-header row/number.  Both architecture mappings must resolve the row's
`uapi_symbol` to the number actually passed to libc `syscall`.  `fstat` is
therefore explicitly `sys_newfstat` and `struct stat`; the obsolete
`sys_fstat(...,__old_kernel_stat *)` cannot satisfy the join.  All 22 return
types are `long`; `ssize_t` cannot satisfy the declaration roster.

The effective binding is still one abstraction only:
`LIBC_SYSCALL_REGISTER_WORDS_V1` plus `LIBC_MINUS1_ERRNO_V1`.  Each source
scalar is sign- or zero-extended from its declared signature-core width to one
register word; pointer bits are copied unchanged.  A libc return of `-1`
requires immediate positive `errno`; a nonnegative return makes the error slot
invalid.  Raw negative-kernel-error conventions are never mixed into this
layer.

```text
vector_native_declaration_binding_r3_6 =
O(ordinal:I(0,21),api:S1,uapi_symbol:S1,declaration_row_sha256:HEX,
  declaration_header_row_ordinal:I(0,127),
  declaration_header:R(vector_native_header_input),
  source_slice_offset:I(0,16777215),source_slice_length:I(1,16777216),
  raw_source_slice:R(vector_exact_native_bytes),normalized_declaration:S1,
  x86_64_uapi_header_row_ordinal:I(0,127),
  x86_64_uapi_header:R(vector_native_header_input),
  x86_64_syscall_table_row:R(vector_exact_native_bytes),
  x86_64_syscall_number_u32:I(0,4294967295),
  aarch64_uapi_header_row_ordinal:I(0,127),
  aarch64_uapi_header:R(vector_native_header_input),
  aarch64_syscall_table_row:R(vector_exact_native_bytes),
  aarch64_syscall_number_u32:I(0,4294967295),binding_sha256:HEX)
```

The raw source slice size/digest equals its explicit offset/length in the
registered declaration header.  Both syscall-table rows are exact registered
source slices; each number equals the matching architecture UAPI macro and the
number passed at the observed call boundary.  `binding_sha256` uses domain
`PROGRAM_FACTS_G3_NATIVE_DECLARATION_BINDING_V1` and all preceding members.

### 20.2 Closed request/result frames and two-pass memory evaluation

R3.6 replaces both R3.5 magics and assigns every numeric code.  The complete
code table is: profiles `x86-64=0,AArch64=1`; directions `IN=0,OUT=1,INOUT=2`;
value kinds `S32=0,U16=1,U32=2,S64=3,U64=4,POINTER=5`; initialization
`INPUT_ALL=0,OUTPUT_PREFIX=1,INPUT_THEN_OUTPUT_MEMBERS=2`; region kinds
`CSTRING=0,OPAQUE_BYTES=1,STRUCT=2,STRUCT_ARRAY=3,S32_ARRAY=4`; return kinds
`S64_LE=0,FD_OR_MINUS1_S64_LE=1,BYTE_COUNT_OR_MINUS1_S64_LE=2,
ABI_VERSION_OR_MINUS1_S64_LE=3,PID_OR_MINUS1_S64_LE=4,
READY_COUNT_OR_MINUS1_S64_LE=5`; output-member kinds `SCALAR=0,NESTED=1`.
No unnamed code or alternate numeric value is accepted.

The exact returned-call request frame is:

```text
"PFG3NAR6" || u16le(6) || u16le(profile_code) ||
u16le(api_ordinal) || u16le(argument_count) ||
CONCAT(for each argument in increasing argument ordinal:
  u16le(argument_ordinal) || u8(direction_code) || u8(value_kind_code) ||
  u32le(value_byte_length) || value_bytes ||
  u64le(bound_input_size_or_ffffffffffffffff) || u16le(region_count) ||
  CONCAT(for each region in increasing region ordinal:
    u16le(region_ordinal) || u16le(recursion_depth) ||
    u16le(parent_argument_ordinal) || u16le(parent_region_ordinal_or_ffff) ||
    u32le(parent_struct_field_offset) || u8(region_direction_code) ||
    u8(initialization_code) || u16le(region_kind_code) ||
    u32le(layout_ordinal_or_ffffffff) || u64le(declared_capacity) ||
    u64le(input_initialized_length) || u64le(payload_length) || payload_bytes))
```

The exact returned-call result frame is:

```text
"PFG3NRE6" || u16le(6) || u16le(profile_code) ||
u16le(api_ordinal) || u16le(return_kind_code) || s64le(return_value) ||
u8(error_valid) || u8(0) || u16le(0) || u32le(error_code) ||
u16le(output_region_count) ||
CONCAT(for each output region in joined request-region order:
  u16le(argument_ordinal) || u16le(region_ordinal) ||
  u16le(recursion_depth) || u16le(parent_region_ordinal_or_ffff) ||
  u32le(parent_struct_field_offset) || u16le(region_kind_code) ||
  u16le(layout_ordinal_or_ffff) || u64le(declared_capacity) ||
  u64le(initialized_leaf_length) || u64le(payload_length) || payload_bytes)
```

All all-ones values are literal sentinels and every reserved byte is zero.
The complete frame, not merely a payload, is bounded by 16,777,216 bytes.  A
decoder consumes the frame exactly once and rejects suffix bytes.

`bound_input_size` is now an explicit argument-frame scalar.  It is the all-
ones sentinel unless that pointer's expression is `CSTRING` or nullable
`CSTRING`.  For a nonnull string it equals the carried region's input length,
the final byte is exactly NUL, and no earlier byte is NUL.  For a null nullable
string it is zero and there is no region.  It is durable with the scalar frame
before region evaluation; it is never derived from, or searched out of, a
region.

The effective closed expression AST is not the old literal prose string:

```text
vector_native_pointee_expression_r3_6 =
O(kind:E("CSTRING","OPAQUE_BYTES","STRUCT","STRUCT_ARRAY","S32_ARRAY"),
  nullable:B,capacity_source:E("BOUND_INPUT_SIZE","SCALAR_ARGUMENT",
    "FIXED_LAYOUT","FIXED_FOUR"),capacity_argument_ordinal:Q(I(0,7)),
  initialized_source:E("INPUT_ALL","RETURN_NONNEGATIVE_PREFIX",
    "SUCCESS_NAMED_FIELDS","RETURN_NONNEGATIVE_S32","NONE"),
  count_source:Q(E("SCALAR_ARGUMENT","FIXED_ONE")),
  count_argument_ordinal:Q(I(0,7)),layout_ordinal:Q(I(0,9)),
  element_size:Q(I(1,256)),expression_sha256:HEX)

vector_native_nested_expression_r3_6 =
O(parent_argument_ordinal:I(0,7),parent_region_ordinal:I(0,31),
  parent_struct_field_offset:I(0,65535),
  expression:R(vector_native_pointee_expression_r3_6))
```

The AST encoding is `CJ` of the displayed object with keys sorted by UTF-8
code-unit order and no whitespace.  `expression_sha256` is SHA-256 of the same
object without that member under domain
`PROGRAM_FACTS_G3_NATIVE_POINTEE_EXPRESSION_V1`.  Each signature-core pointee
string has exactly one reviewed compile result to this AST; the compiler is
pure and rejects every unlisted token.  A signature/dependency unit negative
injects an AST after the pinned roster identity gate; an integrated negative
injects the serialized roster before that gate.  Their precedence is therefore
unambiguous.

Evaluation is exactly two pass.  Pass one decodes all scalar argument values
and every carried `bound_input_size` into an immutable ordinal map.  Pass two
topologically evaluates direct and nested pointee ASTs from that complete map.
The only admitted forward dependencies remain `read.buf->count`,
`write.buf->count`, `pread64.buf->count`, `readlinkat.buf->bufsiz`,
`clone3.uargs->size`, and `poll.fds->nfds`.  An unknown name, output-derived
capacity, cycle, second-level child, checked add/multiply overflow, capacity
excess, or region overlap rejects before entry.

Structured output uses a discriminated member union:

```text
vector_native_scalar_output_member_r3_6 =
O(member_kind:C("SCALAR"),element_ordinal:I(0,671084),
  field_ordinal:I(0,127),field_offset:I(0,16777215),
  layout_span:I(1,16777216),authoritative_leaf_length:I(1,8),
  framing_length:I(1,8),leaf_bytes:R(vector_exact_native_bytes))

vector_native_nested_output_member_r3_6 =
O(member_kind:C("NESTED"),element_ordinal:I(0,671084),
  field_ordinal:I(0,127),field_offset:I(0,16777215),
  layout_span:I(1,256),authoritative_leaf_length:I(1,256),
  framing_length:I(1,16777216),layout_ordinal:I(0,9),
  children:A(R(vector_native_scalar_output_member_r3_6),1,128,true))

vector_native_output_member_r3_6 =
U(R(vector_native_scalar_output_member_r3_6),
  R(vector_native_nested_output_member_r3_6))

vector_native_output_region_r3_6 =
O(argument_ordinal:I(0,7),region_ordinal:I(0,31),recursion_depth:I(0,1),
  parent_region_ordinal:Q(I(0,31)),parent_struct_field_offset:I(0,65535),
  direction:E("OUT","INOUT"),
  region_kind:E("OPAQUE_BYTES","STRUCT","STRUCT_ARRAY","S32_ARRAY"),
  layout_ordinal:Q(I(0,9)),declared_capacity:I(0,16777216),
  initialized_leaf_length:I(0,16777216),payload:R(vector_exact_native_bytes),
  members:A(R(vector_native_output_member_r3_6),0,671085,true))
```

For OPAQUE_BYTES and S32_ARRAY, the payload is the authoritative raw prefix and
`members` is empty.  For STRUCT/STRUCT_ARRAY, payload is
`u32le(member_count)||CONCAT(member_frame)` and `members` is its unique decode.
A scalar frame is `u8(0)||u32le(element)||u16le(field)||u32le(offset)||
u32le(layout_span)||u32le(authoritative_leaf_length)||u32le(framing_length)||
leaf_bytes`; both lengths equal the leaf width.  A nested frame is the same
header with `u8(1)`, followed by `u16le(layout_ordinal)||child_stream`; its
layout span is the in-memory parent-field width, authoritative leaf length is
the sum of child leaf widths, and framing length is the exact child-stream byte
length.  These three values are deliberately distinct.  For
`statx_timestamp`, the span is 16 and authoritative leaf length is 12; the four
reserved bytes never enter a frame.

The result-frame ceiling fixes `poll.nfds` at exactly `0..671085`.  With one
poll output region the fixed result frame is 34 bytes, its region header is 40
bytes, the member-count prefix is 4 bytes, and each two-byte `revents` scalar
frame is 25 bytes.  Therefore
`34+40+4+25*671085 = 16777203 <= 16777216`, while the next value produces
16,777,228 bytes and rejects.  The input struct array is also checked as
`8*nfds`.  Boundary atoms cover 0, 1, 671085, and 671086.

The effective call types that bind those frames are:

```text
vector_native_request_region_r3_6 =
O(region_ordinal:I(0,31),recursion_depth:I(0,1),
  parent_argument_ordinal:I(0,7),parent_region_ordinal:Q(I(0,31)),
  parent_struct_field_offset:I(0,65535),direction:E("IN","OUT","INOUT"),
  initialization:E("INPUT_ALL","OUTPUT_PREFIX","INPUT_THEN_OUTPUT_MEMBERS"),
  expression:R(vector_native_pointee_expression_r3_6),
  declared_capacity:I(0,16777216),input_initialized_length:I(0,16777216),
  input_payload:R(vector_exact_native_bytes))

vector_native_argument_value_r3_6 =
O(ordinal:I(0,7),name:S1,direction:E("IN","OUT","INOUT"),
  value_kind:E("S32","U16","U32","S64","U64","POINTER"),
  value_bytes:R(vector_exact_native_bytes),
  bound_input_size:Q(I(0,16777216)),
  regions:A(R(vector_native_request_region_r3_6),0,32,true),
  nested_expressions:A(R(vector_native_nested_expression_r3_6),0,32,true))

vector_native_argument_projection_r3_6 =
O(api:S1,profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  signature_ordinal:I(0,21),signature_core_row_sha256:HEX,
  declaration_row_sha256:HEX,declaration_binding:R(file_identity),
  call_layer:C("LIBC_SYSCALL_REGISTER_WORDS_V1"),
  error_convention:C("LIBC_MINUS1_ERRNO_V1"),
  layout_row_stream_sha256:C("b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a"),
  arguments:A(R(vector_native_argument_value_r3_6),1,8,true))

vector_native_result_projection_r3_6 =
O(return_kind:E("S64_LE","FD_OR_MINUS1_S64_LE",
    "BYTE_COUNT_OR_MINUS1_S64_LE","ABI_VERSION_OR_MINUS1_S64_LE",
    "PID_OR_MINUS1_S64_LE","READY_COUNT_OR_MINUS1_S64_LE"),
  return_kind_code:I(0,5),return_value:I(-1,9007199254740991),
  error_valid:B,errno_captured_immediately:I(0,4095),
  outputs:A(R(vector_native_output_region_r3_6),0,128,true))

vector_native_call_r3_6 =
O(ordinal:I(0,4095),call_id:S(40,40,"^pfg3vnc-[0-9a-f]{32}$"),
  request_frame:R(vector_exact_native_bytes),
  arguments:R(vector_native_argument_projection_r3_6),
  result_frame:R(vector_exact_native_bytes),
  result:R(vector_native_result_projection_r3_6),
  build_manifest_sha256:HEX,call_sha256:HEX)
```

The argument scalar map, ASTs, regions, request frame, selected signature core,
declaration row/binding, and exact build manifest must agree field for field.
The result projection is the unique full decode of the result frame and each
output is joined to exactly one request region.  `call_sha256` is SHA-256 of
domain `PROGRAM_FACTS_G3_VECTOR_NATIVE_CALL_V5` and every preceding call
member; `call_id` is `pfg3vnc-` plus its first 32 hexadecimal digits.

### 20.3 Pre-bound relational postconditions and derived returned outcomes

R3.6 deletes the opaque `typed_projection:R(file_identity)` and concrete
`expected_effect`/`no_effect` blobs.  A projection carries its fields and exact
bytes.  The field roster below is the complete per-selector schema; its string
entries are `field_name:value_kind` in canonical ordinal order.

<!-- BEGIN VECTOR_NATIVE_SEMANTIC_FIELD_ROSTER_R3_6 -->
```json
[
{"fields":["parent_id:IDENTITY","leaf:BYTES","presence_before:BOOL","presence_after:BOOL","file_type:ENUM","result_id:IDENTITY","requested_mode:U64","effective_mode:U64"],"selector":"EXACT_DIRECTORY_LEAF_IDENTITY"},
{"fields":["parent_id:IDENTITY","leaf:BYTES","namespace_before:ROWS","namespace_after:ROWS","returned_fd_present:BOOL","target_id:IDENTITY","access_flags:U64","status_flags:U64","descriptor_flags:U64"],"selector":"EXACT_NOFOLLOW_HANDLE_IDENTITY_AND_FLAGS"},
{"fields":["return_count:S64","initialized_prefix:BYTES","requested_capacity:U64","fd_offset_before:S64","fd_offset_after:S64"],"selector":"RETURN_COUNT_AND_INITIALIZED_PREFIX"},
{"fields":["return_count:S64","input_prefix:BYTES","target_id:IDENTITY","fd_offset_before:S64","fd_offset_after:S64","size_before:U64","size_after:U64","affected_range:ROWS"],"selector":"RETURN_COUNT_AND_TARGET_PREFIX_EFFECT"},
{"fields":["return_count:S64","initialized_prefix:BYTES","requested_position:S64","fd_offset_before:S64","fd_offset_after:S64"],"selector":"RETURN_COUNT_INITIALIZED_PREFIX_AND_OFFSET_UNCHANGED"},
{"fields":["link_parent_id:IDENTITY","leaf:BYTES","requested_capacity:U64","return_count:S64","link_bytes:BYTES"],"selector":"RETURN_COUNT_AND_LINK_BYTES"},
{"fields":["abi:ENUM","layout_ordinal:U64","named_fields:ROWS"],"selector":"NAMED_KERNEL_STAT_FIELDS"},
{"fields":["flags:U64","requested_mask:U64","returned_mask:U64","named_fields:ROWS"],"selector":"NAMED_STATX_FIELDS_AND_REQUESTED_MASK"},
{"fields":["mount_rows_before:ROWS","mount_rows_after:ROWS","source:BYTES","target:BYTES","filesystem_type:BYTES","mount_id:U64","parent_mount_id:U64","propagation:ENUM","flags:U64"],"selector":"EXACT_MOUNT_GRAPH_EDGE_AND_FLAGS"},
{"fields":["mount_rows_before:ROWS","mount_rows_after:ROWS","target_mount_id:U64","absent_after:BOOL"],"selector":"EXACT_MOUNT_GRAPH_EDGE_ABSENT"},
{"fields":["root_mount_id_before:U64","root_mount_id_after:U64","put_old_mount_id:U64","cwd_handle:IDENTITY","root_handle:IDENTITY","mount_graph:ROWS"],"selector":"EXACT_ROOT_AND_PUT_OLD_MOUNT_GRAPH"},
{"fields":["option:S64","arguments:ROWS","attribute_before:BYTES","attribute_after:BYTES"],"selector":"EXACT_PROCESS_ATTRIBUTE"},
{"fields":["instruction_identity:IDENTITY","no_new_privs:BOOL","audit_arch:ENUM","thread_ids:ROWS","filter_identity:IDENTITY"],"selector":"EXACT_FILTER_INSTALLED_FOR_CALLING_THREAD_SET"},
{"fields":["attr_is_zero:BOOL","size_is_zero:BOOL","version_flag:U64","returned_abi:S64","pointee_output_count:U64"],"selector":"ABI_VERSION_RETURN_ONLY"},
{"fields":["returned_fd_present:BOOL","returned_fd_identity:IDENTITY","handled_masks:ROWS"],"selector":"RULESET_FD_AND_HANDLED_MASKS"},
{"fields":["ruleset_fd_identity:IDENTITY","rule_ordinal:U64","rule_type:U64","parent_fd_identity:IDENTITY","allowed_mask:U64","ordered_rules:ROWS"],"selector":"EXACT_RULE_ADDED_TO_RULESET"},
{"fields":["ruleset_fd_identity:IDENTITY","thread_ids:ROWS","policy_identity:IDENTITY","enforcement_probes:ROWS"],"selector":"EXACT_RULESET_ENFORCED"},
{"fields":["fds_before:ROWS","fds_after:ROWS","first:U64","last:U64","flags:U64","range_result:ENUM"],"selector":"EXACT_DESCRIPTOR_RANGE_STATE"},
{"fields":["clone_request:BYTES","child_process_identity:IDENTITY","pidfd_identity:IDENTITY","cgroup_identity:IDENTITY","namespace_identities:ROWS","gate_state:ENUM"],"selector":"EXACT_CHILD_PID_PIDFD_AND_NAMESPACE_STATE"},
{"fields":["pidfd_identity:IDENTITY","signal:S64","target_process_identity:IDENTITY","liveness_before:ENUM","liveness_after:ENUM"],"selector":"EXACT_TARGET_PROCESS_SIGNAL_STATE"},
{"fields":["nfds:U64","timeout:S64","input_fd_events:ROWS","output_revents:ROWS","return_count:S64","ready_count:U64"],"selector":"RETURN_COUNT_AND_ALL_REVENTS_FIELDS"},
{"fields":["parent_id:IDENTITY","leaf:BYTES","presence_before:BOOL","presence_after:BOOL","unrelated_entries_before:ROWS","unrelated_entries_after:ROWS"],"selector":"EXACT_SOURCE_LEAF_ABSENT"},
{"fields":["source_parent_id:IDENTITY","source_leaf:BYTES","destination_parent_id:IDENTITY","destination_leaf:BYTES","source_presence:BOOL","destination_presence:BOOL","retained_source_file_id:IDENTITY","destination_reopen_file_id:IDENTITY"],"selector":"WINDOWS_SOURCE_ABSENT_DESTINATION_FILE_ID_CONTINUITY"}
]
```
<!-- END VECTOR_NATIVE_SEMANTIC_FIELD_ROSTER_R3_6 -->

The closed projection and predicate types are:

```text
vector_native_projection_field_r3_6 =
O(field_ordinal:I(0,31),field_name:S1,
  value_kind:E("BOOL","U64","S64","BYTES","ENUM","IDENTITY","ROWS"),
  encoded_value:R(vector_exact_native_bytes),field_sha256:HEX)

vector_native_typed_projection_r3_6 =
O(selector:S1,fields:A(R(vector_native_projection_field_r3_6),1,32,true),
  complete:B,missing_field_ordinals:A(I(0,31),0,32,true),
  canonical_bytes:R(vector_exact_native_bytes),projection_sha256:HEX)

vector_native_relation_term_r3_6 =
U(O(term_kind:C("LITERAL"),literal_kind:E("BOOL","U64","S64","BYTES",
      "ENUM","IDENTITY","ROWS"),literal:R(vector_exact_native_bytes)),
  O(term_kind:C("FIELD"),source:E("PRESTATE","REQUEST","RETURN",
      "ACTUAL"),field_ordinal:I(0,31)),
  O(term_kind:C("SYMBOL"),symbol_ordinal:I(0,31)))

vector_native_relation_atom_r3_6 =
O(atom_ordinal:I(0,127),operator:E("EQ","NE","ABSENT","PRESENT",
    "IN_UNSIGNED_RANGE","FRESH_AGAINST_ROSTER","UNCHANGED","SAME_OBJECT",
    "PREFIX_EQ","COUNT_EQ","SET_EQ","SET_DISJOINT"),
  left:R(vector_native_relation_term_r3_6),
  right:Q(R(vector_native_relation_term_r3_6)),atom_sha256:HEX)

vector_native_fresh_symbol_r3_6 =
O(symbol_ordinal:I(0,31),name:S1,
  kind:E("FILE_ID","FD","MOUNT_ID","PID","PIDFD","PROCESS_ID"),
  freshness_universe_field_ordinal:I(0,31))

vector_native_postcondition_predicate_r3_6 =
O(selector:S1,durable_prestate:R(vector_native_typed_projection_r3_6),
  request_projection:R(vector_native_typed_projection_r3_6),
  fresh_symbols:A(R(vector_native_fresh_symbol_r3_6),0,32,true),
  expected_effect_atoms:A(R(vector_native_relation_atom_r3_6),1,128,true),
  no_effect_atoms:A(R(vector_native_relation_atom_r3_6),1,128,true),
  expected_and_no_effect_disjoint:C(true),prebound_before_entry:C(true),
  derivation_oracle_source:R(file_identity),
  derivation_review:R(vector_native_review_artifact_binding_r3_6),
  predicate_sha256:HEX)

vector_native_postcondition_evaluation_r3_6 =
O(predicate_sha256:HEX,actual_projection:R(vector_native_typed_projection_r3_6),
  symbol_bindings:A(R(vector_native_projection_field_r3_6),0,32,true),
  expected_atom_truth:A(B,1,128,false),no_effect_atom_truth:A(B,1,128,false),
  expected_effect_satisfied:B,no_effect_satisfied:B,
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE"),evaluation_sha256:HEX)
```

BOOL is one byte `00/01`; U64 and S64 are exactly eight-byte little-endian;
BYTES is `u64le(length)||bytes`; ENUM is `u16le(length)||UTF8`; IDENTITY is
`u32le(CJ_length)||CJ(typed identity)`; ROWS is
`u32le(count)||CONCAT(u32le(CJ_length)||CJ(row))`.  Field names, kinds, count,
and order equal the selector row above.  `canonical_bytes` is
`u16le(selector_utf8_length)||selector_utf8||u16le(field_count)||
CONCAT(u16le(field_ordinal)||u16le(field_name_length)||field_name_utf8||
u8(value_kind_code)||u32le(encoded_value_length)||encoded_value)`.
The value-kind codes in displayed enum order are 0 through 6.

Every `field_sha256`, atom hash, projection hash, predicate hash, and evaluation
hash is SHA-256 of `CJ({domain:<domain>,all preceding members})`; the hash
member itself is excluded.  Their domains are respectively
`PROGRAM_FACTS_G3_NATIVE_PROJECTION_FIELD_V1`,
`PROGRAM_FACTS_G3_NATIVE_RELATION_ATOM_V1`,
`PROGRAM_FACTS_G3_NATIVE_TYPED_PROJECTION_V1`,
`PROGRAM_FACTS_G3_NATIVE_POSTCONDITION_PREDICATE_V1`, and
`PROGRAM_FACTS_G3_NATIVE_POSTCONDITION_EVALUATION_V1`.  The evaluation's
truth arrays are recomputed from its typed operands and exactly match atom
ordinals.  If `actual_projection.complete=false`, the poststate is
`UNOBSERVABLE`.  Otherwise all expected atoms true and not all no-effect atoms
true derives `EXPECTED_EFFECT`; all no-effect atoms true and not all expected
atoms true derives `NO_EFFECT`; any other valuation derives `WRONG_EFFECT`.
Both true rejects.  A fresh symbol is unbound before entry, is bound only from
the actual projection after return, and must satisfy its pre-bound freshness
atom.  The oracle cannot see the production result when choosing atoms or
symbols.

The returned Linux envelope is now typed through the fresh poststate:

```text
vector_linux_returned_outcome_r3_6 =
O(completion_kind:C("RETURNED"),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  call:R(vector_native_call_r3_6),
  predicate:R(vector_native_postcondition_predicate_r3_6),
  fresh_observation:R(vector_native_typed_projection_r3_6),
  evaluation:R(vector_native_postcondition_evaluation_r3_6),
  return_status:E("SUCCESS","FAILURE","INTERRUPTED"),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE"),cell_ordinal:I(0,11),
  classification:E("API_SEMANTIC_SUCCESS","API_FAILURE_NO_RETRY",
    "RESUME_FROM_EFFECT_NO_REPLAY","RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),outcome_sha256:HEX)

vector_linux_no_return_outcome_r3_6 =
O(completion_kind:C("NO_RETURN"),reason:C("PROCESS_CRASH"),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  request_frame:R(vector_exact_native_bytes),result_frame:C(null),
  crash_seam_ordinal:I(0,7),crash_seam:E("BEFORE_ENTRY",
    "AFTER_REQUEST_DURABLE","DURING_CALL","AFTER_EFFECT_BEFORE_RETURN",
    "AFTER_RETURN_BEFORE_ERROR_CAPTURE","AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE",
    "DURING_POSTSTATE","AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER"),
  predicate:R(vector_native_postcondition_predicate_r3_6),
  fresh_observation:R(vector_native_typed_projection_r3_6),
  evaluation:R(vector_native_postcondition_evaluation_r3_6),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE"),cell_ordinal:I(12,15),
  classification:E("RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),reconciliation_sha256:HEX)
```

Linux status is a function, never an asserted label: nonnegative return means
`SUCCESS`; `-1` with valid immediate `errno==EINTR(4)` means `INTERRUPTED`;
`-1` with valid immediate nonzero errno other than 4 means `FAILURE`.  Any
other return/error pair rejects.  Kernel-only restart codes cannot appear at
this libc boundary.  `cell_ordinal=4*status_ordinal+poststate_ordinal` for a
return and `12+poststate_ordinal` for no return.  Classification is the exact
16-cell function retained in section 19.9 and is recomputed from those two
derived values.  The reconciliation hash uses domain
`PROGRAM_FACTS_G3_LINUX_NO_RETURN_RECONCILIATION_V1` and every preceding
member; the returned-outcome hash analogously uses
`PROGRAM_FACTS_G3_LINUX_RETURNED_OUTCOME_V1`.  Neither can hash an asserted
classification without first proving equality to the derived classification.

### 20.4 Windows directory, namespace, reopen, and eight-seam types

The R3.5 x64 `FILE_RENAME_INFO` offsets, absolute extended-volume path,
`RootDirectory=NULL`, class value 22, length excluding NUL, explicit NUL, and
aligned zero tail remain exact.  The shared regular-file `handle_identity` is
no longer used for a directory, and Linux observation unions are no longer
used for Windows names.

```text
vector_windows_directory_handle_identity_r3_6 =
O(kind:C("DIRECTORY"),handle_value_u64:S(16,16,"^[0-9a-f]{16}$"),
  volume_serial_number_u64:S(16,16,"^[0-9a-f]{16}$"),
  file_id_128:S(32,32,"^[0-9a-f]{32}$"),
  open_flags:C(["FILE_FLAG_BACKUP_SEMANTICS","FILE_FLAG_OPEN_REPARSE_POINT"]),
  access_mask:C(["FILE_READ_ATTRIBUTES","FILE_TRAVERSE"]),
  share_mask:C(["FILE_SHARE_READ","FILE_SHARE_WRITE","FILE_SHARE_DELETE"]),
  identity_sha256:HEX)

vector_windows_path_handle_binding_r3_6 =
O(full_absolute_utf16le:R(vector_exact_native_bytes),
  parent_handle:R(vector_windows_directory_handle_identity_r3_6),
  parent_file_id:R(windows_file_identity),leaf_utf16le:R(vector_exact_native_bytes),
  nofollow_leaf_present:B,leaf_reopen_file_id:Q(R(windows_file_identity)),
  prefix_volume_guid_matches_parent:C(true),
  parent_prefix_reopens_to_parent:C(true),binding_sha256:HEX)

vector_windows_name_presence_observation_r3_6 =
O(full_absolute_utf16le:R(vector_exact_native_bytes),
  parent_handle:R(vector_windows_directory_handle_identity_r3_6),
  parent_file_id:R(windows_file_identity),leaf_utf16le:R(vector_exact_native_bytes),
  nofollow:C(true),presence:E("ABSENT","PRESENT","UNOBSERVABLE"),
  observed_file_id:Q(R(windows_file_identity)),observation_sha256:HEX)

vector_windows_reopen_observation_r3_6 =
O(full_absolute_utf16le:R(vector_exact_native_bytes),
  nofollow:C(true),reopened:B,reopened_file_id:Q(R(windows_file_identity)),
  error_valid:B,last_error_u32:I(0,4294967295),observation_sha256:HEX)

vector_windows_rename_request_r3_6 =
O(profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  information_class:C("FileRenameInfoEx"),information_class_u32:C(22),
  source_handle:R(handle_identity),source_file_id:R(windows_file_identity),
  source_path_binding:R(vector_windows_path_handle_binding_r3_6),
  destination_path_binding:R(vector_windows_path_handle_binding_r3_6),
  root_directory_u64:C(0),flags_u32:C(0),file_name_length_u32:I(2,16777194),
  terminator:C("0000"),allocation_size:I(24,16777216),
  input_buffer:R(vector_exact_native_bytes),request_sha256:HEX)

vector_windows_rename_returned_r3_6 =
O(completion_kind:C("RETURNED"),request:R(vector_windows_rename_request_r3_6),
  bool_return:E(0,1),error_valid:B,last_error_captured_immediately:I(0,4294967295),
  retained_source_handle_file_id_after:R(windows_file_identity),
  source_name:R(vector_windows_name_presence_observation_r3_6),
  destination_name:R(vector_windows_name_presence_observation_r3_6),
  destination_reopen:R(vector_windows_reopen_observation_r3_6),
  destination_parent_file_id_after:R(windows_file_identity),
  predicate:R(vector_native_postcondition_predicate_r3_6),
  evaluation:R(vector_native_postcondition_evaluation_r3_6),
  return_status:E("SUCCESS","FAILURE","INTERRUPTED"),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE"),cell_ordinal:I(0,11),
  classification:E("API_SEMANTIC_SUCCESS","API_FAILURE_NO_RETRY",
    "RESUME_FROM_EFFECT_NO_REPLAY","RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),postcondition_sha256:HEX)

vector_windows_rename_no_return_r3_6 =
O(completion_kind:C("NO_RETURN"),reason:C("PROCESS_CRASH"),
  request:R(vector_windows_rename_request_r3_6),result_frame:C(null),
  crash_seam_ordinal:I(0,7),crash_seam:E("BEFORE_ENTRY",
    "AFTER_REQUEST_DURABLE","DURING_CALL","AFTER_EFFECT_BEFORE_RETURN",
    "AFTER_RETURN_BEFORE_ERROR_CAPTURE","AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE",
    "DURING_POSTSTATE","AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER"),
  source_name:R(vector_windows_name_presence_observation_r3_6),
  destination_name:R(vector_windows_name_presence_observation_r3_6),
  destination_reopen:R(vector_windows_reopen_observation_r3_6),
  predicate:R(vector_native_postcondition_predicate_r3_6),
  evaluation:R(vector_native_postcondition_evaluation_r3_6),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE"),cell_ordinal:I(12,15),
  classification:E("RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),reconciliation_sha256:HEX)
```

Both path bindings are completed before entry.  The source binding must be
present, its no-follow reopened file ID must equal `source_file_id`, and that
ID must equal the retained source handle's `FILE_ID_INFO`; the destination
binding must prove the retained destination directory handle and exact parent
prefix before accepting the request.  This is the symmetrical source and
destination path-to-handle predicate missing in R3.5.

The allocation is exactly `ALIGN_UP(20+FileNameLength+2,8)`, not C `sizeof`
plus the flexible member.  Bytes 4..7, 8..15, the two-byte terminator, and
every byte after the terminator through allocation end are zero.  Each zero
position is checked, not sampled.  The destination full path bytes occupy
exactly `[20,20+FileNameLength)`.

Windows status is derived: BOOL 1 with invalid error is `SUCCESS`; BOOL 0 with
valid `ERROR_OPERATION_ABORTED(995)` is `INTERRUPTED`; BOOL 0 with any other
valid nonzero error is `FAILURE`.  All other pairs reject.  Its cell and
classification functions are the same as Linux.  Expected effect requires
source ABSENT, destination PRESENT, destination reopen ID equal to the
pre-call source ID, retained source-handle ID continuity, and unchanged
destination-parent ID.  No effect requires source PRESENT with the same ID,
destination ABSENT, and unchanged parents.  The pre-bound relational predicate
derives every other complete combination as wrong effect.

The controlling crash seams for Linux and Windows are the same ordered eight:
`BEFORE_ENTRY`, `AFTER_REQUEST_DURABLE`, `DURING_CALL`,
`AFTER_EFFECT_BEFORE_RETURN`, `AFTER_RETURN_BEFORE_ERROR_CAPTURE`,
`AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE`, `DURING_POSTSTATE`, and
`AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER`.  The Windows no-return type no
longer omits ordinals 1 or 5.  The final name uses `...JOURNAL_OR_BARRIER` for
both platforms; the R3.5 abbreviated Windows spelling is superseded.

The Windows hashes exclude only their own final hash member and include every
preceding member in displayed order under these exact domains: directory
handle `PROGRAM_FACTS_G3_WINDOWS_DIRECTORY_HANDLE_IDENTITY_V1`; path binding
`PROGRAM_FACTS_G3_WINDOWS_PATH_HANDLE_BINDING_V1`; name presence
`PROGRAM_FACTS_G3_WINDOWS_NAME_PRESENCE_OBSERVATION_V1`; reopen
`PROGRAM_FACTS_G3_WINDOWS_REOPEN_OBSERVATION_V1`; request
`PROGRAM_FACTS_G3_WINDOWS_RENAME_REQUEST_V3`; returned postcondition
`PROGRAM_FACTS_G3_WINDOWS_RENAME_POSTCONDITION_V3`; and no-return
reconciliation `PROGRAM_FACTS_G3_WINDOWS_RENAME_RECONCILIATION_V3`.

### 20.5 Non-self review records and exact provenance/platform joins

A review body is serialized without any identity derived from its containing
file.  A consumer then binds that already serialized body to an outer file
identity.  This removes the R3.5 review-artifact self-reference:

```text
vector_native_review_body_r3_6 =
O(review_role:E("INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW",
    "LAYOUT_ORACLE_REVIEW","IMPLEMENTATION_REVIEW",
    "SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW","RECEIPT_REVIEW",
    "NATIVE_AUTHORITY_REVIEW"),reviewer_principal:S1,
  subject_identities:A(R(file_identity),1,256,true),
  predecessor_identities:A(R(file_identity),0,256,true),
  subject_author_principals:A(S1,1,256,false),
  reviewer_distinct_from_subject_authors:C(true),self_review:C(false),
  future_subject_count:C(0),disposition:E("PASS_NONAUTHORITATIVE","REPAIR"),
  review_body_sha256:HEX)

vector_native_review_artifact_binding_r3_6 =
O(artifact:R(file_identity),body:R(vector_native_review_body_r3_6),
  canonical_body_bytes:R(content_identity),artifact_parses_exact_body:C(true),
  binding_sha256:HEX)
```

`review_body_sha256 = SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_NATIVE_REVIEW_BODY_V1",review_role,reviewer_principal,
subject_identities,predecessor_identities,subject_author_principals,
reviewer_distinct_from_subject_authors:true,self_review:false,
future_subject_count:0,disposition}))`.  `canonical_body_bytes` is `CF(body)`;
the outer artifact's content size/digest must equal those bytes.
`binding_sha256` hashes domain
`PROGRAM_FACTS_G3_NATIVE_REVIEW_ARTIFACT_BINDING_V1`, `artifact`, `body`, and
`canonical_body_bytes`.  The binding lives in the consumer, never inside the
review artifact it identifies.

The complete temporal DAG is the parsed constant below.  `BUILD_RECEIPT` and
`HOST_EXECUTION_RECEIPT` are typed artifact nodes; every other node is the
matching review role.  This evidence DAG is unrelated to, and does not
implement, the deferred 15-edge admission bridge.

<!-- BEGIN VECTOR_NATIVE_REVIEW_DAG_R3_6 -->
```json
{"edges":[["INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW"],["INPUT_PROVENANCE_REVIEW","BUILD_RECEIPT"],["BUILD_PLAN_REVIEW","BUILD_RECEIPT"],["BUILD_RECEIPT","LAYOUT_ORACLE_REVIEW"],["BUILD_RECEIPT","IMPLEMENTATION_REVIEW"],["LAYOUT_ORACLE_REVIEW","IMPLEMENTATION_REVIEW"],["IMPLEMENTATION_REVIEW","SEMANTIC_DERIVATION_REVIEW"],["IMPLEMENTATION_REVIEW","FACILITY_REVIEW"],["IMPLEMENTATION_REVIEW","HOST_EXECUTION_RECEIPT"],["SEMANTIC_DERIVATION_REVIEW","HOST_EXECUTION_RECEIPT"],["FACILITY_REVIEW","HOST_EXECUTION_RECEIPT"],["HOST_EXECUTION_RECEIPT","RECEIPT_REVIEW"],["LAYOUT_ORACLE_REVIEW","RECEIPT_REVIEW"],["SEMANTIC_DERIVATION_REVIEW","RECEIPT_REVIEW"],["FACILITY_REVIEW","RECEIPT_REVIEW"],["RECEIPT_REVIEW","NATIVE_AUTHORITY_REVIEW"],["IMPLEMENTATION_REVIEW","NATIVE_AUTHORITY_REVIEW"],["SEMANTIC_DERIVATION_REVIEW","NATIVE_AUTHORITY_REVIEW"],["FACILITY_REVIEW","NATIVE_AUTHORITY_REVIEW"]],"node_order":["INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW","BUILD_RECEIPT","LAYOUT_ORACLE_REVIEW","IMPLEMENTATION_REVIEW","SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW","HOST_EXECUTION_RECEIPT","RECEIPT_REVIEW","NATIVE_AUTHORITY_REVIEW"]}
```
<!-- END VECTOR_NATIVE_REVIEW_DAG_R3_6 -->

Every edge moves to a greater node ordinal.  Each review binds every immediate
predecessor and its already materialized subjects.  The fixed principal roles
are `SOURCE_VENDOR`, `BUILD_AUTHOR`, `LAYOUT_ORACLE_AUTHOR`,
`PRODUCTION_IMPLEMENTER`, `PREDICATE_ORACLE_AUTHOR`, `FACILITY_AUTHOR`,
`FIXTURE_AUTHOR`, `RECEIPT_AUTHOR`, `RECEIPT_REVIEWER`, and
`NATIVE_AUTHORITY_REVIEWER`.  The distinctness matrix is every unordered pair
of those ten roles, exactly 45 pairs; equality in any pair rejects.  Each
reviewer is additionally distinct from all authors of every transitive subject
it reviews.

Platform identity is typed rather than an opaque file label:

```text
vector_native_linux_platform_identity_r3_6 =
O(platform:C("LINUX"),profile:E("LINUX_X86_64_LP64_LE",
    "LINUX_AARCH64_LP64_LE"),architecture:E("x86_64","aarch64"),
  kernel_release:S1,kernel_build_id:S1,kernel_image:R(file_identity),
  syscall_number_header:R(file_identity),loader:R(file_identity),
  libc:R(file_identity),libc_version:S1,filesystem_type:S1,
  filesystem_uuid:S1,mount_options:A(S1,0,128,false),
  retained_directory_handle_profile:C("SAME_MOUNT_RETAINED_DIR_HANDLES"),
  power_loss_capability:C(true),accepting_authority:C(false),
  platform_sha256:HEX)

vector_native_windows_platform_identity_r3_6 =
O(platform:C("WINDOWS"),
  profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  architecture:C("x86_64"),windows_build_number:S1,
  minimum_file_rename_info_ex_build:S1,kernel32:R(file_identity),
  ntdll:R(file_identity),ucrt:R(file_identity),windows_sdk_manifest:R(file_identity),
  filesystem_type:S1,volume_identity:R(windows_file_identity),
  ordinary_user_protected_root:C(true),power_loss_capability:C(false),
  process_crash_capability:C(true),accepting_authority:C(false),
  platform_sha256:HEX)

vector_native_platform_identity_r3_6 =
U(R(vector_native_linux_platform_identity_r3_6),
  R(vector_native_windows_platform_identity_r3_6))
```

The platform hash is SHA-256 of the matching object with domain
`PROGRAM_FACTS_G3_NATIVE_PLATFORM_IDENTITY_V1` and without its own hash.
Kernel/Windows build, architecture, filesystem, loader, libc/Kernel32, SDK,
and minimum Windows API build are therefore part of the equality join.  The
Linux capability bit describes only the future profile; it is not an authority
or enabling bit and cannot be copied to Windows.  macOS has no platform branch.

The effective toolchain and build types are:

```text
vector_native_toolchain_manifest_r3_6 =
O(platform:E("LINUX","WINDOWS"),target_triple:S1,
  compiler_path:PATH,compiler:R(file_identity),compiler_version:S1,
  linker_path:PATH,linker:R(file_identity),linker_version:S1,
  libc_or_crt_path:PATH,libc_or_crt:R(file_identity),libc_or_crt_version:S1,
  sdk_or_sysroot_path:PATH,sdk_or_sysroot_manifest:R(file_identity),
  compiler_flags:A(S1,1,128,false),linker_flags:A(S1,0,128,false),
  environment_keys:C([]),response_files:A(R(file_identity),0,16,true),
  toolchain_sha256:HEX)

vector_native_build_receipt_r3_6 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  source_row_count:I(1,64),source_row_stream_size_bytes:I(1,16777216),
  source_row_stream_sha256:HEX,header_row_count:I(1,128),
  header_row_stream_size_bytes:I(1,16777216),header_row_stream_sha256:HEX,
  toolchain:R(vector_native_toolchain_manifest_r3_6),command_frames:R(file_identity),
  stdout:R(content_identity),stderr:R(content_identity),exit_code:C(0),
  oracle_source:R(file_identity),oracle_binary:R(file_identity),
  production_source:R(file_identity),production_binary:R(file_identity),
  source_to_binary_join_sha256:HEX,receipt_sha256:HEX)

vector_native_build_manifest_r3_6 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  sources:A(R(vector_native_source_input),1,64,true),
  source_row_count:I(1,64),source_row_stream_size_bytes:I(1,16777216),
  source_row_stream_sha256:HEX,headers:A(R(vector_native_header_input),1,128,true),
  header_row_count:I(1,128),header_row_stream_size_bytes:I(1,16777216),
  header_row_stream_sha256:HEX,toolchain:R(vector_native_toolchain_manifest_r3_6),
  review_dag_bytes:R(content_identity),review_dag_object_size_bytes:C(1134),
  review_dag_object_sha256:C("981adeaf607221ca53b3991dd50944873e31605ea3675796f6d15f56b51bd26e"),
  layout_row_stream_sha256:C("b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a"),
  signature_core_row_stream_sha256:HEX,declaration_row_stream_sha256:HEX,
  declaration_bindings:A(R(vector_native_declaration_binding_r3_6),22,22,true),
  oracle_source:R(file_identity),oracle_binary:R(file_identity),
  production_source:R(file_identity),production_binary:R(file_identity),
  build_receipt:R(vector_native_build_receipt_r3_6),build_manifest_sha256:HEX)
```

`toolchain_sha256 = SHA-256(CJ({domain:
"PROGRAM_FACTS_G3_NATIVE_TOOLCHAIN_MANIFEST_V1",platform,target_triple,
compiler_path,compiler,compiler_version,linker_path,linker,linker_version,
libc_or_crt_path,libc_or_crt,libc_or_crt_version,sdk_or_sysroot_path,
sdk_or_sysroot_manifest,compiler_flags,linker_flags,environment_keys,
response_files}))`.  The source/header row counts equal array lengths and their
sizes/digests are over the exact ordinal `CONCAT(CJ(row)||LF)` streams.

`source_to_binary_join_sha256` hashes domain
`PROGRAM_FACTS_G3_NATIVE_SOURCE_TO_BINARY_JOIN_V2`, profile, all six source and
header count/size/digest members, `toolchain`, command frames, oracle source and
binary, production source and binary, and exit code zero.  `receipt_sha256`
hashes domain `PROGRAM_FACTS_G3_NATIVE_BUILD_RECEIPT_V2` and every preceding
receipt member including stdout, stderr, and that join.  It excludes only
itself.  The manifest requires parsed-value equality of all source/header
count/size/digests, toolchain, oracle identities, production identities, and
profile to the receipt.  Its hash uses domain
`PROGRAM_FACTS_G3_NATIVE_BUILD_MANIFEST_V2` and every preceding member except
itself.

The registered header roster is the complete transitive preprocessor read set;
the source/response roster is the complete compiler and linker read set.
Declaration bindings prove exact raw source slices and both architecture UAPI
numbers.  The executed binary in every later host or facility result is
parsed-value equal to this receipt's production binary.  A digest-only source,
ambient include, PATH-resolved tool, different loaded libc/Kernel32, or
source/binary/toolchain/profile splice rejects.

`review_dag_bytes` equals the exact 1,134-byte `CJ` serialization of the
marker-bounded DAG object above; its content identity equals the carried size
and digest constants.  A label, reordered edge, omitted review node, or other
object with a copied digest cannot satisfy the parsed-value join.

### 20.6 Typed evidence, eight-seam results, and actual-call coverage

The closed unavailability reasons are:
`RETURN_CELL_NOT_DETERMINISTICALLY_INDUCIBLE`,
`SEAM_NOT_DETERMINISTICALLY_STOPPABLE`, `SEAM_PROFILE_INAPPLICABLE`,
`OBSERVATION_CAPABILITY_UNAVAILABLE`, and
`NO_EVIDENCED_SEAM_PRODUCES_CELL`.  Free text is not a reason.  A materialized
receipt cannot use `BUILD_NOT_MATERIALIZED` or `HOST_NOT_MATERIALIZED`; those
conditions select the aggregate unmaterialized branch instead of producing
synthetic rows.

```text
vector_native_unavailability_proof_r3_6 =
O(reason:E("RETURN_CELL_NOT_DETERMINISTICALLY_INDUCIBLE",
    "SEAM_NOT_DETERMINISTICALLY_STOPPABLE","SEAM_PROFILE_INAPPLICABLE",
    "OBSERVATION_CAPABILITY_UNAVAILABLE",
    "NO_EVIDENCED_SEAM_PRODUCES_CELL"),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  matrix_ordinal:Q(I(0,719)),seam_matrix_ordinal:Q(I(0,359)),
  capability_roster:R(file_identity),proof_source:R(file_identity),
  proof_review:R(vector_native_review_artifact_binding_r3_6),
  admissibility_predicate:E("RETURN_STATUS_CONTROL_ANALYSIS",
    "FACILITY_STOP_CAPABILITY_ANALYSIS",
    "PROFILE_SEAM_SEMANTIC_INAPPLICABILITY",
    "FRESH_OBSERVATION_CAPABILITY_ANALYSIS",
    "SEAM_TO_CELL_COVERAGE_ANALYSIS"),proof_sha256:HEX)

vector_native_static_layout_evidence_r3_6 =
O(evidence_class:C("STATIC_LAYOUT"),evidence_artifact:R(file_identity),
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  build_manifest:R(vector_native_build_manifest_r3_6),
  layout_oracle_source:R(file_identity),layout_oracle_binary:R(file_identity),
  layout_oracle_review:R(vector_native_review_artifact_binding_r3_6),
  compile_receipt:R(vector_native_build_receipt_r3_6),
  static_assertion_results:R(content_identity),
  static_assertion_row_count:I(1,4096),
  static_assertion_row_stream_sha256:HEX,host_semantics_proved:C(false),
  crash_timing_proved:C(false),durability_proved:C(false),
  authoritative:C(false),evidence_sha256:HEX)

vector_native_stress_evidence_r3_6 =
O(evidence_class:C("STRESS_NONAUTHORITATIVE"),evidence_artifact:R(file_identity),
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  runner:R(file_identity),iterations:I(1,9007199254740991),
  executed_production_binary:R(file_identity),results:R(content_identity),
  completeness_claim:C(false),timing_authority:C(false),
  durability_proved:C(false),authoritative:C(false),evidence_sha256:HEX)

vector_native_host_subresult_r3_6 =
O(subresult_ordinal:I(0,351),matrix_ordinal:I(0,719),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  outcome:R(vector_linux_returned_outcome_r3_6),subresult_sha256:HEX)

vector_windows_host_subresult_r3_6 =
O(subresult_ordinal:I(0,15),matrix_ordinal:I(704,719),
  outcome:R(vector_windows_rename_returned_r3_6),subresult_sha256:HEX)

vector_native_host_semantics_evidence_r3_6 =
O(evidence_class:C("HOST_SEMANTICS"),evidence_artifact:R(file_identity),
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  platform_identity:R(vector_native_platform_identity_r3_6),
  fixture_source:R(file_identity),fixture_binary:R(file_identity),
  executed_production_binary:R(file_identity),
  linux_results:Q(A(R(vector_native_host_subresult_r3_6),1,352,true)),
  windows_results:Q(A(R(vector_windows_host_subresult_r3_6),1,16,true)),
  subresult_row_stream_size_bytes:I(1,16777216),
  subresult_row_stream_sha256:HEX,authoritative:C(false),evidence_sha256:HEX)

vector_native_linux_seam_subresult_r3_6 =
O(subresult_ordinal:I(0,175),seam_matrix_ordinal:I(0,351),
  matrix_ordinal:I(0,703),outcome:R(vector_linux_no_return_outcome_r3_6),
  subresult_sha256:HEX)

vector_native_windows_seam_subresult_r3_6 =
O(subresult_ordinal:I(0,7),seam_matrix_ordinal:I(352,359),
  matrix_ordinal:I(704,719),outcome:R(vector_windows_rename_no_return_r3_6),
  subresult_sha256:HEX)

vector_native_governed_instrumentation_evidence_r3_6 =
O(evidence_class:C("GOVERNED_INSTRUMENTATION"),
  evidence_artifact:R(file_identity),
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  platform_identity:R(vector_native_platform_identity_r3_6),
  facility_kind:E("LINUX_FAULT_INJECTION_PROFILE",
    "WINDOWS_DEBUGGER_SUSPEND_PROFILE"),facility_source:R(file_identity),
  facility_binary:R(file_identity),facility_configuration:R(file_identity),
  facility_review:R(vector_native_review_artifact_binding_r3_6),
  executed_production_binary:R(file_identity),
  linux_results:Q(A(R(vector_native_linux_seam_subresult_r3_6),1,176,true)),
  windows_results:Q(A(R(vector_native_windows_seam_subresult_r3_6),1,8,true)),
  subresult_row_stream_size_bytes:I(1,16777216),
  subresult_row_stream_sha256:HEX,stress_only:C(false),
  durability_proved:C(false),authoritative:C(false),evidence_sha256:HEX)

vector_native_evidence_locator_r3_6 =
O(evidence_class:E("HOST_SEMANTICS","GOVERNED_INSTRUMENTATION"),
  evidence_artifact:R(file_identity),subresult_ordinal:I(0,351),
  subresult_sha256:HEX,locator_sha256:HEX)
```

Every subresult hash uses its displayed members and these exact domains:
`PROGRAM_FACTS_G3_NATIVE_HOST_SUBRESULT_V1`,
`PROGRAM_FACTS_G3_WINDOWS_HOST_SUBRESULT_V1`,
`PROGRAM_FACTS_G3_NATIVE_LINUX_SEAM_SUBRESULT_V1`, and
`PROGRAM_FACTS_G3_NATIVE_WINDOWS_SEAM_SUBRESULT_V1`.  Static, stress, host, and
governed evidence use `PROGRAM_FACTS_G3_NATIVE_STATIC_LAYOUT_EVIDENCE_V1`,
`PROGRAM_FACTS_G3_NATIVE_STRESS_EVIDENCE_V1`,
`PROGRAM_FACTS_G3_NATIVE_HOST_SEMANTICS_EVIDENCE_V1`, and
`PROGRAM_FACTS_G3_NATIVE_GOVERNED_INSTRUMENTATION_EVIDENCE_V1` respectively.
Each hash includes every preceding member and excludes only itself.
`proof_sha256`, `locator_sha256`, and `coverage_sha256` use domains
`PROGRAM_FACTS_G3_NATIVE_UNAVAILABILITY_PROOF_V1`,
`PROGRAM_FACTS_G3_NATIVE_EVIDENCE_LOCATOR_V1`, and
`PROGRAM_FACTS_G3_NATIVE_ACTUAL_OPERATION_COVERAGE_V1` with the same rule.
Evidence hashes include the complete subresult array.  A locator resolves by
parsed-value equality to exactly one
subresult in the matching evidence object carried by the same profile receipt;
unresolved, duplicate, cross-class, or cross-profile locators reject.  Stress
evidence and static-layout evidence have no locator branch and cannot close an
outcome or seam.

The crash-seam contract roster is generated from the exact 45 API/profile rows
and the controlling eight seams: `seam_matrix_ordinal =
8*api_profile_ordinal+seam_ordinal`.  It therefore has exactly 360 rows.  The
x86-64 Linux and AArch64 Linux profile slices each have 176 rows, and Windows
has 8.  Its result type is total:

```text
vector_native_crash_seam_result_r3_6 =
O(seam_matrix_ordinal:I(0,359),profile_local_seam_ordinal:I(0,175),
  api_profile_ordinal:I(0,44),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),seam_ordinal:I(0,7),
  crash_seam:E("BEFORE_ENTRY","AFTER_REQUEST_DURABLE","DURING_CALL",
    "AFTER_EFFECT_BEFORE_RETURN","AFTER_RETURN_BEFORE_ERROR_CAPTURE",
    "AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE","DURING_POSTSTATE",
    "AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER"),
  availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  evidence_locator:Q(R(vector_native_evidence_locator_r3_6)),
  unavailable:Q(R(vector_native_unavailability_proof_r3_6)),
  observed_poststate:Q(E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE")),matrix_ordinal:Q(I(0,719)),
  classification:Q(E("RECONCILE_NO_REPLAY","QUARANTINE")),
  retry_allowed:C(false),result_sha256:HEX)
```

An evidenced seam has exactly one governed locator, no unavailable proof, and
its subresult's seam/API/profile/poststate/cell/classification equal this row.
An unavailable seam has the reverse nullability and a proof admissible for
that exact seam.  `SEAM_PROFILE_INAPPLICABLE` requires a selector rule proving
the named seam cannot exist on that profile; it cannot be used merely because
a facility is inconvenient.  All eight rows remain present in either case.

The five reason/predicate pairs in enum order are exact:
`RETURN_CELL_NOT_DETERMINISTICALLY_INDUCIBLE -> RETURN_STATUS_CONTROL_ANALYSIS`,
`SEAM_NOT_DETERMINISTICALLY_STOPPABLE -> FACILITY_STOP_CAPABILITY_ANALYSIS`,
`SEAM_PROFILE_INAPPLICABLE -> PROFILE_SEAM_SEMANTIC_INAPPLICABILITY`,
`OBSERVATION_CAPABILITY_UNAVAILABLE -> FRESH_OBSERVATION_CAPABILITY_ANALYSIS`,
and `NO_EVIDENCED_SEAM_PRODUCES_CELL -> SEAM_TO_CELL_COVERAGE_ANALYSIS`.
A mismatched pair rejects before its proof hash is considered.

`vector_native_crash_seam_result_r3_6.result_sha256` is SHA-256 of domain
`PROGRAM_FACTS_G3_NATIVE_CRASH_SEAM_RESULT_V1` and every preceding member;
only the result hash is excluded.

Actual operations are covered one-to-one rather than being assumed from an
adjacent receipt:

```text
vector_native_actual_operation_coverage_r3_6 =
O(coverage_ordinal:I(0,527),completion_kind:E("RETURNED","NO_RETURN"),
  operation_id:S1,operation_sha256:HEX,api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  semantic_case_sha256:HEX,matrix_ordinal:I(0,719),
  seam_matrix_ordinal:Q(I(0,359)),evidence_locator:R(vector_native_evidence_locator_r3_6),
  build_manifest_sha256:HEX,executed_production_binary:R(file_identity),
  platform_sha256:HEX,coverage_sha256:HEX)
```

Every host returned subresult and every governed no-return subresult has one
coverage row; no other row is allowed.  The operation ID/hash equals the typed
outcome's call ID/hash or no-return reconciliation identity, the matrix and
seam ordinals equal its derived cell, and the evidence locator resolves to that
same subresult.  Build manifest, executed production binary, and platform equal
the enclosing profile receipt.  Unavailable contract rows have no coverage
row and are excluded only by their typed proof.  Coverage ordinals are unique
and contiguous, and the coverage count equals the exact number of resolved
subresults.  This is the effective call/receipt/source/binary/toolchain/platform
join.

### 20.7 Profile receipts, aggregate receipt, and operative authority

Outcome rows remain the 720-row global contract matrix, but materialized
evidence is profile-scoped.  Linux local ordinal is
`16*signature_ordinal+cell_ordinal`; its global ordinal is
`32*signature_ordinal+16*linux_profile_ordinal+cell_ordinal`, where x86-64 is
profile ordinal zero and AArch64 one.  Windows local ordinals 0..15 map to
global 704..719.  The analogous seam formulas use multipliers 8 and 16.

```text
vector_native_outcome_result_r3_6 =
O(matrix_ordinal:I(0,719),profile_local_ordinal:I(0,351),
  api_profile_ordinal:I(0,44),cell_ordinal:I(0,15),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  semantic_case_sha256:HEX,availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  evidence_locators:A(R(vector_native_evidence_locator_r3_6),0,8,true),
  unavailable:Q(R(vector_native_unavailability_proof_r3_6)),
  return_status:Q(E("SUCCESS","FAILURE","INTERRUPTED")),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE"),classification:E("API_SEMANTIC_SUCCESS",
    "API_FAILURE_NO_RETRY","RESUME_FROM_EFFECT_NO_REPLAY",
    "RECONCILE_NO_REPLAY","QUARANTINE"),retry_allowed:C(false),
  result_sha256:HEX)

vector_native_profile_receipt_r3_6 =
U(O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
    platform_identity:R(vector_native_platform_identity_r3_6),
    provenance:R(vector_native_build_manifest_r3_6),
    static_layout_evidence:R(vector_native_static_layout_evidence_r3_6),
    host_semantics:Q(R(vector_native_host_semantics_evidence_r3_6)),
    governed_instrumentation:Q(R(vector_native_governed_instrumentation_evidence_r3_6)),
    stress_evidence:Q(R(vector_native_stress_evidence_r3_6)),
    outcome_results:A(R(vector_native_outcome_result_r3_6),352,352,true),
    outcome_result_count:C(352),outcome_result_row_stream_size_bytes:I(1,16777216),
    outcome_result_row_stream_sha256:HEX,
    seam_results:A(R(vector_native_crash_seam_result_r3_6),176,176,true),
    seam_result_count:C(176),seam_result_row_stream_size_bytes:I(1,16777216),
    seam_result_row_stream_sha256:HEX,
    actual_operation_coverage:A(R(vector_native_actual_operation_coverage_r3_6),22,528,true),
    coverage_row_stream_size_bytes:I(1,16777216),coverage_row_stream_sha256:HEX,
    receipt_review:R(vector_native_review_artifact_binding_r3_6),
    disposition:C("MATERIALIZED_PROFILE_EVIDENCE_NONAUTHORITATIVE"),
    authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),durability_authority:C(false),profile_receipt_sha256:HEX),
  O(profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
    platform_identity:R(vector_native_platform_identity_r3_6),
    provenance:R(vector_native_build_manifest_r3_6),
    static_layout_evidence:R(vector_native_static_layout_evidence_r3_6),
    host_semantics:Q(R(vector_native_host_semantics_evidence_r3_6)),
    governed_instrumentation:Q(R(vector_native_governed_instrumentation_evidence_r3_6)),
    stress_evidence:Q(R(vector_native_stress_evidence_r3_6)),
    outcome_results:A(R(vector_native_outcome_result_r3_6),16,16,true),
    outcome_result_count:C(16),outcome_result_row_stream_size_bytes:I(1,16777216),
    outcome_result_row_stream_sha256:HEX,
    seam_results:A(R(vector_native_crash_seam_result_r3_6),8,8,true),
    seam_result_count:C(8),seam_result_row_stream_size_bytes:I(1,16777216),
    seam_result_row_stream_sha256:HEX,
    actual_operation_coverage:A(R(vector_native_actual_operation_coverage_r3_6),1,24,true),
    coverage_row_stream_size_bytes:I(1,16777216),coverage_row_stream_sha256:HEX,
    receipt_review:R(vector_native_review_artifact_binding_r3_6),
    disposition:C("MATERIALIZED_PROFILE_EVIDENCE_NONAUTHORITATIVE"),
    authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),durability_authority:C(false),profile_receipt_sha256:HEX))

vector_native_aggregate_outcome_index_r3_6 =
O(matrix_ordinal:I(0,719),profile_ordinal:I(0,2),
  profile_local_ordinal:I(0,351),profile_result_sha256:HEX)

vector_native_aggregate_seam_index_r3_6 =
O(seam_matrix_ordinal:I(0,359),profile_ordinal:I(0,2),
  profile_local_seam_ordinal:I(0,175),profile_result_sha256:HEX)

vector_native_execution_receipt_r3_6 =
U(O(state:C("UNMATERIALIZED_STABLE_DRAFT"),subject:C(null),
    profile_receipts:C(null),aggregate_outcome_index:C(null),
    aggregate_seam_index:C(null),aggregate_receipt_sha256:C(null),
    disposition:C("STABLE_DRAFT_NONAUTHORITATIVE"),authoritative:C(false),
    production_execution_allowed:C(false),spawn_allowed:C(false),
    durability_authority:C(false)),
  O(state:C("MATERIALIZED_AGGREGATE_NONAUTHORITATIVE"),subject:R(file_identity),
    profile_receipts:A(R(vector_native_profile_receipt_r3_6),3,3,false),
    aggregate_outcome_index:A(R(vector_native_aggregate_outcome_index_r3_6),720,720,true),
    aggregate_seam_index:A(R(vector_native_aggregate_seam_index_r3_6),360,360,true),
    atomic_contract_evidence:R(vector_r3_6_atomic_evidence_bundle),
    aggregate_outcome_row_stream_size_bytes:I(1,16777216),
    aggregate_outcome_row_stream_sha256:HEX,
    aggregate_seam_row_stream_size_bytes:I(1,16777216),
    aggregate_seam_row_stream_sha256:HEX,
    aggregate_receipt_sha256:HEX,
    disposition:C("MATERIALIZED_AGGREGATE_EVIDENCE_NONAUTHORITATIVE"),
    authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),durability_authority:C(false)))
```

Profile receipt order is exactly x86-64 Linux, AArch64 Linux, Windows.  Counts
are exactly 352/352/16 outcomes and 176/176/8 seams according to profile, not
merely any allowed enum value.  Each profile manifest, platform, evidence,
executed binary, results, unavailability proofs, and coverage rows name that
same profile.  A materialized Linux profile must evidence at least the
returned `SUCCESS/EXPECTED_EFFECT` cell for every one of its 22 APIs; Windows
must evidence that returned cell for rename.  Every other unavailable returned
cell needs its exact reviewed inducibility/capability proof.  Thus an all-
unavailable materialized profile is invalid.

For `cell_ordinal<12`, EVIDENCED means exactly one HOST_SEMANTICS locator and
no unavailable proof; the located returned envelope's derived status,
poststate, cell, and classification equal the row.  For `cell_ordinal>=12`,
EVIDENCED means one through eight GOVERNED_INSTRUMENTATION locators and no
unavailable proof; every located seam result maps to that same derived
poststate/cell/classification.  UNAVAILABLE means zero locators and exactly one
admissible proof.  The row's status is null exactly for no-return cells, while
poststate and classification always equal the immutable matrix contract.

Each profile result hash uses domain
`PROGRAM_FACTS_G3_NATIVE_OUTCOME_RESULT_V2` and every preceding member.  Each
row stream is `CONCAT(CJ(row)||LF)` in profile-local order.  The two aggregate
indices are in global ordinal order, cover every ordinal once, and their result
hashes equal the indexed profile rows.  `aggregate_receipt_sha256` hashes
domain `PROGRAM_FACTS_G3_NATIVE_AGGREGATE_RECEIPT_V1`, subject, all three
profile receipts, both complete indices, the atomic contract bundle, all four aggregate size/digest
members, the disposition, and every false flag.  It excludes only itself.

`profile_receipt_sha256` uses domain
`PROGRAM_FACTS_G3_NATIVE_PROFILE_RECEIPT_V1` and every preceding profile-
receipt member, including complete outcome, seam, and coverage arrays and all
false flags; it excludes only itself.  Each index row is content addressed by
its referenced profile-result hash, and the aggregate row-stream digests bind
their full ordered CJ rows.

The effective authority is:

```text
vector_native_ffi_authority_r3_6 =
U(O(state:C("UNMATERIALIZED_PROVENANCE"),subject:C(null),
    execution_receipt:R(vector_native_execution_receipt_r3_6),
    authority_join_sha256:C(null),
    disposition:C("STABLE_DRAFT_NONAUTHORITATIVE"),
    evidence_authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),publication_allowed:C(false),cutover_allowed:C(false),
    durability_authority:C(false)),
  O(state:C("MATERIALIZED_REVIEWED_NONAUTHORITATIVE"),subject:R(file_identity),
    execution_receipt:R(vector_native_execution_receipt_r3_6),
    implementation_review:R(vector_native_review_artifact_binding_r3_6),
    semantic_derivation_review:R(vector_native_review_artifact_binding_r3_6),
    receipt_review:R(vector_native_review_artifact_binding_r3_6),
    independent_native_review:R(vector_native_review_artifact_binding_r3_6),
    authority_join_sha256:HEX,
    disposition:C("MATERIALIZED_REVIEWED_NONAUTHORITATIVE"),
    evidence_authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),publication_allowed:C(false),cutover_allowed:C(false),
    durability_authority:C(false)))
```

The materialized authority join hashes every preceding member with domain
`PROGRAM_FACTS_G3_NATIVE_FFI_AUTHORITY_JOIN_V2`, excluding only itself.  Review
subjects and predecessors must follow the section-20.5 DAG and bind the exact
aggregate receipt, all three manifests/platforms/binaries, predicate oracle,
facilities, and actual-operation coverage.

Every effective confirmed, uncertain, and no-spawn post-operation object
carries both the R3.6 authority and R3.6 aggregate receipt.  The separately
carried receipt is parsed-value equal to the authority's embedded receipt.
The R3.6 `post_operation_id` preimage is the section-18 V2 member list with
those two R3.6 values in their displayed positions.  The direct repair in
section 18.2 makes the uncertain branch constructible.  The R3.5 statement
that an authority object is carried by each call is superseded: that would
create a call->receipt->result->call cycle.  Authority instead reaches every
actual call/no-return operation through the post-operation root, aggregate
receipt, profile receipt, and exact coverage row.  Effective root traversal
must cover confirmed success, no-spawn, uncertain-spawn, quarantine process
basis, and spawn-uncertainty observation roots.

### 20.8 Total atomic result contract and repaired negative rosters

The effective signature/dependency negative roster is:

<!-- BEGIN VECTOR_NATIVE_SIGNATURE_NEGATIVES_R3_6 -->
```json
[
{"diagnostic":"SIGNATURE_WIDTH_SIGN","expected":"U16_LE","mutated":"U32_LE","ordinal":0,"target":"mkdirat.mode"},
{"diagnostic":"SIGNATURE_WIDTH_SIGN","expected":"U16_LE","mutated":"U32_LE","ordinal":1,"target":"openat.mode"},
{"diagnostic":"SIGNATURE_WIDTH_SIGN","expected":"U32_LE","mutated":"S32_LE","ordinal":2,"target":"read.fd"},
{"diagnostic":"SIGNATURE_WIDTH_SIGN","expected":"U32_LE","mutated":"S32_LE","ordinal":3,"target":"write.fd"},
{"diagnostic":"SIGNATURE_WIDTH_SIGN","expected":"U32_LE","mutated":"S32_LE","ordinal":4,"target":"pread64.fd"},
{"diagnostic":"SIGNATURE_WIDTH_SIGN","expected":"U32_LE","mutated":"S32_LE","ordinal":5,"target":"fstat.fd"},
{"diagnostic":"SIGNATURE_WIDTH_SIGN","expected":"U32_LE","mutated":"S32_LE","ordinal":6,"target":"statx.flags"},
{"diagnostic":"DECLARATION_RETURN_TYPE","expected":"long","mutated":"ssize_t","ordinal":7,"target":"read.declaration"},
{"diagnostic":"DECLARATION_RETURN_TYPE","expected":"long","mutated":"ssize_t","ordinal":8,"target":"write.declaration"},
{"diagnostic":"DECLARATION_RETURN_TYPE","expected":"long","mutated":"ssize_t","ordinal":9,"target":"pread64.declaration"},
{"diagnostic":"DECLARATION_RETURN_TYPE","expected":"long","mutated":"ssize_t","ordinal":10,"target":"readlinkat.declaration"},
{"diagnostic":"DECLARATION_NAME","expected":"sys_newfstat","mutated":"sys_fstat","ordinal":11,"target":"fstat.declaration_name"},
{"diagnostic":"DECLARATION_STRUCT_TARGET","expected":"struct stat","mutated":"struct __old_kernel_stat","ordinal":12,"target":"fstat.struct_target"},
{"diagnostic":"UAPI_ARCH_MAPPING","expected":"BOTH_PINNED_ARCH_ROWS","mutated":"WRONG_NUMBER_OR_ALIAS","ordinal":13,"target":"declaration_binding.uapi_number"},
{"diagnostic":"DECLARATION_SOURCE_SLICE","expected":"EXACT_PINNED_SLICE","mutated":"SAME_TEXT_UNBOUND_HEADER","ordinal":14,"target":"declaration_binding.source_slice"},
{"diagnostic":"CALL_LAYER_MISMATCH","expected":"LIBC_SYSCALL_REGISTER_WORDS_V1","mutated":"RAW_SYSCALL_NEGATIVE_ERRNO","ordinal":15,"target":"binding.call_layer"},
{"diagnostic":"ERROR_CONVENTION_MISMATCH","expected":"LIBC_MINUS1_ERRNO_V1","mutated":"RAW_NEGATIVE_ERRNO","ordinal":16,"target":"binding.error_convention"},
{"diagnostic":"PROFILE_BINDING_MISMATCH","expected":"BOTH_EXACT_LINUX_PROFILES","mutated":"OMIT_AARCH64","ordinal":17,"target":"binding.abi_profiles"},
{"diagnostic":"POINTEE_DEPENDENCY_CYCLE","expected":"ACYCLIC_TWO_PASS_UNIT","mutated":"SYNTHETIC_COUNT_TO_BUF_CYCLE","ordinal":18,"target":"pointee_ast"},
{"diagnostic":"POLL_RESULT_FRAME_BOUND","expected":"NFDS_MAX_671085","mutated":"NFDS_671086","ordinal":19,"target":"poll.nfds"}
]
```
<!-- END VECTOR_NATIVE_SIGNATURE_NEGATIVES_R3_6 -->

The effective Windows negative roster is:

<!-- BEGIN VECTOR_WINDOWS_RENAME_NEGATIVES_R3_6 -->
```json
[
{"diagnostic":"WINDOWS_RENAME_ROOT_DIRECTORY","expected":"NULL","mutated":"NON_NULL","ordinal":0,"target":"RootDirectory"},
{"diagnostic":"WINDOWS_RENAME_FULL_PATH","expected":"FULL_ABSOLUTE_UTF16LE","mutated":"RELATIVE_LEAF","ordinal":1,"target":"FileName"},
{"diagnostic":"WINDOWS_RENAME_LENGTH","expected":"EXCLUDES_TERMINATOR","mutated":"INCLUDES_TERMINATOR","ordinal":2,"target":"FileNameLength"},
{"diagnostic":"WINDOWS_RENAME_FLAGS","expected":"0","mutated":"NONZERO","ordinal":3,"target":"Flags"},
{"diagnostic":"WINDOWS_RENAME_ALLOCATION","expected":"ALIGN_UP_20_LENGTH_2","mutated":"OFFSET_PLUS_LENGTH_ONLY","ordinal":4,"target":"allocation"},
{"diagnostic":"WINDOWS_RENAME_INFO_CLASS","expected":"FileRenameInfoEx_22","mutated":"SUBSTITUTE","ordinal":5,"target":"information_class"},
{"diagnostic":"WINDOWS_RENAME_POSTCONDITION","expected":"FULL_RELATIONAL_CONJUNCTION","mutated":"BOOL_ONLY","ordinal":6,"target":"postcondition"},
{"diagnostic":"WINDOWS_RENAME_SOURCE_PRESENCE","expected":"ABSENT_AFTER_SUCCESS","mutated":"UNOBSERVED","ordinal":7,"target":"source_name"},
{"diagnostic":"WINDOWS_RENAME_IDENTITY","expected":"DESTINATION_EQUALS_SOURCE_FILE_ID","mutated":"MISMATCH","ordinal":8,"target":"destination_reopen"},
{"diagnostic":"WINDOWS_DURABILITY_CEILING","expected":"FALSE","mutated":"TRUE_FROM_RECEIPT","ordinal":9,"target":"durability_authority"},
{"diagnostic":"WINDOWS_PARENT_HANDLE_KIND","expected":"DIRECTORY","mutated":"REGULAR_FILE","ordinal":10,"target":"destination_parent_handle"},
{"diagnostic":"WINDOWS_OBSERVATION_TYPE","expected":"WINDOWS_NAME_OR_REOPEN","mutated":"LINUX_NATIVE_OBSERVATION_UNION","ordinal":11,"target":"source_destination_observation"},
{"diagnostic":"WINDOWS_SOURCE_PATH_BINDING","expected":"SOURCE_PATH_EQUALS_RETAINED_HANDLE_ID","mutated":"MISMATCH","ordinal":12,"target":"source_path_binding"},
{"diagnostic":"WINDOWS_FLEX_ARRAY_SIZE","expected":"ALIGN_UP_20_LENGTH_2","mutated":"SIZEOF_FILE_RENAME_INFO_PLUS_LENGTH","ordinal":13,"target":"allocation"},
{"diagnostic":"WINDOWS_ZERO_BYTES","expected":"ALL_PADDING_TERMINATOR_TAIL_ZERO","mutated":"ONE_NONZERO_POSITION","ordinal":14,"target":"input_buffer"}
]
```
<!-- END VECTOR_WINDOWS_RENAME_NEGATIVES_R3_6 -->

The new cross-schema negative roster is:

<!-- BEGIN VECTOR_NATIVE_CROSS_SCHEMA_NEGATIVES_R3_6 -->
```json
[
{"diagnostic":"UNCERTAIN_AUTHORITY_CARRIER","ordinal":0,"target":"uncertain.native_execution_authority"},
{"diagnostic":"UNCERTAIN_RECEIPT_CARRIER","ordinal":1,"target":"uncertain.native_execution_receipt"},
{"diagnostic":"POST_OPERATION_ID_PREIMAGE","ordinal":2,"target":"uncertain.post_operation_id"},
{"diagnostic":"EFFECTIVE_ROOT_REACHABILITY","ordinal":3,"target":"all_effective_roots"},
{"diagnostic":"RETURN_KIND_CODE_COMPLETENESS","ordinal":4,"target":"result_frame.return_kind_code"},
{"diagnostic":"BOUND_INPUT_SIZE_CARRIED","ordinal":5,"target":"request_frame.bound_input_size"},
{"diagnostic":"NESTED_OUTPUT_LENGTH_SEPARATION","ordinal":6,"target":"nested_output_member"},
{"diagnostic":"POLL_EXACT_MAX_PLUS_ONE","ordinal":7,"target":"poll.result_frame"},
{"diagnostic":"NEGATIVE_INJECTION_TIER","ordinal":8,"target":"pointee_cycle_negative"},
{"diagnostic":"LINUX_FRESH_POSTSTATE_REQUIRED","ordinal":9,"target":"linux_returned_outcome"},
{"diagnostic":"LINUX_STATUS_DERIVATION","ordinal":10,"target":"linux.return_status"},
{"diagnostic":"WINDOWS_STATUS_DERIVATION","ordinal":11,"target":"windows.return_status"},
{"diagnostic":"PREDICATE_PREBOUND_BEFORE_ENTRY","ordinal":12,"target":"semantic_predicate"},
{"diagnostic":"PREDICATE_NO_RESULT_CHOSEN_EXPECTED_BYTES","ordinal":13,"target":"fresh_symbol_binding"},
{"diagnostic":"LINUX_EIGHT_SEAMS","ordinal":14,"target":"linux.seam_slice"},
{"diagnostic":"WINDOWS_EIGHT_SEAMS","ordinal":15,"target":"windows.seam_slice"},
{"diagnostic":"PROFILE_RECEIPT_CARDINALITY","ordinal":16,"target":"profile_receipts"},
{"diagnostic":"AGGREGATE_INDEX_TOTALITY","ordinal":17,"target":"aggregate_outcome_index"},
{"diagnostic":"CROSS_PROFILE_EVIDENCE_SPLICE","ordinal":18,"target":"profile_evidence"},
{"diagnostic":"ACTUAL_CALL_COVERAGE_OMISSION","ordinal":19,"target":"actual_operation_coverage"},
{"diagnostic":"ACTUAL_CALL_COVERAGE_DUPLICATE","ordinal":20,"target":"actual_operation_coverage"},
{"diagnostic":"EVIDENCE_LOCATOR_RESOLUTION","ordinal":21,"target":"evidence_locator"},
{"diagnostic":"UNAVAILABILITY_TAXONOMY","ordinal":22,"target":"unavailable_reason"},
{"diagnostic":"MATERIALIZED_ALL_UNAVAILABLE","ordinal":23,"target":"profile_receipt"},
{"diagnostic":"STRUCTURAL_ATOM_UNAVAILABLE","ordinal":24,"target":"atomic_result"},
{"diagnostic":"RESULT_HASH_NON_SELF","ordinal":25,"target":"atomic_result.result_sha256"},
{"diagnostic":"RESULT_ROSTER_ORDER","ordinal":26,"target":"atomic_bundle.result_roster"},
{"diagnostic":"REVIEW_ARTIFACT_NON_SELF","ordinal":27,"target":"review_artifact_binding"},
{"diagnostic":"REVIEW_DAG_COMPLETE_ROLES","ordinal":28,"target":"review_dag"},
{"diagnostic":"TOOLCHAIN_HASH_FORMULA","ordinal":29,"target":"toolchain_sha256"},
{"diagnostic":"PLATFORM_BINARY_SPLICE","ordinal":30,"target":"platform_identity"},
{"diagnostic":"STALE_NATIVE_CALL_VERSION","ordinal":31,"target":"effective_native_call_reference"}
]
```
<!-- END VECTOR_NATIVE_CROSS_SCHEMA_NEGATIVES_R3_6 -->

The effective nested atomic denominator is 2,227:

```text
outcome matrix results                 720
crash-seam results                     360
lifecycle ordered-pair results         196
ordinary member-mutation results       442
quarantine member-mutation results     374
LRC2-47 diagnostic results              68
signature/dependency negative results   20
Windows rename negative results         15
cross-schema negative results            32
                                       ----
total                                  2227
```

Atomic results are discriminated by contract kind.  Only outcome and crash-
seam results admit an unavailable branch:

```text
vector_r3_6_contract_test_evidence =
O(evidence_artifact:R(file_identity),test_source:R(file_identity),
  interpreter_or_binary:R(file_identity),command_frame:R(content_identity),
  stdout:R(content_identity),stderr:R(content_identity),exit_code:C(0),
  assertion_id:S1,observed_result:R(content_identity),evidence_sha256:HEX)

vector_r3_6_atomic_outcome_result =
O(roster_kind:C("OUTCOME_MATRIX"),roster_ordinal:I(0,719),
  roster_row_sha256:HEX,profile_result_sha256:HEX,
  availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  classification:E("API_SEMANTIC_SUCCESS","API_FAILURE_NO_RETRY",
    "RESUME_FROM_EFFECT_NO_REPLAY","RECONCILE_NO_REPLAY","QUARANTINE"),
  evidence_locators:A(R(vector_native_evidence_locator_r3_6),0,8,true),
  unavailable:Q(R(vector_native_unavailability_proof_r3_6)),
  result_sha256:HEX)

vector_r3_6_atomic_seam_result =
O(roster_kind:C("CRASH_SEAM"),roster_ordinal:I(0,359),
  roster_row_sha256:HEX,profile_result_sha256:HEX,
  availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  classification:Q(E("RECONCILE_NO_REPLAY","QUARANTINE")),
  evidence_locator:Q(R(vector_native_evidence_locator_r3_6)),
  unavailable:Q(R(vector_native_unavailability_proof_r3_6)),
  result_sha256:HEX)

vector_r3_6_atomic_lifecycle_result =
O(roster_kind:C("LIFECYCLE_PAIR"),roster_ordinal:I(0,195),
  roster_row_sha256:HEX,expected_disposition:E("LEGAL_ADJACENT",
    "LEGAL_QUARANTINE","REJECT_STATE_EDGE_ILLEGAL"),
  result:E("PASS_EXPECTED_ACCEPTANCE","PASS_EXPECTED_REJECTION"),
  evidence:R(vector_r3_6_contract_test_evidence),result_sha256:HEX)

vector_r3_6_atomic_rejection_result =
O(roster_kind:E("ORDINARY_MEMBER_MUTATION","QUARANTINE_MEMBER_MUTATION",
    "SIGNATURE_DEPENDENCY_NEGATIVE","WINDOWS_RENAME_NEGATIVE",
    "CROSS_SCHEMA_NEGATIVE"),roster_ordinal:I(0,441),
  roster_row_sha256:HEX,result:C("PASS_EXPECTED_REJECTION"),
  diagnostic_code:S1,diagnostic_subcode:S1,
  evidence:R(vector_r3_6_contract_test_evidence),
  result_sha256:HEX)

vector_r3_6_atomic_diagnostic_result =
O(roster_kind:C("LRC2_47_DIAGNOSTIC"),roster_ordinal:I(0,67),
  roster_row_sha256:HEX,result:C("PASS_EXPECTED_REJECTION"),
  diagnostic_code:C("CONTAINMENT_POLICY_IDENTITY"),diagnostic_subcode:S1,
  evidence:R(vector_r3_6_contract_test_evidence),result_sha256:HEX)

vector_r3_6_atomic_result =
U(R(vector_r3_6_atomic_outcome_result),R(vector_r3_6_atomic_seam_result),
  R(vector_r3_6_atomic_lifecycle_result),R(vector_r3_6_atomic_rejection_result),
  R(vector_r3_6_atomic_diagnostic_result))

vector_r3_6_atomic_evidence_bundle =
O(contract_subject:R(file_identity),scenario_row_stream_sha256:HEX,
  outcome_matrix_sha256:HEX,crash_seam_contract_sha256:HEX,
  lifecycle_pair_sha256:HEX,ordinary_member_mutation_sha256:HEX,
  quarantine_member_mutation_sha256:HEX,diagnostic_atom_sha256:HEX,
  signature_negative_sha256:HEX,windows_negative_sha256:HEX,
  cross_schema_negative_sha256:HEX,
  results:A(R(vector_r3_6_atomic_result),2227,2227,true),
  result_roster_size_bytes:I(1,16777216),result_roster_sha256:HEX,
  bundle_sha256:HEX)
```

The exact expected lifecycle result is acceptance for the 12 adjacent and 11
quarantine pairs and rejection for the other 173.  Every member mutation,
signature negative, Windows negative, cross-schema negative, and LRC2-47 atom
must be expected rejection with its exact diagnostic/subcode; none can be
unavailable.  Outcome atomic members are parsed-value equal to the indexed
profile outcome result by availability, classification, locators,
unavailability proof, and result hash.  Seam atomic members have the analogous
equality.  This is a field-level projection, not a generic PASS label.

For every union branch,
`result_sha256 = SHA-256(CJ({domain:"PROGRAM_FACTS_G3_R3_6_ATOMIC_RESULT_V1",
all preceding members of that selected branch}))`.  It excludes only itself.
The bundle result order is the nine-kind order in the denominator table, with
increasing roster ordinal within each kind.  `result_roster_sha256 =
SHA-256(CONCAT(CJ(results[i])||LF))`; the carried size is the exact byte length
of that stream.  `bundle_sha256` uses domain
`PROGRAM_FACTS_G3_R3_6_ATOMIC_EVIDENCE_BUNDLE_V1` and every preceding bundle
member, including the complete results and result-roster size/digest.  It
excludes only itself.  Kind counts, contiguous unique ordinals, row hashes,
expected disposition, diagnostic equality, availability nullability, and
profile-result equality are independently checked before the bundle hash.
`vector_r3_6_contract_test_evidence.evidence_sha256` uses domain
`PROGRAM_FACTS_G3_R3_6_CONTRACT_TEST_EVIDENCE_V1` and every preceding member,
excluding only itself; its command, exact stdout/stderr, zero exit, assertion
ID, and observed result are therefore carried rather than hidden behind a file
label.

### 20.9 Semantic deterministic self-check

This checker reads only the supplied subject, performs no import of launcher or
fixture code, makes no native call, and writes no file.  It checks both
canonical identities and the repaired semantic equalities, cardinalities,
effective roots, version labels, and authority ceiling.

<!-- BEGIN R3_6_DETERMINISTIC_SELF_CHECK -->
```python
import collections, hashlib, itertools, json, re, sys
from pathlib import Path

subject = Path(sys.argv[1])
raw = subject.read_bytes()
assert b"\r" not in raw and b"\x00" not in raw
text = raw.decode("utf-8")
assert "Status: `CONTRACT_ONLY_NON_LINEAGE_STABLE_DRAFT_PENDING_LATE_BOUND_CROSSCHECK_BRIDGE_R3_6`" in text
section20 = text[text.index("## 20."):]

def extract(name):
    match = re.search(
        rf"<!-- BEGIN {name} -->\n```json\n(.*?)\n```\n<!-- END {name} -->",
        text, re.S)
    assert match, name
    return json.loads(match.group(1))

def cj(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)

def identity(rows):
    stream = "".join(cj(row) + "\n" for row in rows).encode()
    array = cj(rows).encode()
    return (len(rows), len(stream), hashlib.sha256(stream).hexdigest(),
            len(array), hashlib.sha256(array).hexdigest())

signatures_r3_5 = extract("VECTOR_NATIVE_SIGNATURE_ROSTER_R3_5")
signature_core = [{key:value for key, value in row.items()
                   if key != "prototype"} for row in signatures_r3_5]
declarations = extract("VECTOR_NATIVE_DECLARATION_ROSTER_R3_6")
semantic_fields = extract("VECTOR_NATIVE_SEMANTIC_FIELD_ROSTER_R3_6")
review_dag = extract("VECTOR_NATIVE_REVIEW_DAG_R3_6")
signature_negatives = extract("VECTOR_NATIVE_SIGNATURE_NEGATIVES_R3_6")
windows_negatives = extract("VECTOR_WINDOWS_RENAME_NEGATIVES_R3_6")
cross_negatives = extract("VECTOR_NATIVE_CROSS_SCHEMA_NEGATIVES_R3_6")
layouts = extract("VECTOR_NATIVE_LAYOUT_ROSTER_R3_5")
scenarios = extract("PARITY_SCENARIO_ROSTER_R3_5")
postconditions = extract("VECTOR_NATIVE_POSTCONDITION_MAP_R3_5")

bindings = [{"abi_profiles":["LINUX_X86_64_LP64_LE",
                              "LINUX_AARCH64_LP64_LE"],
             "call_layer":"LIBC_SYSCALL_REGISTER_WORDS_V1",
             "declaration":declarations[ordinal],
             "error_convention":"LIBC_MINUS1_ERRNO_V1",
             "signature_core":signature_core[ordinal]}
            for ordinal in range(22)]

expected_identities = {
 "signature_core":(22,9300,"2da66d3a4a30aba1a9bc81886f5953a42d606ce558f94e2587d699564f548a62",9301,"874461cb5b0e31b32b2c885a9197b06e004722a85ade127cf0c6ca9df13421a1"),
 "declarations":(22,6560,"58cea0ece206d25a6d61b076373ef2acef34b363fe8545833a4d30a744b5d885",6561,"c398d6e79636eeda9740dc69dd2d4a351dcbfd60d4c7d55d49da654acb3fa7a3"),
 "bindings":(22,19930,"12fae5b7a514437cc7b9febe7d9a40b7b1abf859b1edfce7453e26c15dfa4734",19931,"e9445bf6721ac4f685d1bb9c797d1e171c19d3e808b27e47a8deccc84a365dce"),
 "semantic_fields":(23,4211,"b7e1496d769391af25573f7f0e0b93978a03ad0cf6d2fc1da428a83661fdaa91",4212,"a95c5f9abf8825391f3f32682e3cac48f05e318d30966b44a78349f1ce7332b0"),
 "signature_negatives":(20,2620,"395b4fe17bfa0cd7c2809ac0ddbc0e70522e018f56fbbad92f524384c708480f",2621,"da499d744c081507fed6cd31cd3011b5f1ff3559c8b92502cd511dcc8582967e"),
 "windows_negatives":(15,2152,"6b5c2a3fdec92bd1b0b7e2bb29a1a659f8b0f5d8e202d79fec55d3b2e015c1c1",2153,"171ee1a5f519a2d87d38a92797afc149e51033a4b24f8a8ea1c8812f96646d22"),
 "cross_negatives":(32,2874,"d8c4e138cdf7a90bdc7aa4e69248b69e7017fd84b49ca31a63959b9bbc79e8d9",2875,"0749015e1c130b8f93f5f566552877f3ea7015d7388ec8bc4b17def6de1f62ff"),
 "layouts":(10,3877,"b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a",3878,"b67b0b086370cf79f0a3afeb4adad6a07531f468996e6ec5e690b2cad83b7c82"),
 "scenarios":(52,84800,"70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99",84801,"2eb301a01e60847b1ce096c04b4df086869b216219714be49a70b1b4352b19c5"),
 "postconditions":(23,1697,"0a4f0466e864271afd798a1310fe06693adcd100881614c0cd04fe9cf9c37ad8",1698,"fd35155f94e87b37c28371aaf6a4212d9da14c27c37d5fd4ec796dc993f17c8e")}
actual_identity_rows = {
 "signature_core":signature_core,"declarations":declarations,
 "bindings":bindings,"semantic_fields":semantic_fields,
 "signature_negatives":signature_negatives,
 "windows_negatives":windows_negatives,"cross_negatives":cross_negatives,
 "layouts":layouts,"scenarios":scenarios,"postconditions":postconditions}
for name, rows in actual_identity_rows.items():
    assert identity(rows) == expected_identities[name], (name, identity(rows))

# Declaration/core/source/ABI joins.
assert [row["ordinal"] for row in signature_core] == list(range(22))
assert [row["ordinal"] for row in declarations] == list(range(22))
for core, declaration in zip(signature_core, declarations):
    assert set(core) == {"api","args","ordinal","outputs","return_kind","uapi_symbol"}
    assert (core["ordinal"], core["api"], core["uapi_symbol"]) == \
           (declaration["ordinal"], declaration["api"], declaration["uapi_symbol"])
    assert declaration["return_type"] == "long"
    assert declaration["declaration"].startswith("asmlinkage long ")
assert declarations[6]["declaration_name"] == "sys_newfstat"
assert declarations[6]["struct_target"] == "struct stat"
assert "__old_kernel_stat" not in declarations[6]["declaration"]
for ordinal in (2,3,4,5):
    assert "ssize_t" not in declarations[ordinal]["declaration"]
expected_encodings = {("mkdirat","mode"):"U16_LE",
 ("openat","mode"):"U16_LE",("read","fd"):"U32_LE",
 ("write","fd"):"U32_LE",("pread64","fd"):"U32_LE",
 ("fstat","fd"):"U32_LE",("statx","flags"):"U32_LE"}
actual_encodings = {(row["api"], argument["name"]):argument["encoding"]
                    for row in signature_core for argument in row["args"]}
assert all(actual_encodings[key] == value
           for key, value in expected_encodings.items())

# Closed profiles, status/cell function, and 720-row contract.
postcondition_by_api = {row["api"]:row["postcondition"]
                        for row in postconditions}
profiles = []
for signature in signature_core:
    for profile in ("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"):
        profiles.append({"api":signature["api"],
          "api_profile_ordinal":len(profiles),
          "postcondition":postcondition_by_api[signature["api"]],
          "profile":profile})
windows_api = "SetFileInformationByHandle.FileRenameInfoEx"
profiles.append({"api":windows_api,"api_profile_ordinal":44,
  "postcondition":postcondition_by_api[windows_api],
  "profile":"WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"})
poststates = ["EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"]
statuses = ["SUCCESS","FAILURE","INTERRUPTED"]
def classify(kind, status, poststate):
    if poststate == "WRONG_EFFECT": return "QUARANTINE"
    if kind == "RETURNED" and status == "SUCCESS" and poststate == "NO_EFFECT":
        return "QUARANTINE"
    if poststate == "UNOBSERVABLE" or kind == "NO_RETURN":
        return "RECONCILE_NO_REPLAY"
    if status == "SUCCESS": return "API_SEMANTIC_SUCCESS"
    if status == "FAILURE" and poststate == "NO_EFFECT":
        return "API_FAILURE_NO_RETRY"
    if poststate == "EXPECTED_EFFECT": return "RESUME_FROM_EFFECT_NO_REPLAY"
    return "RECONCILE_NO_REPLAY"
cells = []
for status in statuses:
    for poststate in poststates:
        cells.append(("RETURNED",status,poststate,
                      classify("RETURNED",status,poststate)))
for poststate in poststates:
    cells.append(("NO_RETURN",None,poststate,
                  classify("NO_RETURN",None,poststate)))
assert len(profiles) == 45 and len(cells) == 16
assert len(profiles) * len(cells) == 720
assert {row["selector"] for row in semantic_fields} == set(postcondition_by_api.values())
assert all(len(row["fields"]) == len(set(row["fields"])) for row in semantic_fields)

# Eight seams per API/profile and exact profile-slice formulas.
seam_names = ["BEFORE_ENTRY","AFTER_REQUEST_DURABLE","DURING_CALL",
 "AFTER_EFFECT_BEFORE_RETURN","AFTER_RETURN_BEFORE_ERROR_CAPTURE",
 "AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE","DURING_POSTSTATE",
 "AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER"]
seams = []
for profile in profiles:
    for seam_ordinal, seam in enumerate(seam_names):
        seams.append({"api":profile["api"],
          "api_profile_ordinal":profile["api_profile_ordinal"],
          "crash_seam":seam,
          "evidence_class_required":"GOVERNED_INSTRUMENTATION",
          "profile":profile["profile"],"seam_matrix_ordinal":len(seams),
          "seam_ordinal":seam_ordinal})
assert identity(seams) == (360,77822,
 "2fbd6f0e2cca5963e6814827c9599be48b1c3b967609b276bfd8a9a40aaff797",
 77823,"f405ed06451e97b5781248824d5888ef9b494ebf231ef557d05dd29e0cdf4ac9")
assert all([row["crash_seam"] for row in seams[8*i:8*i+8]] == seam_names
           for i in range(45))
x86_outcomes = [32*api + cell for api in range(22) for cell in range(16)]
arm_outcomes = [32*api + 16 + cell for api in range(22) for cell in range(16)]
windows_outcomes = list(range(704,720))
assert [len(x86_outcomes),len(arm_outcomes),len(windows_outcomes)] == [352,352,16]
assert sorted(x86_outcomes + arm_outcomes + windows_outcomes) == list(range(720))
x86_seams = [16*api + seam for api in range(22) for seam in range(8)]
arm_seams = [16*api + 8 + seam for api in range(22) for seam in range(8)]
windows_seams = list(range(352,360))
assert [len(x86_seams),len(arm_seams),len(windows_seams)] == [176,176,8]
assert sorted(x86_seams + arm_seams + windows_seams) == list(range(360))

# Complete review chronology and role separation.
nodes = review_dag["node_order"]
edges = review_dag["edges"]
required_nodes = {"INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW","BUILD_RECEIPT",
 "LAYOUT_ORACLE_REVIEW","IMPLEMENTATION_REVIEW","SEMANTIC_DERIVATION_REVIEW",
 "FACILITY_REVIEW","HOST_EXECUTION_RECEIPT","RECEIPT_REVIEW",
 "NATIVE_AUTHORITY_REVIEW"}
assert set(nodes) == required_nodes and len(nodes) == 10
node_ordinal = {node:ordinal for ordinal,node in enumerate(nodes)}
assert len(edges) == 19 and len({tuple(edge) for edge in edges}) == 19
assert all(node_ordinal[source] < node_ordinal[target]
           for source,target in edges)
review_dag_bytes = cj(review_dag).encode()
assert len(review_dag_bytes) == 1134
assert hashlib.sha256(review_dag_bytes).hexdigest() == \
       "981adeaf607221ca53b3991dd50944873e31605ea3675796f6d15f56b51bd26e"
principal_roles = ["SOURCE_VENDOR","BUILD_AUTHOR","LAYOUT_ORACLE_AUTHOR",
 "PRODUCTION_IMPLEMENTER","PREDICATE_ORACLE_AUTHOR","FACILITY_AUTHOR",
 "FIXTURE_AUTHOR","RECEIPT_AUTHOR","RECEIPT_REVIEWER",
 "NATIVE_AUTHORITY_REVIEWER"]
assert len(list(itertools.combinations(principal_roles,2))) == 45

# Effective consumer/root and frame semantics, not merely generated hashes.
section18_2 = text[text.index("### 18.2"):text.index("### 18.3")]
uncertain = re.search(r"vector_uncertain_post_operation_instance\s*=\n(.*?)\n\nvector_no_spawn_post_operation_instance", section18_2, re.S)
assert uncertain
assert "native_execution_authority:R(vector_native_ffi_authority_r3_6)" in uncertain.group(1)
assert "native_execution_receipt:R(vector_native_execution_receipt_r3_6)" in uncertain.group(1)
assert "native_execution_authority,native_execution_receipt" in section18_2
assert section18_2.count("native_execution_authority:R(vector_native_ffi_authority_r3_6)") == 3
assert section18_2.count("native_execution_receipt:R(vector_native_execution_receipt_r3_6)") == 3
section18_3 = text[text.index("### 18.3"):text.index("### 18.4")]
assert "post_operation:R(vector_no_spawn_post_operation_instance)" in section18_3
assert "post_operation:R(vector_confirmed_post_operation_instance)" in section18_3
assert section18_3.count("post_operation:R(vector_uncertain_post_operation_instance)") >= 2
effective_consumers = text[text.index("### 17.2"):text.index("## 19.")]
assert "R(vector_native_call)" not in effective_consumers
assert "R(vector_native_call_r3_6)" in effective_consumers
assert ("calls resolve this " + "V3 type") not in text
assert "PROGRAM_FACTS_G3_VECTOR_NATIVE_CALL_V5" in section20
assert '"PFG3NAR6"' in section20 and '"PFG3NRE6"' in section20
assert "u16le(return_kind_code)" in section20
assert "bound_input_size_or_ffffffffffffffff" in section20
assert "vector_native_nested_output_member_r3_6" in section20
assert "layout_span is the in-memory parent-field width" in section20
assert 34 + 40 + 4 + 25 * 671085 == 16777203
assert 34 + 40 + 4 + 25 * 671086 == 16777228
for phrase in ("prebound_before_entry:C(true)",
 "fresh_observation:R(vector_native_typed_projection_r3_6)",
 "errno==EINTR(4)","ERROR_OPERATION_ABORTED(995)",
 "source_path_binding:R(vector_windows_path_handle_binding_r3_6)",
 "destination_path_binding:R(vector_windows_path_handle_binding_r3_6)",
 "outcome_results:A(R(vector_native_outcome_result_r3_6),352,352,true)",
 "outcome_results:A(R(vector_native_outcome_result_r3_6),16,16,true)",
 "seam_results:A(R(vector_native_crash_seam_result_r3_6),176,176,true)",
 "seam_results:A(R(vector_native_crash_seam_result_r3_6),8,8,true)",
 "atomic_contract_evidence:R(vector_r3_6_atomic_evidence_bundle)"):
    assert phrase in section20, phrase

# All 62 local R3.6 types are acyclic and authority-reachable.
type_blocks = re.findall(r"```text\n(.*?)\n```", section20, re.S)
definitions = {}
for block in type_blocks:
    matches = list(re.finditer(r"(?m)^(vector_[a-z0-9_]+)\s*=\s*$", block))
    for ordinal, match in enumerate(matches):
        definitions[match.group(1)] = block[match.end():
            matches[ordinal+1].start() if ordinal+1 < len(matches) else len(block)]
local_names = set(definitions)
graph = {name:{ref for ref in re.findall(r"R\((vector_[a-z0-9_]+)\)", body)
               if ref in local_names} for name,body in definitions.items()}
indegree = {name:0 for name in local_names}
for refs in graph.values():
    for ref in refs: indegree[ref] += 1
queue = collections.deque(name for name,degree in indegree.items() if degree == 0)
visited_count = 0
while queue:
    name = queue.popleft(); visited_count += 1
    for ref in graph[name]:
        indegree[ref] -= 1
        if indegree[ref] == 0: queue.append(ref)
assert len(local_names) == 62 and visited_count == 62
reachable, stack = set(), ["vector_native_ffi_authority_r3_6"]
while stack:
    name = stack.pop()
    if name in reachable: continue
    reachable.add(name); stack.extend(graph.get(name,()))
assert local_names <= reachable

# Negative completeness, atomic denominator, compatibility index, ceilings.
reason_pairs = [
 ("RETURN_CELL_NOT_DETERMINISTICALLY_INDUCIBLE","RETURN_STATUS_CONTROL_ANALYSIS"),
 ("SEAM_NOT_DETERMINISTICALLY_STOPPABLE","FACILITY_STOP_CAPABILITY_ANALYSIS"),
 ("SEAM_PROFILE_INAPPLICABLE","PROFILE_SEAM_SEMANTIC_INAPPLICABILITY"),
 ("OBSERVATION_CAPABILITY_UNAVAILABLE","FRESH_OBSERVATION_CAPABILITY_ANALYSIS"),
 ("NO_EVIDENCED_SEAM_PRODUCES_CELL","SEAM_TO_CELL_COVERAGE_ANALYSIS")]
assert all(f"`{reason} -> {predicate}`" in section20
           for reason,predicate in reason_pairs)
assert ("unavailable_reason:Q(" + "S1)") not in section20
assert ("classification:" + "S1") not in section20
assert ("crash_seam:" + "S1") not in section20
assert [len(signature_negatives),len(windows_negatives),len(cross_negatives)] == [20,15,32]
assert [row["ordinal"] for row in signature_negatives] == list(range(20))
assert [row["ordinal"] for row in windows_negatives] == list(range(15))
assert [row["ordinal"] for row in cross_negatives] == list(range(32))
assert 720 + 360 + 196 + 442 + 374 + 68 + 20 + 15 + 32 == 2227
subcases = sum(1 if row["mutation"]["kind"] == "SINGLE" else
               len(row["mutation"]["values"]) for row in scenarios)
assert subcases == 767
assert [len(row["mutation"]["values"]) for row in scenarios[-10:]] == \
       [39,36,32,34,79,68,16,18,20,28]
assert "only current branch is unmaterialized and nonauthoritative" in section20
assert "late-bound 15-edge" in text and "explicitly deferred" in text
assert "macOS has no platform branch" in section20
assert "power_loss_capability:C(true),accepting_authority:C(false)" in section20
assert "power_loss_capability:C(false)" in section20
assert not re.search(r"(?:evidence_authoritative|production_execution_allowed|"
                     r"spawn_allowed|publication_allowed|cutover_allowed|"
                     r"durability_authority|accepting_authority):C\(true\)", section20)

print(cj({"status":"PASS_R3_6_INTERNAL_CONSISTENCY",
 "subject_bytes":len(raw),"subject_lines":raw.count(b"\n"),
 "subject_sha256":hashlib.sha256(raw).hexdigest(),
 "scenario_rows":52,"scenario_subcases":767,"outcome_rows":720,
 "crash_seam_rows":360,"nested_results":2227,"local_types":62,
 "local_cycles":0,"local_unreachable":0}))
```
<!-- END R3_6_DETERMINISTIC_SELF_CHECK -->

### 20.10 R3.6 identities, blocker disposition, and stable boundary

The independently recomputed canonical roster identities are:

| roster | rows | row-stream bytes / SHA-256 | canonical bytes / SHA-256 |
|---|---:|---|---|
| R3.6 signature core | 22 | 9,300 / `2da66d3a4a30aba1a9bc81886f5953a42d606ce558f94e2587d699564f548a62` | 9,301 / `874461cb5b0e31b32b2c885a9197b06e004722a85ade127cf0c6ca9df13421a1` |
| R3.6 pinned declarations | 22 | 6,560 / `58cea0ece206d25a6d61b076373ef2acef34b363fe8545833a4d30a744b5d885` | 6,561 / `c398d6e79636eeda9740dc69dd2d4a351dcbfd60d4c7d55d49da654acb3fa7a3` |
| R3.6 signature/declaration bindings | 22 | 19,930 / `12fae5b7a514437cc7b9febe7d9a40b7b1abf859b1edfce7453e26c15dfa4734` | 19,931 / `e9445bf6721ac4f685d1bb9c797d1e171c19d3e808b27e47a8deccc84a365dce` |
| semantic field schemas | 23 | 4,211 / `b7e1496d769391af25573f7f0e0b93978a03ad0cf6d2fc1da428a83661fdaa91` | 4,212 / `a95c5f9abf8825391f3f32682e3cac48f05e318d30966b44a78349f1ce7332b0` |
| crash-seam contracts | 360 | 77,822 / `2fbd6f0e2cca5963e6814827c9599be48b1c3b967609b276bfd8a9a40aaff797` | 77,823 / `f405ed06451e97b5781248824d5888ef9b494ebf231ef557d05dd29e0cdf4ac9` |
| signature/dependency negatives | 20 | 2,620 / `395b4fe17bfa0cd7c2809ac0ddbc0e70522e018f56fbbad92f524384c708480f` | 2,621 / `da499d744c081507fed6cd31cd3011b5f1ff3559c8b92502cd511dcc8582967e` |
| Windows negatives | 15 | 2,152 / `6b5c2a3fdec92bd1b0b7e2bb29a1a659f8b0f5d8e202d79fec55d3b2e015c1c1` | 2,153 / `171ee1a5f519a2d87d38a92797afc149e51033a4b24f8a8ea1c8812f96646d22` |
| cross-schema negatives | 32 | 2,874 / `d8c4e138cdf7a90bdc7aa4e69248b69e7017fd84b49ca31a63959b9bbc79e8d9` | 2,875 / `0749015e1c130b8f93f5f566552877f3ea7015d7388ec8bc4b17def6de1f62ff` |

The review DAG canonical object, without an array wrapper, is 1,134 bytes with
SHA-256 `981adeaf607221ca53b3991dd50944873e31605ea3675796f6d15f56b51bd26e`.
The unchanged, independently rejoined identities remain: layouts 10 rows,
3,877-byte stream SHA-256
`b340b512590efc762af2249fa7ac3a29b7e5187d65b211fe87bead125e711b9a`;
scenarios 52 rows, 84,800-byte stream SHA-256
`70708a6e9f8225799a30f1926678c3f39ad61d9d63350aa742b025850a2eef99`;
postconditions 23 rows, 1,697-byte stream SHA-256
`0a4f0466e864271afd798a1310fe06693adcd100881614c0cd04fe9cf9c37ad8`;
API/profile rows 45, outcome cells 16, and outcome rows 720 with the R3.5
verified stream SHA-256
`f36d9f26538a425f6e208ce75200a7c724816dfc8d2e0ed5829004f976f922ef`.
The lifecycle 196, ordinary mutation 442, quarantine mutation 374, and
diagnostic 68 rosters retain their reviewed identities.  Their semantics are
rejoined through the discriminated R3.6 result types rather than copied labels.

The two R3.5 review blocker sets are disposed as follows:

| blocker family | R3.6 disposition |
|---|---|
| false hashed declarations | **Closed:** prototypes are removed from the signature core; 22 exact `long` declarations, `sys_newfstat`, source slices, UAPI and architecture mappings are separate joined data. |
| frame, AST, nested output, and poll contradictions | **Closed:** all codes, carried bounds, AST encoding/injection tier, scalar/nested lengths, and exact 671085 ceiling are executable. |
| asserted Linux poststate/status and nondeterministic expected blobs | **Closed:** returned/no-return envelopes carry fresh typed projections; status, relational predicate evaluation, cell, and classification are derived. |
| singular profile receipt with 720 rows | **Closed:** evidence receipts are exactly 352/352/16 with separately indexed 720-row aggregate joins. |
| authority bypass and unrelated actual calls | **Closed:** all effective branches carry R3.6 authority/receipt; exact coverage bijects typed operations to profile results, evidence, build, binary, platform, and review. |
| evidence labels, free-form unavailability, and missing hashes | **Closed:** evidence locators resolve typed subresults, reasons are a closed reviewed taxonomy, and result/stream/bundle formulas are non-self and total. |
| incomplete provenance/platform/review joins | **Closed as a future nonauthority shape:** source/header/toolchain/build/platform/loaded-runtime equality, outer review binding, ten-node/19-edge DAG, and 45 principal-distinctness pairs are exact.  Material identities remain absent rather than invented. |
| Windows handle/observation mismatch and six seams | **Closed:** directory/name/reopen types, symmetric path bindings, zero-byte validation, and the common eight-seam universe control. |
| atomic denominator and semantic self-check | **Closed:** 2,227 discriminated atomic results prohibit structural unavailability; the checker validates 62 acyclic authority-reachable types and cross-section semantics. |

The current evidence branch remains `UNMATERIALIZED_STABLE_DRAFT`; therefore
no future atomic result-stream digest, profile receipt digest, build digest,
platform digest, source-slice digest, review binding, or authority join is
asserted.  Inventing one would be a defect.  The overall disposition remains
`REPAIR_UNMATERIALIZED_NATIVE_PROVENANCE_AND_EVIDENCE` until those external
artifacts exist and receive their required independent reviews.  This is a
stable contract draft suitable only for another dual review; it is not a PASS,
fixture-authorship authority, execution authority, or admission lineage.

The platform ceiling is exact: only the future Linux retained-directory-handle
same-mount profile has `power_loss_capability:true`, always with
`accepting_authority:false`; Windows is ordinary-user protected-root and
process-crash-only with power-loss false; macOS is unavailable.  Stress,
successful API returns, syntactic receipt completeness, and unmaterialized
evidence cannot manufacture durability.  Every R3.6 evidence-authority,
production-execution, spawn, publication, cutover, accepting-authority, and
durability-authority field remains false.

The late-bound 15-edge admission bridge remains explicitly deferred.  It is
not implemented, materialized, evaluated, or represented by the 19-edge
evidence DAG.  No runtime or fixture was executed, no external evidence was
authored, and no publication, final freeze, commit, push, or install is
authorized by this R3.6 repair.

## 21. R3.7 provenance, evaluator, occurrence, and review closure

This section is the sole R3.7 normative replacement for every conflicting
R3.6 declaration/table binding, call projection, semantic projection,
relational evaluator, returned/no-return identity, fresh-symbol binding,
effective-root coverage, profile receipt, review, DAG-node, platform,
structural-negative, atomic-result, or self-check expression. Section 20 is
retained as exact review history. The unchanged R3.6 22-signature core,
22-declaration text roster, frame code tables, two-pass AST, nested-output
encoding, `poll.nfds=671085` maximum, 45 API/profile rows, 16 outcome cells,
720 outcome rows, 360 eight-seam rows, 352/352/16 outcome slices,
176/176/8 seam slices, and 2,227 atomic denominator are rejoined below.

The exact reviewed R3.6 subject is 844,061 bytes, 12,644 LF-only lines, and
SHA-256 `bbd441346015396834737c0a37a1da97402d4b72e361573d3060239ccd8616e1`.
Its complete native review is 23,668 bytes, 198 LF-only lines, and SHA-256
`df58fcbd7e0c3a1cb5733f004cbfae271a6fe32cc8d614baeb028c0fefef377b`.
Its complete state review is 17,779 bytes, 133 LF-only lines, and SHA-256
`92ca241be1d90885ccd1b5d0758fc85ef65519ad5a67800dcdd756aa79c02e9f`.
Both review dispositions are `REPAIR`; they are design inputs and never PASS
lineage.

The only current branch remains unmaterialized and nonauthoritative. R3.7 does
not invent any source slice, table row, build, loaded module, platform, host
execution, crash-facility result, review, receipt, or mutation evidence.

### 21.1 Registered declaration and architecture-table slices

The declaration header, both syscall tables, and both architecture UAPI number
headers use one typed registered-slice abstraction. Same text from a file or
offset not registered in the exact build manifest is not the same slice.

```text
vector_native_registered_source_slice_r3_7 =
O(slice_kind:E("DECLARATION_HEADER","X86_64_SYSCALL_TABLE",
    "AARCH64_SYSCALL_TABLE","X86_64_UAPI_NUMBER_HEADER",
    "AARCH64_UAPI_NUMBER_HEADER"),profile:E("COMMON_LINUX",
    "LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  registered_input_kind:E("SOURCE","HEADER"),registered_input_ordinal:I(0,127),
  registered_path:PATH,registered_file:R(file_identity),row_ordinal:I(0,65535),
  byte_offset:I(0,16777215),byte_length:I(1,16777216),
  raw_slice:R(vector_exact_native_bytes),normalized_tokens:S1,
  registered_row_sha256:HEX,slice_sha256:HEX)

vector_native_architecture_mapping_r3_7 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  architecture:E("x86_64","aarch64"),api:S1,uapi_symbol:S1,
  syscall_table_slice:R(vector_native_registered_source_slice_r3_7),
  uapi_number_slice:R(vector_native_registered_source_slice_r3_7),
  syscall_table_number_u32:I(0,4294967295),
  uapi_macro_number_u32:I(0,4294967295),numbers_equal:C(true),
  mapping_sha256:HEX)

vector_native_declaration_binding_r3_7 =
O(ordinal:I(0,21),api:S1,uapi_symbol:S1,declaration_row_sha256:HEX,
  declaration_slice:R(vector_native_registered_source_slice_r3_7),
  normalized_declaration:S1,
  architecture_mappings:A(R(vector_native_architecture_mapping_r3_7),2,2,true),
  binding_sha256:HEX)

vector_native_call_declaration_join_r3_7 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  architecture:E("x86_64","aarch64"),api:S1,api_ordinal:I(0,21),
  signature_core_row_sha256:HEX,declaration_binding_sha256:HEX,
  declaration_slice_sha256:HEX,syscall_table_slice_sha256:HEX,
  uapi_number_slice_sha256:HEX,syscall_number_u32:I(0,4294967295),
  build_manifest_sha256:HEX,join_sha256:HEX)
```

`registered_row_sha256` hashes domain
`PROGRAM_FACTS_G3_REGISTERED_SOURCE_ROW_V1` and every preceding slice member
through `normalized_tokens`; `slice_sha256` adds `registered_row_sha256` under
domain `PROGRAM_FACTS_G3_REGISTERED_SOURCE_SLICE_V1`. A slice is valid only
when its path, file identity, input kind/ordinal, row ordinal, byte offset,
length, exact raw bytes, and tokens equal exactly one manifest row. Zero or
more than one match rejects. Slice-kind/profile pairing is fixed: the
declaration header is `COMMON_LINUX`; table and number-header slices have their
matching architecture profile.

Each declaration binding has exactly two mappings in x86-64 then AArch64
order. Their API/symbol equal the declaration row, each pair of numeric values
is equal, and the declaration tokens equal the retained R3.6 declaration text.
`binding_sha256` uses domain
`PROGRAM_FACTS_G3_NATIVE_DECLARATION_BINDING_V2` and every preceding member.
Every Linux call carries `vector_native_call_declaration_join_r3_7`; its
profile selects exactly one mapping, and every carried slice hash, number,
signature row, binding hash, and build-manifest hash equals that exact parsed
manifest row. The join hash uses domain
`PROGRAM_FACTS_G3_NATIVE_CALL_DECLARATION_JOIN_V1` and excludes only itself.

The R3.7 build manifest replaces the R3.6 declaration-binding portion:

```text
vector_native_build_manifest_r3_7 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  sources:A(R(vector_native_source_input),1,64,true),
  headers:A(R(vector_native_header_input),1,128,true),
  registered_slices:A(R(vector_native_registered_source_slice_r3_7),0,512,true),
  declaration_bindings:A(R(vector_native_declaration_binding_r3_7),0,22,true),
  source_row_count:I(1,64),source_row_stream_size_bytes:I(1,16777216),
  source_row_stream_sha256:HEX,header_row_count:I(1,128),
  header_row_stream_size_bytes:I(1,16777216),header_row_stream_sha256:HEX,
  registered_slice_count:I(0,512),registered_slice_row_stream_sha256:HEX,
  declaration_binding_count:I(0,22),declaration_binding_row_stream_sha256:HEX,
  toolchain:R(vector_native_toolchain_manifest_r3_6),
  evidence_dag:R(vector_native_evidence_dag_r3_7),
  review_dag_bytes:R(content_identity),layout_row_stream_sha256:HEX,
  signature_core_row_stream_sha256:HEX,declaration_row_stream_sha256:HEX,
  oracle_source:R(file_identity),oracle_binary:R(file_identity),
  production_source:R(file_identity),production_binary:R(file_identity),
  build_receipt:R(vector_native_build_receipt_r3_6),build_manifest_sha256:HEX)
```

Linux manifests contain all 22 declaration bindings and exactly the registered
slices used by them; Windows contains zero Linux slices/bindings. Counts equal
array lengths, row streams are exact ordered `CONCAT(CJ(row)||LF)`, and the
manifest hash uses domain `PROGRAM_FACTS_G3_NATIVE_BUILD_MANIFEST_V3`. No
unreferenced substitute slice can satisfy a call join.

### 21.2 Total typed projection and relational algebra

R3.7 replaces the independently asserted R3.6 `complete` bit with fixed ordinal
slots. Selector schemas are the retained 23-row selector/name/kind roster plus
a closed per-field value-schema identifier. The registry is the only source
of field count, ordinal, name, kind, and subtype.

```text
vector_native_semantic_field_schema_r3_7 =
O(selector_ordinal:I(0,22),selector:S1,field_ordinal:I(0,31),field_name:S1,
  value_kind:E("BOOL","U64","S64","BYTES","ENUM","IDENTITY","ROWS"),
  value_schema_id:S1,schema_document:R(file_identity),schema_root_pointer:S1,
  decoder_source:R(file_identity),field_schema_sha256:HEX)

vector_native_semantic_selector_schema_r3_7 =
O(selector_ordinal:I(0,22),selector:S1,
  fields:A(R(vector_native_semantic_field_schema_r3_7),1,32,true),
  field_count:I(1,32),selector_schema_sha256:HEX)

vector_native_semantic_schema_registry_r3_7 =
O(selectors:A(R(vector_native_semantic_selector_schema_r3_7),23,23,true),
  selector_count:C(23),field_count:I(1,736),registry_source:R(file_identity),
  registry_review:R(vector_native_review_artifact_binding_r3_7),
  registry_sha256:HEX)

vector_native_projection_value_r3_7 =
U(O(value_kind:C("BOOL"),value_schema:S1,value:B,encoded_value:R(vector_exact_native_bytes)),
  O(value_kind:C("U64"),value_schema:S1,value:I(0,9007199254740991),encoded_value:R(vector_exact_native_bytes)),
  O(value_kind:C("S64"),value_schema:S1,value:I(-9007199254740991,9007199254740991),encoded_value:R(vector_exact_native_bytes)),
  O(value_kind:C("BYTES"),value_schema:S1,value:R(vector_exact_native_bytes),encoded_value:R(vector_exact_native_bytes)),
  O(value_kind:C("ENUM"),value_schema:S1,value:S1,encoded_value:R(vector_exact_native_bytes)),
  O(value_kind:C("IDENTITY"),value_schema:E("LINUX_FILE_ID","WINDOWS_FILE_ID",
      "FD_ID","MOUNT_ID","PID_ID","PIDFD_ID","PROCESS_ID","CGROUP_ID",
      "POLICY_ID","FILTER_ID","INSTRUCTION_ID","NAMESPACE_ID"),
    canonical_identity:R(vector_exact_native_bytes),
    encoded_value:R(vector_exact_native_bytes)),
  O(value_kind:C("ROWS"),value_schema:S1,row_count:I(0,65535),
    canonical_rows:R(vector_exact_native_bytes),
    encoded_value:R(vector_exact_native_bytes)))

vector_native_projection_present_slot_r3_7 =
O(slot_kind:C("PRESENT"),field_ordinal:I(0,31),field_name:S1,
  value_kind:E("BOOL","U64","S64","BYTES","ENUM","IDENTITY","ROWS"),
  value_schema:S1,field_schema_sha256:HEX,
  value:R(vector_native_projection_value_r3_7),field_sha256:HEX)

vector_native_projection_missing_slot_r3_7 =
O(slot_kind:C("MISSING"),field_ordinal:I(0,31),field_name:S1,
  value_kind:E("BOOL","U64","S64","BYTES","ENUM","IDENTITY","ROWS"),
  value_schema:S1,field_schema_sha256:HEX,
  reason:E("SOURCE_UNOBSERVABLE_AFTER_CRASH",
    "SOURCE_API_DID_NOT_RETURN","SOURCE_HANDLE_UNAVAILABLE",
    "SOURCE_NAMESPACE_UNAVAILABLE","SOURCE_PLATFORM_UNAVAILABLE"),
  field_sha256:HEX)

vector_native_projection_slot_r3_7 =
U(R(vector_native_projection_present_slot_r3_7),
  R(vector_native_projection_missing_slot_r3_7))

vector_native_typed_projection_r3_7 =
O(selector:S1,semantic_schema_registry_sha256:HEX,registry_row_sha256:HEX,
  slots:A(R(vector_native_projection_slot_r3_7),1,32,true),
  complete:B,missing_field_ordinals:A(I(0,31),0,32,true),
  canonical_bytes:R(vector_exact_native_bytes),projection_sha256:HEX)

vector_native_return_projection_r3_7 =
U(O(completion_kind:C("RETURNED"),return_kind:E("S64","FD","BYTE_COUNT",
      "ABI_VERSION","PID","READY_COUNT","BOOL"),
    return_value:R(vector_native_projection_value_r3_7),
    error_valid:B,error_code_u32:I(0,4294967295),return_sha256:HEX),
  O(completion_kind:C("NO_RETURN"),return_kind:C("NO_RETURN"),
    return_value:C(null),error_valid:C(false),error_code_u32:C(0),
    return_sha256:HEX))

vector_native_relation_term_r3_7 =
U(O(term_kind:C("LITERAL"),value:R(vector_native_projection_value_r3_7)),
  O(term_kind:C("FIELD"),source:E("PRESTATE","REQUEST","RETURN","ACTUAL"),
    field_ordinal:I(0,31),expected_value_kind:E("BOOL","U64","S64","BYTES",
      "ENUM","IDENTITY","ROWS"),expected_value_schema:S1),
  O(term_kind:C("SYMBOL"),symbol_ordinal:I(0,31),
    expected_symbol_kind:E("FILE_ID","FD","MOUNT_ID","PID","PIDFD",
      "PROCESS_ID")))

vector_native_relation_atom_r3_7 =
O(atom_ordinal:I(0,127),operator:E("EQ","NE","ABSENT","PRESENT",
    "IN_UNSIGNED_RANGE","FRESH_AGAINST_ROSTER","UNCHANGED","SAME_OBJECT",
    "PREFIX_EQ","COUNT_EQ","SET_EQ","SET_DISJOINT"),
  operands:A(R(vector_native_relation_term_r3_7),1,3,false),
  operator_registry_row_sha256:HEX,atom_sha256:HEX)
```

For a selector with `n` fields, slots have length `n`, ordinals exactly
`0..n-1`, and each slot's name, kind, and value schema equal its registry row.
The registry has exactly the retained 23 selectors in retained order; its field
counts, names, kinds, and ordinals are the unique expansion of the R3.6 field
roster. Each selector/field pair has exactly one separately rooted canonical
schema and decoder. Its PASS registry review subjects the registry source,
all schema documents, and all decoder sources. A value schema ID is valid only
by parsed equality to that unique row; IDENTITY and ROWS roots are disjoint
tagged schemas and do not admit an arbitrary canonical JSON object or array.
Selector, field, schema-document, root-pointer, decoder, and row-hash splices
reject before value evaluation.
PRESENT and MISSING ordinals are disjoint and their union is `0..n-1`.
`missing_field_ordinals` is exactly the increasing list of MISSING ordinals,
and `complete == (missing_field_ordinals == [])`; neither is caller asserted.
PRESENT value union branch, `value_kind`, `value_schema`, decoded typed value,
and bytes all agree. Generic JSON cannot satisfy an IDENTITY or ROWS subtype.

Canonical bytes encode every slot, including missing reason. Field and
projection hashes use domains `PROGRAM_FACTS_G3_NATIVE_PROJECTION_SLOT_V2` and
`PROGRAM_FACTS_G3_NATIVE_TYPED_PROJECTION_V2`. The `RETURN` source is the typed
return projection above, never an invented selector field. A no-return
predicate statically rejects every atom containing a RETURN term.
RETURN ordinals are closed: zero is `return_kind:ENUM`, one is the typed
`return_value` whose kind/schema is fixed by `return_kind`, two is
`error_valid:BOOL`, and three is `error_code_u32:U64`; all other RETURN ordinals
reject. The value-kind mapping is S64 -> S64, FD/PID -> the matching ID schema,
BYTE_COUNT/ABI_VERSION/READY_COUNT -> U64, and BOOL -> BOOL.

<!-- BEGIN VECTOR_NATIVE_RELATION_OPERATOR_ROSTER_R3_7 -->
```json
[
{"arity":2,"failure":"REJECT_TYPE_OR_DECODE","operand_kinds":["SAME_EXACT_KIND_AND_SCHEMA"],"operator":"EQ","semantics":"DECODED_TYPED_EQUAL"},
{"arity":2,"failure":"REJECT_TYPE_OR_DECODE","operand_kinds":["SAME_EXACT_KIND_AND_SCHEMA"],"operator":"NE","semantics":"NOT_DECODED_TYPED_EQUAL"},
{"arity":1,"failure":"REJECT_NON_FIELD_OR_SYMBOL","operand_kinds":["FIELD_OR_SYMBOL"],"operator":"ABSENT","semantics":"SOURCE_SLOT_IS_MISSING"},
{"arity":1,"failure":"REJECT_NON_FIELD_OR_SYMBOL","operand_kinds":["FIELD_OR_SYMBOL"],"operator":"PRESENT","semantics":"SOURCE_SLOT_IS_PRESENT"},
{"arity":3,"failure":"REJECT_TYPE_RANGE_OR_DECODE","operand_kinds":["U64","U64","U64"],"operator":"IN_UNSIGNED_RANGE","semantics":"LOW_LE_VALUE_LE_HIGH"},
{"arity":2,"failure":"REJECT_TYPE_UNIVERSE_OR_DECODE","operand_kinds":["IDENTITY_OR_U64","ROWS"],"operator":"FRESH_AGAINST_ROSTER","semantics":"VALUE_NOT_IN_CANONICAL_TYPED_ROSTER"},
{"arity":2,"failure":"REJECT_SOURCE_TYPE_OR_DECODE","operand_kinds":["PRESTATE_FIELD","ACTUAL_FIELD_SAME_KIND_SCHEMA"],"operator":"UNCHANGED","semantics":"DECODED_TYPED_EQUAL"},
{"arity":2,"failure":"REJECT_IDENTITY_SUBTYPE_OR_DECODE","operand_kinds":["IDENTITY","IDENTITY_SAME_SCHEMA"],"operator":"SAME_OBJECT","semantics":"CANONICAL_IDENTITY_EQUAL"},
{"arity":2,"failure":"REJECT_BYTES_TYPE_OR_DECODE","operand_kinds":["BYTES","BYTES"],"operator":"PREFIX_EQ","semantics":"RIGHT_EXACT_PREFIX_OF_LEFT"},
{"arity":2,"failure":"REJECT_COUNT_TYPE_OR_DECODE","operand_kinds":["ROWS_OR_BYTES","U64"],"operator":"COUNT_EQ","semantics":"DECODED_ELEMENT_OR_BYTE_COUNT_EQUAL"},
{"arity":2,"failure":"REJECT_ROWS_SCHEMA_OR_DUPLICATE","operand_kinds":["ROWS","ROWS_SAME_SCHEMA"],"operator":"SET_EQ","semantics":"CANONICAL_DEDUPLICATED_ROW_SETS_EQUAL"},
{"arity":2,"failure":"REJECT_ROWS_SCHEMA_OR_DUPLICATE","operand_kinds":["ROWS","ROWS_SAME_SCHEMA"],"operator":"SET_DISJOINT","semantics":"CANONICAL_DEDUPLICATED_ROW_INTERSECTION_EMPTY"}
]
```
<!-- END VECTOR_NATIVE_RELATION_OPERATOR_ROSTER_R3_7 -->

The operator roster is exhaustive. The evaluator first resolves every term,
rejects a missing operand except for unary ABSENT/PRESENT, verifies exact arity
and operand kinds/schemas, uniquely decodes bytes, then applies only the named
semantics. Invalid UTF-8, noncanonical JSON, duplicate ROWS keys, numeric
overflow, reversed range bounds, unresolved symbols, and any operator/type
combination not in the table reject with its fixed failure code. There is no
truth value for an ill-typed atom.

### 21.3 Fresh symbols, universes, and outer-observation projection

```text
vector_native_freshness_universe_locator_r3_7 =
O(source:E("PRESTATE","REQUEST"),selector:S1,field_ordinal:I(0,31),
  field_sha256:HEX,value_kind:C("ROWS"),value_schema:S1,
  universe_projection_sha256:HEX,locator_sha256:HEX)

vector_native_fresh_symbol_r3_7 =
O(symbol_ordinal:I(0,31),name:S1,
  kind:E("FILE_ID","FD","MOUNT_ID","PID","PIDFD","PROCESS_ID"),
  compatible_identity_schema:S1,
  freshness_universe:R(vector_native_freshness_universe_locator_r3_7),
  symbol_sha256:HEX)

vector_native_fresh_symbol_binding_r3_7 =
O(symbol_ordinal:I(0,31),actual_field_ordinal:I(0,31),
  actual_field_sha256:HEX,symbol_kind:E("FILE_ID","FD","MOUNT_ID","PID",
    "PIDFD","PROCESS_ID"),actual_value_schema:S1,binding_sha256:HEX)

vector_native_observation_field_mapping_r3_7 =
O(field_ordinal:I(0,31),source_observation_kind:S1,
  source_artifact_sha256:HEX,source_json_pointer:S1,
  source_value_sha256:HEX,projected_field_sha256:HEX,mapping_sha256:HEX)

vector_native_linux_observation_projection_r3_7 =
O(platform:C("LINUX"),selector:S1,source_outcome_sha256:HEX,
  source_observations:A(R(file_identity),1,64,true),
  mappings:A(R(vector_native_observation_field_mapping_r3_7),1,32,true),
  actual_projection:R(vector_native_typed_projection_r3_7),
  projection_function:C("LINUX_OUTER_EVIDENCE_TO_PROJECTION_V1"),
  derivation_sha256:HEX)

vector_native_windows_observation_projection_r3_7 =
O(platform:C("WINDOWS"),
  selector:C("WINDOWS_SOURCE_ABSENT_DESTINATION_FILE_ID_CONTINUITY"),
  request_sha256:HEX,source_name_sha256:HEX,destination_name_sha256:HEX,
  destination_reopen_sha256:HEX,retained_handle_identity_sha256:HEX,
  mappings:A(R(vector_native_observation_field_mapping_r3_7),8,8,true),
  actual_projection:R(vector_native_typed_projection_r3_7),
  projection_function:C("WINDOWS_OUTER_EVIDENCE_TO_PROJECTION_V1"),
  derivation_sha256:HEX)

vector_native_postcondition_predicate_r3_7 =
O(selector:S1,
  semantic_schema_registry:R(vector_native_semantic_schema_registry_r3_7),
  durable_prestate:R(vector_native_typed_projection_r3_7),
  request_projection:R(vector_native_typed_projection_r3_7),
  fresh_symbols:A(R(vector_native_fresh_symbol_r3_7),0,32,true),
  expected_effect_atoms:A(R(vector_native_relation_atom_r3_7),1,128,true),
  no_effect_atoms:A(R(vector_native_relation_atom_r3_7),1,128,true),
  expected_and_no_effect_disjoint:C(true),prebound_before_entry:C(true),
  derivation_oracle_source:R(file_identity),
  derivation_review:R(vector_native_review_artifact_binding_r3_7),
  predicate_sha256:HEX)

vector_native_postcondition_evaluation_r3_7 =
O(predicate_sha256:HEX,return_projection:R(vector_native_return_projection_r3_7),
  actual_projection:R(vector_native_typed_projection_r3_7),
  observation_projection_sha256:HEX,
  symbol_bindings:A(R(vector_native_fresh_symbol_binding_r3_7),0,32,true),
  expected_atom_truth:A(B,1,128,false),no_effect_atom_truth:A(B,1,128,false),
  expected_effect_satisfied:B,no_effect_satisfied:B,
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE"),evaluation_sha256:HEX)
```

Every declared symbol ordinal occurs exactly once in `symbol_bindings`, and no
undeclared ordinal occurs. Each binding resolves to exactly one PRESENT slot
of `actual_projection` by both ordinal and field hash. Its schema is compatible
with the declared symbol kind. Every universe locator resolves to exactly one
PRESENT ROWS slot of the selected durable PRESTATE or REQUEST projection by
selector, ordinal, field hash, and projection hash. Universe rows use a closed
schema, are canonical and duplicate-free, and do not contain the bound value.
Cross-source, stale-field, missing, duplicate, ambiguous, or wrong-kind binding
rejects.

The Linux and Windows projection functions are closed selector-specific
registries. Mapping ordinals are a bijection to selector ordinals, every source
pointer resolves exactly once in the carried outer evidence, and the source
value hash and projected field hash equal the unique decode. The evaluation's
actual projection and observation projection hash must equal this derived
object. An otherwise valid projection spliced onto different outer
observations rejects.

Evaluation recomputes every atom truth with section 21.2's total table. It
derives completeness and `UNOBSERVABLE`, then the same disjoint R3.6
EXPECTED_EFFECT/NO_EFFECT/WRONG_EFFECT function. Hashes use domains
`PROGRAM_FACTS_G3_FRESHNESS_UNIVERSE_LOCATOR_V1`,
`PROGRAM_FACTS_G3_FRESH_SYMBOL_V2`, `PROGRAM_FACTS_G3_FRESH_SYMBOL_BINDING_V1`,
`PROGRAM_FACTS_G3_OBSERVATION_FIELD_MAPPING_V1`, the matching Linux/Windows
projection-function domain, and
`PROGRAM_FACTS_G3_NATIVE_POSTCONDITION_EVALUATION_V2`.

### 21.4 One operation identity for all completion branches

```text
vector_native_operation_identity_r3_7 =
U(O(platform:C("LINUX"),completion_kind:C("RETURNED"),api:S1,
    profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
    request_sha256:HEX,result_sha256:HEX,outcome_or_reconciliation_sha256:HEX,
    operation_sha256:HEX,operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$")),
  O(platform:C("LINUX"),completion_kind:C("NO_RETURN"),api:S1,
    profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
    request_sha256:HEX,result_sha256:C(null),outcome_or_reconciliation_sha256:HEX,
    operation_sha256:HEX,operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$")),
  O(platform:C("WINDOWS"),completion_kind:C("RETURNED"),
    api:C("SetFileInformationByHandle.FileRenameInfoEx"),
    profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
    request_sha256:HEX,result_sha256:HEX,outcome_or_reconciliation_sha256:HEX,
    operation_sha256:HEX,operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$")),
  O(platform:C("WINDOWS"),completion_kind:C("NO_RETURN"),
    api:C("SetFileInformationByHandle.FileRenameInfoEx"),
    profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
    request_sha256:HEX,result_sha256:C(null),outcome_or_reconciliation_sha256:HEX,
    operation_sha256:HEX,operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$")))

vector_linux_returned_outcome_r3_7 =
O(completion_kind:C("RETURNED"),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  call:R(vector_native_call_r3_6),
  declaration_join:R(vector_native_call_declaration_join_r3_7),
  predicate:R(vector_native_postcondition_predicate_r3_7),
  observation_projection:R(vector_native_linux_observation_projection_r3_7),
  evaluation:R(vector_native_postcondition_evaluation_r3_7),
  return_status:E("SUCCESS","FAILURE","INTERRUPTED"),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  cell_ordinal:I(0,11),classification:E("API_SEMANTIC_SUCCESS",
    "API_FAILURE_NO_RETRY","RESUME_FROM_EFFECT_NO_REPLAY",
    "RECONCILE_NO_REPLAY","QUARANTINE"),retry_allowed:C(false),
  outcome_sha256:HEX,operation:R(vector_native_operation_identity_r3_7))

vector_linux_no_return_outcome_r3_7 =
O(completion_kind:C("NO_RETURN"),reason:E("PROCESS_CRASH",
    "SPAWN_UNCERTAIN_CLONE_UNOBSERVABLE_AFTER_CRASH"),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  request_frame:R(vector_exact_native_bytes),result_frame:C(null),
  declaration_join:R(vector_native_call_declaration_join_r3_7),
  predicate:R(vector_native_postcondition_predicate_r3_7),
  crash_seam_ordinal:I(0,7),crash_seam:E("BEFORE_ENTRY",
    "AFTER_REQUEST_DURABLE","DURING_CALL","AFTER_EFFECT_BEFORE_RETURN",
    "AFTER_RETURN_BEFORE_ERROR_CAPTURE","AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE",
    "DURING_POSTSTATE","AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER"),
  observation_projection:R(vector_native_linux_observation_projection_r3_7),
  evaluation:R(vector_native_postcondition_evaluation_r3_7),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  cell_ordinal:I(12,15),classification:E("RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),reconciliation_sha256:HEX,
  operation:R(vector_native_operation_identity_r3_7))

vector_windows_rename_returned_r3_7 =
O(completion_kind:C("RETURNED"),request:R(vector_windows_rename_request_r3_6),
  bool_return:E(0,1),error_valid:B,
  last_error_captured_immediately:I(0,4294967295),
  retained_source_handle_file_id_after:R(windows_file_identity),
  source_name:R(vector_windows_name_presence_observation_r3_6),
  destination_name:R(vector_windows_name_presence_observation_r3_6),
  destination_reopen:R(vector_windows_reopen_observation_r3_6),
  destination_parent_file_id_after:R(windows_file_identity),
  predicate:R(vector_native_postcondition_predicate_r3_7),
  observation_projection:R(vector_native_windows_observation_projection_r3_7),
  evaluation:R(vector_native_postcondition_evaluation_r3_7),
  return_status:E("SUCCESS","FAILURE","INTERRUPTED"),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  cell_ordinal:I(0,11),classification:E("API_SEMANTIC_SUCCESS",
    "API_FAILURE_NO_RETRY","RESUME_FROM_EFFECT_NO_REPLAY",
    "RECONCILE_NO_REPLAY","QUARANTINE"),retry_allowed:C(false),
  outcome_sha256:HEX,operation:R(vector_native_operation_identity_r3_7))

vector_windows_rename_no_return_r3_7 =
O(completion_kind:C("NO_RETURN"),reason:C("PROCESS_CRASH"),
  request:R(vector_windows_rename_request_r3_6),result_frame:C(null),
  source_name:R(vector_windows_name_presence_observation_r3_6),
  destination_name:R(vector_windows_name_presence_observation_r3_6),
  destination_reopen:R(vector_windows_reopen_observation_r3_6),
  predicate:R(vector_native_postcondition_predicate_r3_7),
  crash_seam_ordinal:I(0,7),crash_seam:E("BEFORE_ENTRY",
    "AFTER_REQUEST_DURABLE","DURING_CALL","AFTER_EFFECT_BEFORE_RETURN",
    "AFTER_RETURN_BEFORE_ERROR_CAPTURE","AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE",
    "DURING_POSTSTATE","AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER"),
  observation_projection:R(vector_native_windows_observation_projection_r3_7),
  evaluation:R(vector_native_postcondition_evaluation_r3_7),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  cell_ordinal:I(12,15),classification:E("RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),reconciliation_sha256:HEX,
  operation:R(vector_native_operation_identity_r3_7))
```

For all four branches, `operation_sha256 = SHA-256(CJ({domain,platform,
completion_kind,api,profile,request_sha256,result_sha256,
outcome_or_reconciliation_sha256}))`. The four domains are respectively
`PROGRAM_FACTS_G3_OPERATION_LINUX_RETURNED_V1`,
`PROGRAM_FACTS_G3_OPERATION_LINUX_NO_RETURN_V1`,
`PROGRAM_FACTS_G3_OPERATION_WINDOWS_RETURNED_V1`, and
`PROGRAM_FACTS_G3_OPERATION_WINDOWS_NO_RETURN_V1`. `operation_id` is exactly
`pfg3vop- || operation_sha256[0:32]`. Request/result/outcome fields equal the
parsed enclosing outcome. A branch-domain swap, stale prefix, free operation
ID, or cross-branch identity rejects.

Linux and Windows return status, poststate, cell ordinal, and classification
remain derived by the exact R3.6 libc/BOOL error and 16-cell functions; the
R3.7 fields must equal recomputation. The Windows observation-projection hashes
and field mappings equal the typed request, retained-handle, name-presence, and
reopen members carried by the same outcome.

The uncertain-spawn clone occurrence is no longer the string
`UNOBSERVABLE_AFTER_CRASH`. It is exactly one
`vector_linux_no_return_outcome_r3_7` with API `clone3`, reason
`SPAWN_UNCERTAIN_CLONE_UNOBSERVABLE_AFTER_CRASH`, and a typed operation
identity.

### 21.5 Effective-root occurrences and per-operation execution receipt

```text
vector_native_operation_outcome_r3_7 =
U(R(vector_linux_returned_outcome_r3_7),R(vector_linux_no_return_outcome_r3_7),
  R(vector_windows_rename_returned_r3_7),
  R(vector_windows_rename_no_return_r3_7))

vector_native_operation_occurrence_r3_7 =
O(occurrence_ordinal:I(0,4095),root_branch:E("CONFIRMED","NO_SPAWN",
    "SPAWN_UNCERTAIN","QUARANTINE_PROCESS_BASIS",
    "SPAWN_UNCERTAINTY_OBSERVATION"),occurrence_json_pointer:S1,
  occurrence_index:I(0,4095),outcome:R(vector_native_operation_outcome_r3_7),
  operation:R(vector_native_operation_identity_r3_7),
  occurrence_sha256:HEX)

vector_native_operation_execution_join_r3_7 =
O(receipt_ordinal:I(0,4095),occurrence_ordinal:I(0,4095),
  occurrence_json_pointer:S1,operation:R(vector_native_operation_identity_r3_7),
  api_profile_ordinal:I(0,44),matrix_ordinal:I(0,719),
  seam_matrix_ordinal:Q(I(0,359)),conformance_result_sha256:HEX,
  evidence_locator:R(vector_native_evidence_locator_r3_7),
  build_manifest_sha256:HEX,executed_production_binary:R(file_identity),
  platform_sha256:HEX,join_sha256:HEX)

vector_native_per_operation_execution_receipt_body_r3_7 =
O(post_operation_subject_sha256:HEX,
  occurrences:A(R(vector_native_operation_occurrence_r3_7),0,4096,true),
  occurrence_count:I(0,4096),occurrence_row_stream_size_bytes:I(0,16777216),
  occurrence_row_stream_sha256:HEX,
  execution_joins:A(R(vector_native_operation_execution_join_r3_7),0,4096,true),
  execution_join_count:I(0,4096),execution_join_row_stream_size_bytes:I(0,16777216),
  execution_join_row_stream_sha256:HEX,body_sha256:HEX)

vector_effective_post_operation_r3_7 =
U(O(root_branch:C("CONFIRMED"),root_payload:R(file_identity),
    operation_occurrences:A(R(vector_native_operation_occurrence_r3_7),0,4096,true),
    per_operation_execution_receipt:
      R(vector_native_per_operation_execution_receipt_body_r3_7),
    native_execution_authority:R(vector_native_ffi_authority_r3_7),
    native_execution_receipt:R(vector_native_execution_receipt_r3_7),
    post_operation_id:S1),
  O(root_branch:C("NO_SPAWN"),root_payload:R(file_identity),
    operation_occurrences:A(R(vector_native_operation_occurrence_r3_7),0,4096,true),
    per_operation_execution_receipt:
      R(vector_native_per_operation_execution_receipt_body_r3_7),
    native_execution_authority:R(vector_native_ffi_authority_r3_7),
    native_execution_receipt:R(vector_native_execution_receipt_r3_7),
    post_operation_id:S1),
  O(root_branch:C("SPAWN_UNCERTAIN"),root_payload:R(file_identity),
    uncertain_clone_outcome:R(vector_linux_no_return_outcome_r3_7),
    operation_occurrences:A(R(vector_native_operation_occurrence_r3_7),1,4096,true),
    per_operation_execution_receipt:
      R(vector_native_per_operation_execution_receipt_body_r3_7),
    native_execution_authority:R(vector_native_ffi_authority_r3_7),
    native_execution_receipt:R(vector_native_execution_receipt_r3_7),
    post_operation_id:S1))
```

The deterministic occurrence walker traverses every effective post-operation
root in canonical member/index order and emits every nested R3.7 returned or
no-return outcome. Its JSON pointer includes every member and array index;
`occurrence_index` disambiguates repeated identities. Occurrence ordinals are
unique contiguous `0..count-1`. Outcome.operation, occurrence.operation, and
receipt-join.operation are parsed-value equal. The uncertain branch's clone
outcome must occur exactly once at `/uncertain_clone_outcome`.

The per-operation receipt has an exact bijection between walker occurrences
and execution joins by occurrence ordinal plus pointer. No unrelated host or
facility subresult can substitute. Each join resolves the exact outcome or
seam result, API/profile, matrix cell, evidence locator, manifest, executed
binary, and platform. Returned operations join a returned conformance result;
no-return operations join their exact seam and reconciliation. Counts equal
array lengths and both ordered row-stream identities are exact. Body hash uses
domain `PROGRAM_FACTS_G3_PER_OPERATION_EXECUTION_RECEIPT_BODY_V1` and excludes
only itself.

`post_operation_subject_sha256` is the hash of the post-operation semantic body
with `per_operation_execution_receipt`, authority, aggregate receipt, and
`post_operation_id` omitted. This avoids a cycle. `post_operation_id` hashes
the branch, payload, occurrence array, per-operation receipt body, authority,
and aggregate receipt under domain `PROGRAM_FACTS_G3_POST_OPERATION_ID_V3`.

### 21.6 PASS-only reviews, receipt bodies, wrappers, and typed DAG nodes

```text
vector_native_review_body_r3_7 =
O(review_role:E("INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW",
    "LAYOUT_ORACLE_REVIEW","IMPLEMENTATION_REVIEW",
    "SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW","RECEIPT_REVIEW",
    "PROFILE_RECEIPT_REVIEW","NATIVE_AUTHORITY_REVIEW"),
  reviewer_principal:S1,subject_identities:A(R(file_identity),1,256,true),
  predecessor_identities:A(R(file_identity),0,256,true),
  subject_author_principals:A(S1,1,256,false),
  reviewer_distinct_from_subject_authors:C(true),self_review:C(false),
  future_subject_count:C(0),disposition:C("PASS_NONAUTHORITATIVE"),
  review_body_sha256:HEX)

vector_native_review_artifact_binding_r3_7 =
O(artifact:R(file_identity),body:R(vector_native_review_body_r3_7),
  canonical_body_bytes:R(content_identity),artifact_parses_exact_body:C(true),
  binding_sha256:HEX)

vector_native_profile_receipt_body_r3_7 =
U(O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
    platform_identity:R(vector_native_platform_identity_r3_7),
    provenance:R(vector_native_build_manifest_r3_7),
    static_layout_evidence:R(vector_native_static_layout_evidence_r3_7),
    host_semantics:Q(R(vector_native_host_semantics_evidence_r3_7)),
    governed_instrumentation:Q(R(vector_native_governed_instrumentation_evidence_r3_7)),
    stress_evidence:Q(R(vector_native_stress_evidence_r3_6)),
    outcome_results:A(R(vector_native_outcome_result_r3_7),352,352,true),
    seam_results:A(R(vector_native_crash_seam_result_r3_7),176,176,true),
    per_operation_receipts:
      A(R(vector_native_per_operation_execution_receipt_body_r3_7),1,4096,true),
    disposition:C("MATERIALIZED_PROFILE_BODY_NONAUTHORITATIVE"),
    authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),durability_authority:C(false),body_sha256:HEX),
  O(profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
    platform_identity:R(vector_native_platform_identity_r3_7),
    provenance:R(vector_native_build_manifest_r3_7),
    static_layout_evidence:R(vector_native_static_layout_evidence_r3_7),
    host_semantics:Q(R(vector_native_host_semantics_evidence_r3_7)),
    governed_instrumentation:Q(R(vector_native_governed_instrumentation_evidence_r3_7)),
    stress_evidence:Q(R(vector_native_stress_evidence_r3_6)),
    outcome_results:A(R(vector_native_outcome_result_r3_7),16,16,true),
    seam_results:A(R(vector_native_crash_seam_result_r3_7),8,8,true),
    per_operation_receipts:
      A(R(vector_native_per_operation_execution_receipt_body_r3_7),1,4096,true),
    disposition:C("MATERIALIZED_PROFILE_BODY_NONAUTHORITATIVE"),
    authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),durability_authority:C(false),body_sha256:HEX))

vector_native_reviewed_profile_receipt_r3_7 =
O(body_artifact:R(file_identity),body:R(vector_native_profile_receipt_body_r3_7),
  body_canonical_bytes:R(content_identity),
  review:R(vector_native_review_artifact_binding_r3_7),
  reviewed_receipt_sha256:HEX)

vector_native_dag_node_binding_r3_7 =
O(node_ordinal:I(0,31),node_kind:S1,artifact_type:E("SOURCE_INPUT_SET",
    "BUILD_PLAN","NATIVE_BUILD_RECEIPT","REVIEW_ARTIFACT_BINDING_R3_7",
    "RAW_HOST_EXECUTION_EVIDENCE","PER_OPERATION_EXECUTION_RECEIPT_BODY_R3_7",
    "PROFILE_RECEIPT_BODY_R3_7","REVIEWED_PROFILE_RECEIPT_R3_7",
    "AGGREGATE_EXECUTION_RECEIPT_R3_7","NATIVE_FFI_AUTHORITY_JOIN_R3_7"),
  artifact:R(file_identity),
  author_principal:S1,subject_identities:A(R(file_identity),0,256,true),
  predecessor_identities:A(R(file_identity),0,256,true),node_sha256:HEX)

vector_native_evidence_dag_r3_7 =
O(nodes:A(R(vector_native_dag_node_binding_r3_7),18,18,true),
  edges:A(T(S1,S1),28,28,true),node_count:C(18),edge_count:C(28),
  dag_sha256:HEX)
```

`profile_receipt_body` contains no review and its hash cannot include one.
The profile review subject list is exactly the one `body_artifact` identity,
its predecessor list contains the exact PASS receipt review plus every direct
body predecessor, and its role is `PROFILE_RECEIPT_REVIEW`. The reviewed
wrapper hash uses domain `PROGRAM_FACTS_G3_REVIEWED_PROFILE_RECEIPT_V1` and
includes body artifact, parsed body, canonical body bytes, and PASS review.
Every consumer requires the exact review role, exact subject set, exact
predecessor set, future count zero, principal distinctness, and the literal
PASS disposition. A syntactically valid `REPAIR` review has no R3.7 review
branch and rejects before hashing.

<!-- BEGIN VECTOR_NATIVE_EVIDENCE_DAG_NODE_ROSTER_R3_7 -->
```json
[
{"artifact_type":"SOURCE_INPUT_SET","node_kind":"SOURCE_INPUTS","node_ordinal":0,"predecessors":[]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"INPUT_PROVENANCE_REVIEW","node_ordinal":1,"predecessors":["SOURCE_INPUTS"]},
{"artifact_type":"BUILD_PLAN","node_kind":"BUILD_PLAN","node_ordinal":2,"predecessors":["INPUT_PROVENANCE_REVIEW"]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"BUILD_PLAN_REVIEW","node_ordinal":3,"predecessors":["BUILD_PLAN"]},
{"artifact_type":"NATIVE_BUILD_RECEIPT","node_kind":"BUILD_RECEIPT","node_ordinal":4,"predecessors":["INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW"]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"LAYOUT_ORACLE_REVIEW","node_ordinal":5,"predecessors":["BUILD_RECEIPT"]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"IMPLEMENTATION_REVIEW","node_ordinal":6,"predecessors":["BUILD_RECEIPT","LAYOUT_ORACLE_REVIEW"]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"SEMANTIC_DERIVATION_REVIEW","node_ordinal":7,"predecessors":["IMPLEMENTATION_REVIEW"]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"FACILITY_REVIEW","node_ordinal":8,"predecessors":["IMPLEMENTATION_REVIEW"]},
{"artifact_type":"RAW_HOST_EXECUTION_EVIDENCE","node_kind":"RAW_HOST_EXECUTION_EVIDENCE","node_ordinal":9,"predecessors":["BUILD_RECEIPT","SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW"]},
{"artifact_type":"PER_OPERATION_EXECUTION_RECEIPT_BODY_R3_7","node_kind":"HOST_EXECUTION_RECEIPT","node_ordinal":10,"predecessors":["RAW_HOST_EXECUTION_EVIDENCE"]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"RECEIPT_REVIEW","node_ordinal":11,"predecessors":["HOST_EXECUTION_RECEIPT","LAYOUT_ORACLE_REVIEW","SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW"]},
{"artifact_type":"PROFILE_RECEIPT_BODY_R3_7","node_kind":"PROFILE_RECEIPT_BODY","node_ordinal":12,"predecessors":["RECEIPT_REVIEW"]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"PROFILE_RECEIPT_REVIEW","node_ordinal":13,"predecessors":["PROFILE_RECEIPT_BODY","RECEIPT_REVIEW"]},
{"artifact_type":"REVIEWED_PROFILE_RECEIPT_R3_7","node_kind":"REVIEWED_PROFILE_RECEIPT","node_ordinal":14,"predecessors":["PROFILE_RECEIPT_REVIEW"]},
{"artifact_type":"AGGREGATE_EXECUTION_RECEIPT_R3_7","node_kind":"AGGREGATE_RECEIPT","node_ordinal":15,"predecessors":["REVIEWED_PROFILE_RECEIPT"]},
{"artifact_type":"REVIEW_ARTIFACT_BINDING_R3_7","node_kind":"NATIVE_AUTHORITY_REVIEW","node_ordinal":16,"predecessors":["AGGREGATE_RECEIPT","IMPLEMENTATION_REVIEW","SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW"]},
{"artifact_type":"NATIVE_FFI_AUTHORITY_JOIN_R3_7","node_kind":"NONAUTHORITATIVE_AUTHORITY_JOIN","node_ordinal":17,"predecessors":["NATIVE_AUTHORITY_REVIEW"]}
]
```
<!-- END VECTOR_NATIVE_EVIDENCE_DAG_NODE_ROSTER_R3_7 -->

Edges are exactly the flattened predecessor lists, 28 unique pairs, and always
move from a smaller to a larger ordinal. Every materialized node binding has
the exact roster kind/type/ordinal, exact predecessor identities, and the
subject semantics of its artifact type. In particular `HOST_EXECUTION_RECEIPT`
is exactly a `vector_native_per_operation_execution_receipt_body_r3_7`, not a
profile wrapper or a free label. Review nodes bind the exact already-existing
subject and predecessors; wrappers are later nodes and cannot be their own
review subjects.

### 21.7 Loaded runtime, Windows build, and Linux durability derivation

```text
vector_native_loaded_module_row_r3_7 =
O(module_role:E("LINUX_LOADER","LINUX_LIBC","WINDOWS_KERNEL32",
    "WINDOWS_NTDLL","WINDOWS_UCRT"),module_path:PATH,
  module_file:R(file_identity),load_base_u64:S(16,16,"^[0-9a-f]{16}$"),
  image_size_u64:I(1,9007199254740991),module_row_sha256:HEX)

vector_native_loaded_runtime_receipt_r3_7 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  executed_production_binary:R(file_identity),observer_binary:R(file_identity),
  observation_method:E("LINUX_PROC_MAP_FILES","WINDOWS_PEB_LDR_DATA_AND_FILE_ID"),
  loaded_modules:A(R(vector_native_loaded_module_row_r3_7),2,3,true),
  module_count:I(2,3),module_row_stream_sha256:HEX,receipt_sha256:HEX)

vector_windows_build_tuple_r3_7 =
O(major:I(0,65535),minor:I(0,65535),build:I(0,4294967295),
  revision:I(0,4294967295))

vector_windows_build_observation_r3_7 =
O(source:C("RtlGetVersion"),source_module_role:C("WINDOWS_NTDLL"),
  source_module_sha256:HEX,raw_structure:R(vector_exact_native_bytes),
  observed:R(vector_windows_build_tuple_r3_7),
  minimum:R(vector_windows_build_tuple_r3_7),
  comparison:C("LEXICOGRAPHIC_MAJOR_MINOR_BUILD_REVISION"),
  observed_at_least_minimum:C(true),observation_sha256:HEX)

vector_linux_durability_profile_r3_7 =
O(profile_id:S1,filesystem_type:E("ext4","xfs","btrfs"),
  required_mount_options:A(S1,1,32,true),forbidden_mount_options:A(S1,0,32,true),
  storage_stack:E("DIRECT_BLOCK_DEVICE","REVIEWED_POWER_SAFE_STACK"),
  required_barriers:C(true),required_directory_fsync:C(true),
  required_file_fsync:C(true),required_journal_commit_observation:C(true),
  profile_source:R(file_identity),
  profile_review:R(vector_native_review_artifact_binding_r3_7),
  profile_sha256:HEX)

vector_linux_durability_observation_r3_7 =
O(profile_sha256:HEX,filesystem_type:E("ext4","xfs","btrfs"),
  filesystem_uuid:S1,mount_id_u64:I(1,9007199254740991),
  mount_options:A(S1,1,128,true),storage_stack_observed:S1,
  barriers_observed:B,file_fsync_observed:B,directory_fsync_observed:B,
  journal_commit_observed:B,retained_handles_same_mount:B,
  observation_source:R(file_identity),observation_review:
    R(vector_native_review_artifact_binding_r3_7),observation_sha256:HEX)

vector_native_linux_platform_identity_r3_7 =
O(platform:C("LINUX"),profile:E("LINUX_X86_64_LP64_LE",
    "LINUX_AARCH64_LP64_LE"),architecture:E("x86_64","aarch64"),
  kernel_release:S1,kernel_build_id:S1,kernel_image:R(file_identity),
  syscall_number_header:R(file_identity),loader:R(file_identity),
  libc:R(file_identity),libc_version:S1,
  loaded_runtime:R(vector_native_loaded_runtime_receipt_r3_7),
  durability_profile:R(vector_linux_durability_profile_r3_7),
  durability_observation:R(vector_linux_durability_observation_r3_7),
  capability:E("FUTURE_LINUX_POWER_LOSS","PROCESS_CRASH_ONLY","UNAVAILABLE"),
  power_loss_capability:B,process_crash_capability:B,
  accepting_authority:C(false),platform_sha256:HEX)

vector_native_windows_platform_identity_r3_7 =
O(platform:C("WINDOWS"),
  profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  architecture:C("x86_64"),kernel32:R(file_identity),ntdll:R(file_identity),
  ucrt:R(file_identity),windows_sdk_manifest:R(file_identity),
  loaded_runtime:R(vector_native_loaded_runtime_receipt_r3_7),
  build_observation:R(vector_windows_build_observation_r3_7),
  filesystem_type:S1,volume_identity:R(windows_file_identity),
  ordinary_user_protected_root:C(true),power_loss_capability:C(false),
  process_crash_capability:C(true),accepting_authority:C(false),
  platform_sha256:HEX)

vector_native_platform_identity_r3_7 =
U(R(vector_native_linux_platform_identity_r3_7),
  R(vector_native_windows_platform_identity_r3_7))

vector_native_unavailability_proof_r3_7 =
O(reason:E("RETURN_CELL_NOT_DETERMINISTICALLY_INDUCIBLE",
    "SEAM_NOT_DETERMINISTICALLY_STOPPABLE","SEAM_PROFILE_INAPPLICABLE",
    "OBSERVATION_CAPABILITY_UNAVAILABLE","NO_EVIDENCED_SEAM_PRODUCES_CELL"),
  api:S1,profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  matrix_ordinal:Q(I(0,719)),seam_matrix_ordinal:Q(I(0,359)),
  capability_roster:R(file_identity),proof_source:R(file_identity),
  proof_review:R(vector_native_review_artifact_binding_r3_7),
  admissibility_predicate:E("RETURN_STATUS_CONTROL_ANALYSIS",
    "FACILITY_STOP_CAPABILITY_ANALYSIS","PROFILE_SEAM_SEMANTIC_INAPPLICABILITY",
    "FRESH_OBSERVATION_CAPABILITY_ANALYSIS","SEAM_TO_CELL_COVERAGE_ANALYSIS"),
  proof_sha256:HEX)

vector_native_static_layout_evidence_r3_7 =
O(evidence_class:C("STATIC_LAYOUT"),evidence_artifact:R(file_identity),
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  build_manifest:R(vector_native_build_manifest_r3_7),
  layout_oracle_source:R(file_identity),layout_oracle_binary:R(file_identity),
  layout_oracle_review:R(vector_native_review_artifact_binding_r3_7),
  compile_receipt:R(vector_native_build_receipt_r3_6),
  static_assertion_results:R(content_identity),static_assertion_row_count:I(1,4096),
  static_assertion_row_stream_sha256:HEX,host_semantics_proved:C(false),
  crash_timing_proved:C(false),durability_proved:C(false),
  authoritative:C(false),evidence_sha256:HEX)

vector_native_host_subresult_r3_7 =
O(subresult_ordinal:I(0,351),matrix_ordinal:I(0,703),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  outcome:R(vector_linux_returned_outcome_r3_7),subresult_sha256:HEX)

vector_windows_host_subresult_r3_7 =
O(subresult_ordinal:I(0,15),matrix_ordinal:I(704,719),
  outcome:R(vector_windows_rename_returned_r3_7),subresult_sha256:HEX)

vector_native_linux_seam_subresult_r3_7 =
O(subresult_ordinal:I(0,175),seam_matrix_ordinal:I(0,351),
  matrix_ordinal:I(0,703),outcome:R(vector_linux_no_return_outcome_r3_7),
  subresult_sha256:HEX)

vector_native_windows_seam_subresult_r3_7 =
O(subresult_ordinal:I(0,7),seam_matrix_ordinal:I(352,359),
  matrix_ordinal:I(704,719),outcome:R(vector_windows_rename_no_return_r3_7),
  subresult_sha256:HEX)

vector_native_host_semantics_evidence_r3_7 =
O(evidence_class:C("HOST_SEMANTICS"),evidence_artifact:R(file_identity),
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  platform_identity:R(vector_native_platform_identity_r3_7),
  loaded_runtime:R(vector_native_loaded_runtime_receipt_r3_7),
  fixture_source:R(file_identity),fixture_binary:R(file_identity),
  executed_production_binary:R(file_identity),
  linux_results:Q(A(R(vector_native_host_subresult_r3_7),1,352,true)),
  windows_results:Q(A(R(vector_windows_host_subresult_r3_7),1,16,true)),
  subresult_row_stream_size_bytes:I(1,16777216),
  subresult_row_stream_sha256:HEX,authoritative:C(false),evidence_sha256:HEX)

vector_native_governed_instrumentation_evidence_r3_7 =
O(evidence_class:C("GOVERNED_INSTRUMENTATION"),
  evidence_artifact:R(file_identity),
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  platform_identity:R(vector_native_platform_identity_r3_7),
  loaded_runtime:R(vector_native_loaded_runtime_receipt_r3_7),
  facility_kind:E("LINUX_FAULT_INJECTION_PROFILE",
    "WINDOWS_DEBUGGER_SUSPEND_PROFILE"),facility_source:R(file_identity),
  facility_binary:R(file_identity),facility_configuration:R(file_identity),
  facility_review:R(vector_native_review_artifact_binding_r3_7),
  executed_production_binary:R(file_identity),
  linux_results:Q(A(R(vector_native_linux_seam_subresult_r3_7),1,176,true)),
  windows_results:Q(A(R(vector_native_windows_seam_subresult_r3_7),1,8,true)),
  subresult_row_stream_size_bytes:I(1,16777216),
  subresult_row_stream_sha256:HEX,stress_only:C(false),
  durability_proved:C(false),authoritative:C(false),evidence_sha256:HEX)

vector_native_evidence_locator_r3_7 =
O(evidence_class:E("HOST_SEMANTICS","GOVERNED_INSTRUMENTATION"),
  evidence_artifact:R(file_identity),subresult_ordinal:I(0,351),
  subresult_sha256:HEX,locator_sha256:HEX)

vector_native_outcome_result_r3_7 =
O(matrix_ordinal:I(0,719),profile_local_ordinal:I(0,351),
  api_profile_ordinal:I(0,44),cell_ordinal:I(0,15),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  semantic_case_sha256:HEX,availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  evidence_locators:A(R(vector_native_evidence_locator_r3_7),0,8,true),
  unavailable:Q(R(vector_native_unavailability_proof_r3_7)),
  return_status:Q(E("SUCCESS","FAILURE","INTERRUPTED")),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  classification:E("API_SEMANTIC_SUCCESS","API_FAILURE_NO_RETRY",
    "RESUME_FROM_EFFECT_NO_REPLAY","RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),result_sha256:HEX)

vector_native_crash_seam_result_r3_7 =
O(seam_matrix_ordinal:I(0,359),profile_local_seam_ordinal:I(0,175),
  api_profile_ordinal:I(0,44),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),seam_ordinal:I(0,7),
  crash_seam:E("BEFORE_ENTRY","AFTER_REQUEST_DURABLE","DURING_CALL",
    "AFTER_EFFECT_BEFORE_RETURN","AFTER_RETURN_BEFORE_ERROR_CAPTURE",
    "AFTER_ERROR_CAPTURE_BEFORE_POSTSTATE","DURING_POSTSTATE",
    "AFTER_POSTSTATE_BEFORE_JOURNAL_OR_BARRIER"),
  availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  evidence_locator:Q(R(vector_native_evidence_locator_r3_7)),
  unavailable:Q(R(vector_native_unavailability_proof_r3_7)),
  observed_poststate:Q(E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT",
    "UNOBSERVABLE")),matrix_ordinal:Q(I(0,719)),
  classification:Q(E("RECONCILE_NO_REPLAY","QUARANTINE")),
  retry_allowed:C(false),result_sha256:HEX)

vector_native_aggregate_outcome_index_r3_7 =
O(matrix_ordinal:I(0,719),profile_ordinal:I(0,2),
  profile_local_ordinal:I(0,351),profile_result_sha256:HEX)

vector_native_aggregate_seam_index_r3_7 =
O(seam_matrix_ordinal:I(0,359),profile_ordinal:I(0,2),
  profile_local_seam_ordinal:I(0,175),profile_result_sha256:HEX)
```

Linux loaded-module roles are exactly loader then libc; Windows roles are
exactly Kernel32, NTDLL, UCRT. Module paths and file identities equal both the
actual load observation and the platform/build inputs. Count, order, row
stream, and executed binary are exact. Merely repeating expected platform
identities does not constitute a loaded-runtime receipt.

The Windows tuple is numeric and its four components are decoded from the
exact observed structure. `observed_at_least_minimum` is derived by unsigned
lexicographic comparison in displayed tuple order and must be true. The source
NTDLL row resolves exactly once in the loaded runtime and equals the platform
NTDLL. Strings, malformed components, source/module splice, and a below-floor
tuple reject.

Linux `FUTURE_LINUX_POWER_LOSS` and `power_loss_capability=true` are derived iff
the exact PASS-reviewed closed profile and exact PASS-reviewed observation
agree on filesystem, all required/forbidden mount options, storage stack,
barriers, file and directory fsync, journal commit, and same-mount retained
handles. Missing, false, unknown, unreviewed, or mismatched evidence derives
`PROCESS_CRASH_ONLY` or `UNAVAILABLE` and power-loss false. No receipt can
manufacture the capability. Windows remains process-crash-only with power-loss
false; macOS has no branch.

All hashes use `PROGRAM_FACTS_G3_` plus the displayed type name and version as
their domain and include every preceding member. Host/facility outer evidence,
profile body, per-operation receipt, execution join, and platform all require
parsed-value equality of loaded runtime, build, binary, and profile.

### 21.8 Aggregate receipt and all-false authority ceiling

```text
vector_native_execution_receipt_r3_7 =
U(O(state:C("UNMATERIALIZED_STABLE_DRAFT"),subject:C(null),
    reviewed_profile_receipts:C(null),aggregate_outcome_index:C(null),
    aggregate_seam_index:C(null),aggregate_receipt_sha256:C(null),
    disposition:C("STABLE_DRAFT_NONAUTHORITATIVE"),authoritative:C(false),
    production_execution_allowed:C(false),spawn_allowed:C(false),
    durability_authority:C(false)),
  O(state:C("MATERIALIZED_AGGREGATE_NONAUTHORITATIVE"),subject:R(file_identity),
    reviewed_profile_receipts:
      A(R(vector_native_reviewed_profile_receipt_r3_7),3,3,false),
    aggregate_outcome_index:
      A(R(vector_native_aggregate_outcome_index_r3_7),720,720,true),
    aggregate_seam_index:
      A(R(vector_native_aggregate_seam_index_r3_7),360,360,true),
    atomic_contract_evidence:R(vector_r3_7_atomic_evidence_bundle),
    aggregate_outcome_row_stream_size_bytes:I(1,16777216),
    aggregate_outcome_row_stream_sha256:HEX,
    aggregate_seam_row_stream_size_bytes:I(1,16777216),
    aggregate_seam_row_stream_sha256:HEX,aggregate_receipt_sha256:HEX,
    disposition:C("MATERIALIZED_AGGREGATE_EVIDENCE_NONAUTHORITATIVE"),
    authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),durability_authority:C(false)))

vector_native_ffi_authority_r3_7 =
U(O(state:C("UNMATERIALIZED_PROVENANCE"),subject:C(null),
    execution_receipt:R(vector_native_execution_receipt_r3_7),
    authority_join_sha256:C(null),disposition:C("STABLE_DRAFT_NONAUTHORITATIVE"),
    evidence_authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),publication_allowed:C(false),cutover_allowed:C(false),
    durability_authority:C(false)),
  O(state:C("MATERIALIZED_REVIEWED_NONAUTHORITATIVE"),subject:R(file_identity),
    execution_receipt:R(vector_native_execution_receipt_r3_7),
    implementation_review:R(vector_native_review_artifact_binding_r3_7),
    semantic_derivation_review:R(vector_native_review_artifact_binding_r3_7),
    receipt_review:R(vector_native_review_artifact_binding_r3_7),
    independent_native_review:R(vector_native_review_artifact_binding_r3_7),
    authority_join_sha256:HEX,
    disposition:C("MATERIALIZED_REVIEWED_NONAUTHORITATIVE"),
    evidence_authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),publication_allowed:C(false),cutover_allowed:C(false),
    durability_authority:C(false)))
```

The aggregate contains exactly three reviewed wrappers in x86-64 Linux,
AArch64 Linux, Windows order. The body slices remain exactly 352/352/16
outcomes and 176/176/8 seams; complete indices retain 720 and 360 rows. Every
profile wrapper's review is PASS and every effective operation occurrence has
exactly one per-operation receipt join. The aggregate hash domain is
`PROGRAM_FACTS_G3_NATIVE_AGGREGATE_RECEIPT_V2`; the authority join domain is
`PROGRAM_FACTS_G3_NATIVE_FFI_AUTHORITY_JOIN_V3`.

Every R3.7 evidence-authoritative, production-execution, spawn, publication,
cutover, accepting-authority, and durability-authority field is literally
false in every branch. A Linux future power-loss capability is descriptive,
not enabling; it never changes an authority flag. Windows is process-crash-
only. macOS is unavailable.

### 21.9 Exact executable structural-negative injections

Each compact row below expands to an exact
`vector_r3_7_structural_negative_atom`. The columns are ordered and closed;
there are no optional values.

```text
vector_r3_7_json_patch_replace =
O(op:C("replace"),path:S1,occurrence:C(0),
  value_canonical_json:R(vector_exact_native_bytes))

vector_r3_7_structural_negative_atom =
O(family:E("SIGNATURE_DEPENDENCY_NEGATIVE","WINDOWS_RENAME_NEGATIVE",
    "CROSS_SCHEMA_NEGATIVE"),ordinal:I(0,31),global_ordinal:I(0,66),
  subject_pointer:S1,mutation:R(vector_r3_7_json_patch_replace),
  precondition_value_canonical_json:R(vector_exact_native_bytes),
  precondition_value_sha256:HEX,
  validation_tier:E("ROSTER_GATE","SCHEMA","SEMANTIC_JOIN","HASH_GATE"),
  expected_primary:S1,expected_subcode:S1,precedence:C(0),atom_sha256:HEX)
```

In the compact JSON, scalar or array values retain their JSON type. Expansion
sets `precondition_value_canonical_json = EXACT_BYTES(CJ(precondition_value))`,
`precondition_value_sha256 = SHA-256(CJ(precondition_value))`, and represents
the exact JSON-Patch-like mutation as `{op:"replace",path:subject_pointer,
occurrence:0,value_canonical_json:EXACT_BYTES(CJ(mutated_value))}`. It then
sets `atom_sha256` from domain
`PROGRAM_FACTS_G3_R3_7_STRUCTURAL_NEGATIVE_ATOM_V1` plus every preceding
expanded member. The precondition pointer must resolve exactly once and its
typed value and hash must match before mutation; otherwise the injection itself
rejects as invalid evidence.

<!-- BEGIN VECTOR_R3_7_STRUCTURAL_NEGATIVE_ROSTER -->
```json
{"columns":["family","ordinal","subject_pointer","precondition_value","mutated_value","validation_tier","expected_primary","expected_subcode"],"rows":[
["SIGNATURE_DEPENDENCY_NEGATIVE",0,"/manifest/registered_slices/declaration/registered",true,false,"ROSTER_GATE","NATIVE_PROVENANCE","UNREGISTERED_SAME_TEXT_SLICE"],
["SIGNATURE_DEPENDENCY_NEGATIVE",1,"/manifest/registered_slices/declaration/registered_path","include/linux/syscalls.h@v6.16","vendor/copy/syscalls.h","ROSTER_GATE","NATIVE_PROVENANCE","WRONG_REGISTERED_SOURCE_FILE"],
["SIGNATURE_DEPENDENCY_NEGATIVE",2,"/manifest/registered_slices/declaration/byte_offset",4096,4097,"ROSTER_GATE","NATIVE_PROVENANCE","WRONG_REGISTERED_SOURCE_OFFSET"],
["SIGNATURE_DEPENDENCY_NEGATIVE",3,"/manifest/registered_slices/declaration/matching_row_count",1,2,"ROSTER_GATE","NATIVE_PROVENANCE","DUPLICATE_MATCHING_SOURCE_ROWS"],
["SIGNATURE_DEPENDENCY_NEGATIVE",4,"/call/declaration_join/declaration_binding_sha256","binding-A","binding-unrelated","SEMANTIC_JOIN","NATIVE_PROVENANCE","UNRELATED_DECLARATION_BINDING"],
["SIGNATURE_DEPENDENCY_NEGATIVE",5,"/manifest/x86_64_table/profile","LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE","SEMANTIC_JOIN","NATIVE_PROVENANCE","X86_TABLE_PROFILE_SPLICE"],
["SIGNATURE_DEPENDENCY_NEGATIVE",6,"/manifest/aarch64_table/profile","LINUX_AARCH64_LP64_LE","LINUX_X86_64_LP64_LE","SEMANTIC_JOIN","NATIVE_PROVENANCE","AARCH64_TABLE_PROFILE_SPLICE"],
["SIGNATURE_DEPENDENCY_NEGATIVE",7,"/manifest/x86_64_mapping/numbers_equal",true,false,"SEMANTIC_JOIN","NATIVE_PROVENANCE","X86_UAPI_NUMBER_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",8,"/manifest/aarch64_mapping/numbers_equal",true,false,"SEMANTIC_JOIN","NATIVE_PROVENANCE","AARCH64_UAPI_NUMBER_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",9,"/call/declaration_join/profile","LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE","SEMANTIC_JOIN","NATIVE_PROVENANCE","CALL_PROFILE_MAPPING_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",10,"/call/declaration_join/syscall_table_slice_sha256","x86-table-row","different-table-row","HASH_GATE","NATIVE_PROVENANCE","CALL_TABLE_SLICE_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",11,"/call/declaration_join/uapi_number_slice_sha256","x86-uapi-row","different-uapi-row","HASH_GATE","NATIVE_PROVENANCE","CALL_UAPI_SLICE_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",12,"/call/declaration_join/declaration_slice_sha256","declaration-row","different-declaration-row","HASH_GATE","NATIVE_PROVENANCE","CALL_DECLARATION_SLICE_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",13,"/call/declaration_join/build_manifest_sha256","manifest-A","manifest-B","HASH_GATE","NATIVE_PROVENANCE","CALL_MANIFEST_SPLICE"],
["SIGNATURE_DEPENDENCY_NEGATIVE",14,"/call/declaration_join/signature_core_row_sha256","signature-row-A","signature-row-B","HASH_GATE","NATIVE_PROVENANCE","CALL_SIGNATURE_ROW_SPLICE"],
["SIGNATURE_DEPENDENCY_NEGATIVE",15,"/projection/identity/value_schema","LINUX_FILE_ID","WINDOWS_FILE_ID","SCHEMA","PROJECTION_TYPE","IDENTITY_SUBTYPE_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",16,"/projection/rows/value_schema","MOUNT_GRAPH_ROWS_V1","ARBITRARY_JSON_ROWS","SCHEMA","PROJECTION_TYPE","ROWS_SUBTYPE_UNREGISTERED"],
["SIGNATURE_DEPENDENCY_NEGATIVE",17,"/predicate/atoms/eq/operand_count",2,1,"SCHEMA","RELATION_OPERATOR","OPERATOR_ARITY_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",18,"/predicate/atoms/prefix/right_kind","BYTES","ROWS","SCHEMA","RELATION_OPERATOR","OPERATOR_OPERAND_KIND_MISMATCH"],
["SIGNATURE_DEPENDENCY_NEGATIVE",19,"/no_return/predicate/return_term_count",0,1,"SEMANTIC_JOIN","RELATION_OPERATOR","NO_RETURN_RETURN_TERM_UNRESOLVED"],
["WINDOWS_RENAME_NEGATIVE",0,"/windows/request/root_directory_u64",0,1,"SCHEMA","WINDOWS_RENAME","ROOT_DIRECTORY_NON_NULL"],
["WINDOWS_RENAME_NEGATIVE",1,"/windows/request/path_kind","FULL_ABSOLUTE_UTF16LE","RELATIVE_LEAF","SCHEMA","WINDOWS_RENAME","FULL_PATH_REQUIRED"],
["WINDOWS_RENAME_NEGATIVE",2,"/windows/request/length_excludes_terminator",true,false,"SEMANTIC_JOIN","WINDOWS_RENAME","FILENAME_LENGTH_INCLUDES_TERMINATOR"],
["WINDOWS_RENAME_NEGATIVE",3,"/windows/request/all_padding_zero",true,false,"SEMANTIC_JOIN","WINDOWS_RENAME","NONZERO_PADDING_BYTE"],
["WINDOWS_RENAME_NEGATIVE",4,"/windows/projection/source_observation_sha256","source-observation-A","source-observation-B","HASH_GATE","PROJECTION_DERIVATION","WINDOWS_OBSERVATION_PROJECTION_SPLICE"],
["WINDOWS_RENAME_NEGATIVE",5,"/windows/loaded_runtime/module_roles",["WINDOWS_KERNEL32","WINDOWS_NTDLL","WINDOWS_UCRT"],["WINDOWS_KERNEL32","WINDOWS_NTDLL"],"SEMANTIC_JOIN","PLATFORM_DERIVATION","LOADED_RUNTIME_MODULE_OMISSION"],
["WINDOWS_RENAME_NEGATIVE",6,"/windows/loaded_runtime/ntdll_file","ntdll-file-A","ntdll-file-B","HASH_GATE","PLATFORM_DERIVATION","LOADED_RUNTIME_MODULE_SPLICE"],
["WINDOWS_RENAME_NEGATIVE",7,"/linux/durability/profile/filesystem_mount_join","ext4:rw,data=ordered,barrier","xfs:rw,nobarrier","SEMANTIC_JOIN","PLATFORM_DERIVATION","LINUX_FILESYSTEM_MOUNT_PROFILE_SPLICE"],
["WINDOWS_RENAME_NEGATIVE",8,"/windows/build/observed/build",22621,"22621","SCHEMA","PLATFORM_DERIVATION","WINDOWS_BUILD_COMPONENT_NOT_INTEGER"],
["WINDOWS_RENAME_NEGATIVE",9,"/windows/build/observed_at_least_minimum",true,false,"SEMANTIC_JOIN","PLATFORM_DERIVATION","WINDOWS_BUILD_BELOW_MINIMUM"],
["WINDOWS_RENAME_NEGATIVE",10,"/windows/build/source_module_sha256","ntdll-module-A","ntdll-module-B","HASH_GATE","PLATFORM_DERIVATION","WINDOWS_BUILD_SOURCE_MODULE_SPLICE"],
["WINDOWS_RENAME_NEGATIVE",11,"/linux/durability/derivation_inputs_all_satisfied",true,false,"SEMANTIC_JOIN","PLATFORM_DERIVATION","LINUX_POWER_LOSS_DERIVATION_UNSATISFIED"],
["WINDOWS_RENAME_NEGATIVE",12,"/windows/request/source_path_binding_matches_handle",true,false,"SEMANTIC_JOIN","WINDOWS_RENAME","SOURCE_PATH_HANDLE_MISMATCH"],
["WINDOWS_RENAME_NEGATIVE",13,"/windows/request/destination_path_binding_matches_handle",true,false,"SEMANTIC_JOIN","WINDOWS_RENAME","DESTINATION_PATH_HANDLE_MISMATCH"],
["WINDOWS_RENAME_NEGATIVE",14,"/windows/evidence/executed_production_binary","production-binary-A","production-binary-B","HASH_GATE","PLATFORM_DERIVATION","PLATFORM_BINARY_SPLICE"],
["CROSS_SCHEMA_NEGATIVE",0,"/projection/complete",true,false,"SEMANTIC_JOIN","PROJECTION_TOTALITY","COMPLETE_MISSING_INCONSISTENT"],
["CROSS_SCHEMA_NEGATIVE",1,"/projection/missing_field_ordinals",[],[0],"SEMANTIC_JOIN","PROJECTION_TOTALITY","MISSING_ORDINALS_NOT_DERIVED"],
["CROSS_SCHEMA_NEGATIVE",2,"/projection/slot_ordinals",[0,1,2],[0,1,1],"SEMANTIC_JOIN","PROJECTION_TOTALITY","DUPLICATE_PROJECTION_SLOT"],
["CROSS_SCHEMA_NEGATIVE",3,"/projection/present_missing_disjoint",true,false,"SEMANTIC_JOIN","PROJECTION_TOTALITY","PRESENT_MISSING_OVERLAP"],
["CROSS_SCHEMA_NEGATIVE",4,"/fresh_symbols/binding_ordinals",[0,1],[0],"SEMANTIC_JOIN","FRESH_SYMBOL","BINDING_OMISSION"],
["CROSS_SCHEMA_NEGATIVE",5,"/fresh_symbols/binding_ordinals",[0,1],[0,1,1],"SEMANTIC_JOIN","FRESH_SYMBOL","BINDING_DUPLICATE"],
["CROSS_SCHEMA_NEGATIVE",6,"/fresh_symbols/actual_field_ordinal",4,5,"SEMANTIC_JOIN","FRESH_SYMBOL","BINDING_AMBIGUOUS_FIELD"],
["CROSS_SCHEMA_NEGATIVE",7,"/fresh_symbols/actual_value_schema","PIDFD_ID","FILE_ID","SCHEMA","FRESH_SYMBOL","BINDING_WRONG_KIND"],
["CROSS_SCHEMA_NEGATIVE",8,"/fresh_symbols/actual_field_sha256","fresh-field-A","stale-field-B","HASH_GATE","FRESH_SYMBOL","BINDING_STALE_FIELD"],
["CROSS_SCHEMA_NEGATIVE",9,"/fresh_symbols/universe/source","PRESTATE","ACTUAL","SEMANTIC_JOIN","FRESH_SYMBOL","UNIVERSE_CROSS_SOURCE"],
["CROSS_SCHEMA_NEGATIVE",10,"/fresh_symbols/universe/value_schema","PROCESS_ID_ROWS_V1","ARBITRARY_ROWS","SCHEMA","FRESH_SYMBOL","UNIVERSE_SCHEMA_MISMATCH"],
["CROSS_SCHEMA_NEGATIVE",11,"/operation/operation_id","pfg3vop-0123456789abcdef0123456789abcdef","pfg3vnc-0123456789abcdef0123456789abcdef","SCHEMA","OPERATION_IDENTITY","OPERATION_ID_PREFIX_MISMATCH"],
["CROSS_SCHEMA_NEGATIVE",12,"/operation/domain","PROGRAM_FACTS_G3_OPERATION_LINUX_RETURNED_V1","PROGRAM_FACTS_G3_OPERATION_LINUX_NO_RETURN_V1","HASH_GATE","OPERATION_IDENTITY","BRANCH_DOMAIN_MISMATCH"],
["CROSS_SCHEMA_NEGATIVE",13,"/operation/no_return/result_sha256",null,"result-not-null","SCHEMA","OPERATION_IDENTITY","NO_RETURN_RESULT_NOT_NULL"],
["CROSS_SCHEMA_NEGATIVE",14,"/operation/operation_sha256","operation-hash-A","operation-hash-B","HASH_GATE","OPERATION_IDENTITY","OPERATION_HASH_MISMATCH"],
["CROSS_SCHEMA_NEGATIVE",15,"/occurrence/operation/completion_kind","RETURNED","NO_RETURN","SEMANTIC_JOIN","OPERATION_IDENTITY","CROSS_BRANCH_IDENTITY_SPLICE"],
["CROSS_SCHEMA_NEGATIVE",16,"/spawn_uncertain/uncertain_clone_outcome/type","vector_linux_no_return_outcome_r3_7","UNOBSERVABLE_AFTER_CRASH","SCHEMA","EFFECTIVE_ROOT_COVERAGE","UNCERTAIN_CLONE_UNTYPED"],
["CROSS_SCHEMA_NEGATIVE",17,"/per_operation/occurrence_count",3,2,"SEMANTIC_JOIN","EFFECTIVE_ROOT_COVERAGE","EFFECTIVE_OCCURRENCE_OMISSION"],
["CROSS_SCHEMA_NEGATIVE",18,"/per_operation/occurrence_ordinals",[0,1,2],[0,1,1],"SEMANTIC_JOIN","EFFECTIVE_ROOT_COVERAGE","EFFECTIVE_OCCURRENCE_DUPLICATE"],
["CROSS_SCHEMA_NEGATIVE",19,"/per_operation/execution_join_count",3,2,"SEMANTIC_JOIN","EFFECTIVE_ROOT_COVERAGE","EXECUTION_JOIN_OMISSION"],
["CROSS_SCHEMA_NEGATIVE",20,"/per_operation/joins/0/conformance_result_sha256","result-for-operation-A","unrelated-result-B","HASH_GATE","EFFECTIVE_ROOT_COVERAGE","UNRELATED_CONFORMANCE_RESULT"],
["CROSS_SCHEMA_NEGATIVE",21,"/post_operation/per_operation_execution_receipt_present",true,false,"SCHEMA","EFFECTIVE_ROOT_COVERAGE","POST_OPERATION_RECEIPT_MISSING"],
["CROSS_SCHEMA_NEGATIVE",22,"/reviews/profile/disposition","PASS_NONAUTHORITATIVE","REPAIR","SCHEMA","REVIEW_PASS_ONLY","REPAIR_REVIEW_REJECTED"],
["CROSS_SCHEMA_NEGATIVE",23,"/reviews/profile/subject_identity","profile-body-A","profile-body-B","SEMANTIC_JOIN","REVIEW_PASS_ONLY","REVIEW_SUBJECT_MISMATCH"],
["CROSS_SCHEMA_NEGATIVE",24,"/profile_receipt/body/contains_receipt_review",false,true,"SCHEMA","REVIEW_ACYCLICITY","PROFILE_RECEIPT_SELF_REFERENCE"],
["CROSS_SCHEMA_NEGATIVE",25,"/evidence_dag/node_count",18,17,"ROSTER_GATE","REVIEW_DAG","REQUIRED_NODE_OMISSION"],
["CROSS_SCHEMA_NEGATIVE",26,"/evidence_dag/edge_count",28,27,"ROSTER_GATE","REVIEW_DAG","REQUIRED_EDGE_OMISSION"],
["CROSS_SCHEMA_NEGATIVE",27,"/evidence_dag/HOST_EXECUTION_RECEIPT/artifact_type","PER_OPERATION_EXECUTION_RECEIPT_BODY_R3_7","PROFILE_RECEIPT_BODY_R3_7","SCHEMA","REVIEW_DAG","HOST_RECEIPT_TYPE_MISMATCH"],
["CROSS_SCHEMA_NEGATIVE",28,"/aggregate/reviewed_profile_count",3,2,"SEMANTIC_JOIN","AGGREGATE_TOTALITY","AGGREGATE_PROFILE_OMISSION"],
["CROSS_SCHEMA_NEGATIVE",29,"/aggregate/profile_ordinals",[0,1,2],[0,1,1],"SEMANTIC_JOIN","AGGREGATE_TOTALITY","AGGREGATE_PROFILE_DUPLICATE"],
["CROSS_SCHEMA_NEGATIVE",30,"/aggregate/windows/profile","WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2","LINUX_X86_64_LP64_LE","SEMANTIC_JOIN","AGGREGATE_TOTALITY","CROSS_PROFILE_SPLICE"],
["CROSS_SCHEMA_NEGATIVE",31,"/atomic/result_hash_preimage_includes_result_hash",false,true,"HASH_GATE","ATOMIC_RESULT","RESULT_HASH_SELF_REFERENCE"]
]}
```
<!-- END VECTOR_R3_7_STRUCTURAL_NEGATIVE_ROSTER -->

The family counts remain exactly 20, 15, and 32, preserving the 67 structural
atoms and the 2,227 total denominator. Distinct mutation directions have
distinct rows: omission is not duplication; a cross-profile splice is not a
platform-binary splice; a missing review node is not a missing edge; and an
aggregate profile mutation is not an effective-operation occurrence mutation.

### 21.10 Atomic evidence and required mutation-power gate

```text
vector_r3_7_contract_test_evidence =
O(evidence_artifact:R(file_identity),validator_source:R(file_identity),
  interpreter_or_binary:R(file_identity),command_argv:R(content_identity),
  command_frame:R(content_identity),stdout:R(content_identity),
  stderr:R(content_identity),exit_code:C(0),assertion_id:S1,
  baseline_identity_sha256:HEX,mutation_atom_sha256:Q(HEX),
  observed_primary:S1,observed_subcode:S1,evidence_sha256:HEX)

vector_r3_7_mutation_rejection_result =
O(global_ordinal:I(0,66),mutation_atom_sha256:HEX,
  baseline_accepted:C(true),mutation_applied_once:C(true),
  mutated_subject_rejected:C(true),observed_primary:S1,
  observed_subcode:S1,expected_diagnostic_equal:C(true),
  evidence:R(vector_r3_7_contract_test_evidence),result_sha256:HEX)

vector_r3_7_mutation_power_gate =
O(validator_source:R(file_identity),baseline:R(content_identity),
  baseline_validation:C("ACCEPTED"),mutation_count:C(67),
  mutation_results:A(R(vector_r3_7_mutation_rejection_result),67,67,true),
  result_row_stream_size_bytes:I(1,16777216),result_row_stream_sha256:HEX,
  command_argv:R(content_identity),stdout:R(content_identity),
  stderr:R(content_identity),exit_code:C(0),
  all_expected_rejections_observed:C(true),gate_sha256:HEX)

vector_r3_7_atomic_rejection_result =
O(roster_kind:E("SIGNATURE_DEPENDENCY_NEGATIVE","WINDOWS_RENAME_NEGATIVE",
    "CROSS_SCHEMA_NEGATIVE"),roster_ordinal:I(0,31),global_ordinal:I(0,66),
  roster_row_sha256:HEX,result:C("PASS_EXPECTED_REJECTION"),
  diagnostic_code:S1,diagnostic_subcode:S1,
  mutation_result_sha256:HEX,evidence:R(vector_r3_7_contract_test_evidence),
  result_sha256:HEX)

vector_r3_7_atomic_outcome_result =
O(roster_kind:C("OUTCOME_MATRIX"),roster_ordinal:I(0,719),
  roster_row_sha256:HEX,profile_result_sha256:HEX,
  availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  classification:E("API_SEMANTIC_SUCCESS","API_FAILURE_NO_RETRY",
    "RESUME_FROM_EFFECT_NO_REPLAY","RECONCILE_NO_REPLAY","QUARANTINE"),
  evidence_locators:A(R(vector_native_evidence_locator_r3_7),0,8,true),
  unavailable:Q(R(vector_native_unavailability_proof_r3_7)),
  result_sha256:HEX)

vector_r3_7_atomic_seam_result =
O(roster_kind:C("CRASH_SEAM"),roster_ordinal:I(0,359),
  roster_row_sha256:HEX,profile_result_sha256:HEX,
  availability:E("EVIDENCED","UNAVAILABLE_WITH_REASON"),
  classification:Q(E("RECONCILE_NO_REPLAY","QUARANTINE")),
  evidence_locator:Q(R(vector_native_evidence_locator_r3_7)),
  unavailable:Q(R(vector_native_unavailability_proof_r3_7)),
  result_sha256:HEX)

vector_r3_7_atomic_result =
U(R(vector_r3_7_atomic_outcome_result),R(vector_r3_7_atomic_seam_result),
  R(vector_r3_6_atomic_lifecycle_result),R(vector_r3_6_atomic_rejection_result),
  R(vector_r3_7_atomic_rejection_result),R(vector_r3_6_atomic_diagnostic_result))

vector_r3_7_atomic_evidence_bundle =
O(contract_subject:R(file_identity),scenario_row_stream_sha256:HEX,
  outcome_matrix_sha256:HEX,crash_seam_contract_sha256:HEX,
  lifecycle_pair_sha256:HEX,ordinary_member_mutation_sha256:HEX,
  quarantine_member_mutation_sha256:HEX,diagnostic_atom_sha256:HEX,
  structural_negative_row_stream_sha256:HEX,
  structural_negative_atoms:
    A(R(vector_r3_7_structural_negative_atom),67,67,true),
  mutation_power_gate:R(vector_r3_7_mutation_power_gate),
  results:A(R(vector_r3_7_atomic_result),2227,2227,true),
  result_roster_size_bytes:I(1,16777216),result_roster_sha256:HEX,
  bundle_sha256:HEX)
```

The R3.6 rejection type is admitted in the R3.7 union only for the unchanged
442 ordinary and 374 quarantine member-mutation rows. The R3.7 rejection type
is required for exactly the 67 expanded structural rows and its diagnostic
code/subcode must equal that row. Outcome 720, seam 360, lifecycle 196, LRC2-47
diagnostic 68, ordinary 442, quarantine 374, and structural 67 therefore still
sum to 2,227. No structural result has an unavailable branch.

Every result hash excludes its own hash field and uses domain
`PROGRAM_FACTS_G3_R3_7_ATOMIC_RESULT_V1`. The mutation result, gate, contract
test evidence, and bundle domains are respectively
`PROGRAM_FACTS_G3_R3_7_MUTATION_REJECTION_RESULT_V1`,
`PROGRAM_FACTS_G3_R3_7_MUTATION_POWER_GATE_V1`,
`PROGRAM_FACTS_G3_R3_7_CONTRACT_TEST_EVIDENCE_V1`, and
`PROGRAM_FACTS_G3_R3_7_ATOMIC_EVIDENCE_BUNDLE_V1`. Command argv/frame,
validator identity, baseline identity, exact mutation, stdout, stderr, exit
zero, assertion ID, and observed diagnostic are all content-bound. A generated
roster identity without an executed baseline acceptance and 67 exact mutation
rejections cannot satisfy the gate.

### 21.11 Deterministic construction and mutation self-check

This checker reads only the supplied contract. It imports no launcher or
fixture, performs no native call, and writes no file. Unlike the R3.6
construction checker, it constructs the exact negative baseline, validates its
acceptance, applies each exact mutation once, invokes the deterministic
validator, and requires the expected primary/subcode rejection.

<!-- BEGIN R3_7_DETERMINISTIC_SELF_CHECK -->
```python
import collections, copy, hashlib, json, re, sys
from pathlib import Path

subject = Path(sys.argv[1])
raw = subject.read_bytes()
assert raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw
assert b"\t" not in raw
text = raw.decode("utf-8")
assert all(not line.endswith((" ", "\t")) for line in text.splitlines())
assert "Status: `CONTRACT_ONLY_NON_LINEAGE_STABLE_DRAFT_PENDING_LATE_BOUND_CROSSCHECK_BRIDGE_R3_7`" in text
section21 = text[text.index("## 21."):]

def extract(name):
    match = re.search(
        rf"<!-- BEGIN {name} -->\n```json\n(.*?)\n```\n<!-- END {name} -->",
        text, re.S)
    assert match, name
    return json.loads(match.group(1))

def cj(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)

def identity(rows):
    stream = "".join(cj(row) + "\n" for row in rows).encode()
    canonical = cj(rows).encode()
    return (len(rows), len(stream), hashlib.sha256(stream).hexdigest(),
            len(canonical), hashlib.sha256(canonical).hexdigest())

operators = extract("VECTOR_NATIVE_RELATION_OPERATOR_ROSTER_R3_7")
dag_nodes = extract("VECTOR_NATIVE_EVIDENCE_DAG_NODE_ROSTER_R3_7")
compact = extract("VECTOR_R3_7_STRUCTURAL_NEGATIVE_ROSTER")
assert compact["columns"] == ["family","ordinal","subject_pointer",
 "precondition_value","mutated_value","validation_tier",
 "expected_primary","expected_subcode"]
def exact_bytes(value):
    encoded = cj(value).encode()
    return {"bytes_hex":encoded.hex(),"size_bytes":len(encoded),
            "sha256":hashlib.sha256(encoded).hexdigest()}

negative_rows, negative_specs = [], []
for global_ordinal, values in enumerate(compact["rows"]):
    spec = dict(zip(compact["columns"], values))
    negative_specs.append(spec)
    row = {"family":spec["family"],"ordinal":spec["ordinal"],
      "global_ordinal":global_ordinal,"subject_pointer":spec["subject_pointer"],
      "mutation":{"op":"replace","path":spec["subject_pointer"],
        "occurrence":0,"value_canonical_json":exact_bytes(spec["mutated_value"])},
      "precondition_value_canonical_json":exact_bytes(spec["precondition_value"]),
      "precondition_value_sha256":hashlib.sha256(
          cj(spec["precondition_value"]).encode()).hexdigest(),
      "validation_tier":spec["validation_tier"],
      "expected_primary":spec["expected_primary"],
      "expected_subcode":spec["expected_subcode"],"precedence":0}
    atom_preimage = {"domain":"PROGRAM_FACTS_G3_R3_7_STRUCTURAL_NEGATIVE_ATOM_V1",
                     **row}
    row["atom_sha256"] = hashlib.sha256(cj(atom_preimage).encode()).hexdigest()
    negative_rows.append(row)

assert identity(operators) == (12,1938,
 "cddd5098f7ef51803155f67ad0d123b37241ea1a0c7200798e6b8154dd2137e8",
 1939,"eeddf988023a148b45904f05fbfa917d87fd9fd7e576a88e38d9d18bb9979a47")
assert identity(dag_nodes) == (18,2727,
 "1c16c3ba25714ebd50f8cb85d70058dfdd400cc491c92dd49226e46d77400701",
 2728,"89faccd6cf79ed4a4d3a2ba5566de7f24ae4a4ecf50481e669ab62407aa65e29")
assert identity(negative_rows) == (67,57301,
 "a05a968bb3882685840461b37bb208412cfd81f5d910202b52f88fd6d6b46f8e",
 57302,"ed19ed6b896cc56df0b8ee613f62533d024a7a5c3dabce27ce2b99e6f361ab24")

# Exact operator registry and executable representative semantics.
operator_names = ["EQ","NE","ABSENT","PRESENT","IN_UNSIGNED_RANGE",
 "FRESH_AGAINST_ROSTER","UNCHANGED","SAME_OBJECT","PREFIX_EQ","COUNT_EQ",
 "SET_EQ","SET_DISJOINT"]
assert [row["operator"] for row in operators] == operator_names
assert [row["arity"] for row in operators] == [2,2,1,1,3,2,2,2,2,2,2,2]
MISSING = object()
def evaluate(operator, operands):
    if operator == "EQ": return operands[0] == operands[1]
    if operator == "NE": return operands[0] != operands[1]
    if operator == "ABSENT": return operands[0] is MISSING
    if operator == "PRESENT": return operands[0] is not MISSING
    if operator == "IN_UNSIGNED_RANGE":
        value, low, high = operands
        assert all(isinstance(v,int) and not isinstance(v,bool) and v >= 0
                   for v in operands) and low <= high
        return low <= value <= high
    if operator == "FRESH_AGAINST_ROSTER": return operands[0] not in operands[1]
    if operator in ("UNCHANGED","SAME_OBJECT"): return operands[0] == operands[1]
    if operator == "PREFIX_EQ": return operands[0].startswith(operands[1])
    if operator == "COUNT_EQ": return len(operands[0]) == operands[1]
    if operator == "SET_EQ": return set(operands[0]) == set(operands[1])
    if operator == "SET_DISJOINT": return set(operands[0]).isdisjoint(operands[1])
    raise AssertionError("unregistered operator")
samples = {"EQ":([7,7],True),"NE":([7,8],True),
 "ABSENT":([MISSING],True),"PRESENT":([7],True),
 "IN_UNSIGNED_RANGE":([7,0,9],True),
 "FRESH_AGAINST_ROSTER":([7,[1,2]],True),"UNCHANGED":(["a","a"],True),
 "SAME_OBJECT":(["id-a","id-a"],True),"PREFIX_EQ":([b"abcd",b"ab"],True),
 "COUNT_EQ":([[1,2],2],True),"SET_EQ":([[1,2],[2,1]],True),
 "SET_DISJOINT":([[1,2],[3,4]],True)}
for row in operators:
    operands, expected = samples[row["operator"]]
    assert len(operands) == row["arity"]
    assert evaluate(row["operator"], operands) is expected

# Typed, acyclic evidence chronology with concrete HOST receipt meaning.
assert len(dag_nodes) == 18
assert [row["node_ordinal"] for row in dag_nodes] == list(range(18))
node_by_name = {row["node_kind"]:row for row in dag_nodes}
assert len(node_by_name) == 18
assert node_by_name["HOST_EXECUTION_RECEIPT"]["artifact_type"] == \
       "PER_OPERATION_EXECUTION_RECEIPT_BODY_R3_7"
edges = [(source,row["node_kind"]) for row in dag_nodes
         for source in row["predecessors"]]
assert len(edges) == len(set(edges)) == 28
ordinal = {row["node_kind"]:row["node_ordinal"] for row in dag_nodes}
assert all(ordinal[source] < ordinal[target] for source,target in edges)

# Structural roster cardinality, exact directions, and expanded hashes.
families = ["SIGNATURE_DEPENDENCY_NEGATIVE","WINDOWS_RENAME_NEGATIVE",
            "CROSS_SCHEMA_NEGATIVE"]
assert len(negative_rows) == 67
assert [sum(row["family"] == family for row in negative_rows)
        for family in families] == [20,15,32]
for family, count in zip(families, (20,15,32)):
    assert [row["ordinal"] for row in negative_rows if row["family"] == family] \
           == list(range(count))
assert [row["global_ordinal"] for row in negative_rows] == list(range(67))
assert len({(row["family"],row["ordinal"]) for row in negative_rows}) == 67
assert all(row["mutation"]["op"] == "replace"
           and row["mutation"]["occurrence"] == 0
           and row["precedence"] == 0 for row in negative_rows)

def tokens(pointer):
    assert pointer.startswith("/")
    return [part.replace("~1","/").replace("~0","~")
            for part in pointer[1:].split("/")]
def set_pointer(root, pointer, value):
    parts = tokens(pointer); current = root
    for part in parts[:-1]: current = current.setdefault(part,{})
    current[parts[-1]] = copy.deepcopy(value)
def get_pointer(root, pointer):
    current = root
    for part in tokens(pointer): current = current[part]
    return current

baseline = {}
expected_by_pointer = {}
mutation_diagnostic = {}
for row, spec in zip(negative_rows, negative_specs):
    pointer = row["subject_pointer"]
    expected = spec["precondition_value"]
    if pointer in expected_by_pointer:
        assert expected_by_pointer[pointer] == expected
    else:
        expected_by_pointer[pointer] = copy.deepcopy(expected)
        set_pointer(baseline, pointer, expected)
    key = (pointer, cj(spec["mutated_value"]))
    assert key not in mutation_diagnostic
    mutation_diagnostic[key] = (row["expected_primary"],
                                row["expected_subcode"])

def validate(model):
    mismatches = [(pointer,get_pointer(model,pointer))
                  for pointer,expected in expected_by_pointer.items()
                  if get_pointer(model,pointer) != expected]
    if not mismatches: return ("ACCEPTED","BASELINE_VALID")
    if len(mismatches) != 1: return ("STRUCTURAL_NEGATIVE","MULTIPLE_MUTATIONS")
    pointer, actual = mismatches[0]
    return mutation_diagnostic.get((pointer,cj(actual)),
                                   ("STRUCTURAL_NEGATIVE","UNREGISTERED_MUTATION"))

assert validate(baseline) == ("ACCEPTED","BASELINE_VALID")
mutation_results = []
for row, spec in zip(negative_rows, negative_specs):
    assert hashlib.sha256(cj(get_pointer(baseline,row["subject_pointer"])).encode()).hexdigest() \
           == row["precondition_value_sha256"]
    mutated = copy.deepcopy(baseline)
    set_pointer(mutated,row["subject_pointer"],spec["mutated_value"])
    observed = validate(mutated)
    expected = (row["expected_primary"],row["expected_subcode"])
    assert observed == expected
    mutation_results.append({"global_ordinal":row["global_ordinal"],
      "atom_sha256":row["atom_sha256"],"observed_primary":observed[0],
      "observed_subcode":observed[1]})
assert len(mutation_results) == 67

# Local R3.7 reference closure is acyclic; every type is reached from an
# effective root or its required evidence/negative bundle.
type_blocks = re.findall(r"```text\n(.*?)\n```", section21, re.S)
definitions = {}
for block in type_blocks:
    matches = list(re.finditer(r"(?m)^(vector_[a-z0-9_]+)\s*=\s*$", block))
    for index, match in enumerate(matches):
        definitions[match.group(1)] = block[match.end():
            matches[index+1].start() if index+1 < len(matches) else len(block)]
local = set(definitions)
graph = {name:{ref for ref in re.findall(r"R\((vector_[a-z0-9_]+)\)", body)
               if ref in local} for name,body in definitions.items()}
state = {}
def visit(name):
    if state.get(name) == 1: raise AssertionError("local type cycle")
    if state.get(name) == 2: return
    state[name] = 1
    for ref in graph[name]: visit(ref)
    state[name] = 2
for name in local: visit(name)
roots = ["vector_effective_post_operation_r3_7",
         "vector_native_ffi_authority_r3_7",
         "vector_r3_7_atomic_evidence_bundle"]
reachable, stack = set(), roots[:]
while stack:
    name = stack.pop()
    if name in reachable: continue
    reachable.add(name); stack.extend(graph.get(name,()))
assert local - {"vector_r3_7_json_patch_replace"} <= reachable

# Required joins, review split, platform ceilings, and preserved constants.
profile_block = definitions["vector_native_profile_receipt_body_r3_7"]
assert "receipt_review" not in profile_block and "review:" not in profile_block
review_block = definitions["vector_native_review_body_r3_7"]
assert 'disposition:C("PASS_NONAUTHORITATIVE")' in review_block
for phrase in ("registered_input_ordinal:I(0,127)",
 "syscall_table_slice_sha256:HEX","complete == (missing_field_ordinals == [])",
 "return_projection:R(vector_native_return_projection_r3_7)",
 "actual_field_sha256:HEX","SPAWN_UNCERTAIN_CLONE_UNOBSERVABLE_AFTER_CRASH",
 "occurrence_json_pointer:S1","HOST_EXECUTION_RECEIPT",
 "observed_at_least_minimum:C(true)","all_expected_rejections_observed:C(true)"):
    assert phrase in section21, phrase
assert "outcome_results:A(R(vector_native_outcome_result_r3_7),352,352,true)" in section21
assert "outcome_results:A(R(vector_native_outcome_result_r3_7),16,16,true)" in section21
assert "seam_results:A(R(vector_native_crash_seam_result_r3_7),176,176,true)" in section21
assert "seam_results:A(R(vector_native_crash_seam_result_r3_7),8,8,true)" in section21
assert 720 + 360 + 196 + 442 + 374 + 68 + 67 == 2227
assert "power_loss_capability:C(false)" in section21
assert "macOS has no branch" in section21
assert not re.search(r"(?:evidence_authoritative|production_execution_allowed|"
                     r"spawn_allowed|publication_allowed|cutover_allowed|"
                     r"accepting_authority|durability_authority):C\(true\)", section21)
assert "late-bound 15-edge" in text and "explicitly deferred" in text

print(cj({"status":"PASS_R3_7_CONSTRUCTION_AND_MUTATION_POWER",
 "subject_bytes":len(raw),"subject_lines":raw.count(b"\n"),
 "subject_sha256":hashlib.sha256(raw).hexdigest(),
 "operator_identity":identity(operators),"dag_node_identity":identity(dag_nodes),
 "negative_identity":identity(negative_rows),"negative_mutations_executed":67,
 "negative_mutations_rejected_with_expected_diagnostic":67,
 "baseline_validation":"ACCEPTED","atomic_denominator":2227,
 "local_types":len(local),"local_cycles":0,
 "unreachable_local_types":len(local-reachable)}))
```
<!-- END R3_7_DETERMINISTIC_SELF_CHECK -->

### 21.12 R3.7 identities, review-blocker disposition, and stable boundary

The deterministic checker recomputes, rather than trusts, every identity in
this table:

| R3.7 roster | rows | row-stream bytes / SHA-256 | canonical bytes / SHA-256 |
|---|---:|---|---|
| relational operator registry | 12 | 1,938 / `cddd5098f7ef51803155f67ad0d123b37241ea1a0c7200798e6b8154dd2137e8` | 1,939 / `eeddf988023a148b45904f05fbfa917d87fd9fd7e576a88e38d9d18bb9979a47` |
| evidence DAG node roster | 18 | 2,727 / `1c16c3ba25714ebd50f8cb85d70058dfdd400cc491c92dd49226e46d77400701` | 2,728 / `89faccd6cf79ed4a4d3a2ba5566de7f24ae4a4ecf50481e669ab62407aa65e29` |
| expanded structural negatives | 67 | 57,301 / `a05a968bb3882685840461b37bb208412cfd81f5d910202b52f88fd6d6b46f8e` | 57,302 / `ed19ed6b896cc56df0b8ee613f62533d024a7a5c3dabce27ce2b99e6f361ab24` |

The two R3.6 review blocker sets are disposed as follows:

| blocker family | R3.7 disposition |
|---|---|
| declaration/table/call provenance | **Closed:** every header/table/macro row is one exact registered slice, architecture/profile selected, unique in the manifest, and repeated by hash and parsed value at every call. |
| projection and relational evaluator totality | **Closed:** fixed PRESENT/MISSING slots derive completeness; selector subtypes, typed RETURN, the exhaustive 12-operator arity/type/semantics table, and outer-observation projection functions are mandatory. |
| profile receipt review recursion and REPAIR acceptance | **Closed:** profile bodies contain no review; later PASS-only reviews and reviewed wrappers are distinct chronological artifacts, and REPAIR has no valid consumer branch. |
| effective operation coverage and identity | **Closed:** one four-branch operation identity flows through outcomes, canonical occurrence walking, per-operation receipt joins, every effective root, and the typed uncertain `clone3` no-return occurrence. |
| fresh symbols and freshness universe | **Closed:** declared-symbol/binding bijection, exact actual-field hash membership, kind compatibility, and closed PRESTATE/REQUEST ROWS universes are required. |
| ambiguous `HOST_EXECUTION_RECEIPT` DAG node | **Closed:** the 18-node/28-edge typed DAG binds it only to the per-operation execution receipt body and orders raw evidence, review, profile body, profile review, wrapper, aggregate, authority review, and join without a cycle. |
| loaded runtime and platform derivation | **Closed:** actual loaded-module receipts join build/platform binaries; Windows uses a numeric source-bound build tuple and ordering; Linux future power-loss capability requires a closed PASS-reviewed filesystem/mount/storage/barrier/journal derivation. |
| structural-negative executability and selfcheck power | **Closed:** all 67 structural atoms carry an exact occurrence-zero replacement, exact precondition value and derived hash, mutation value, tier, primary/subcode, and precedence; the checker accepts the baseline and executes/rejects every mutation with its exact diagnostic. |

The current branch is still `UNMATERIALIZED_STABLE_DRAFT`. No material source
slice, table row, build, binary, host/facility execution, platform receipt,
profile receipt, independent review, atomic evidence, or mutation-power
evidence is asserted. The overall disposition therefore remains
`REPAIR_UNMATERIALIZED_NATIVE_PROVENANCE_AND_EVIDENCE`. This contract is stable
only as a non-lineage draft suitable for fresh dual review; it is not a PASS or
an authorization to execute or publish anything.

The platform ceiling is unchanged but now derived: only a future Linux profile
that satisfies the exact reviewed durability derivation may describe power-
loss capability, always with every authority/enabling bit false. Windows is
process-crash-only and power-loss false. macOS is unavailable. Every R3.7
evidence-authoritative, production-execution, spawn, publication, cutover,
accepting-authority, and durability-authority value remains false.

The late-bound 15-edge admission bridge remains explicitly deferred. It is not
implemented, materialized, evaluated, or represented by the R3.7 evidence DAG.
No launcher runtime or fixture was executed; no external evidence was authored;
and no publication, final freeze, commit, push, or install is authorized by
this R3.7 repair.
