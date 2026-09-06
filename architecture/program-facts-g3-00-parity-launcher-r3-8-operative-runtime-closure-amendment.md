# Program Facts G3-00 parity launcher R3.8 operative runtime-closure amendment

Status: `CONTRACT_ONLY_NON_LINEAGE_STABLE_DRAFT_PENDING_LATE_BOUND_CROSSCHECK_BRIDGE_R3_8`

Disposition: `REPAIR_UNMATERIALIZED_NATIVE_PROVENANCE_AND_EVIDENCE`

Admission: `BLOCKED_PENDING_SEPARATELY_ACCEPTED_CROSSCHECK_V3_LINEAGE_BRIDGE`

This is a new-only successor to the frozen R3.7 contract. It modifies no prior
subject or review artifact. Where this document conflicts with the R3.7
predecessor, this document controls; every nonconflicting R3.7 rule remains in
force. The deferred 15-edge admission bridge is not part of this amendment.

## 1. Exact immutable inputs and boundary

| input | bytes | LF | CR | SHA-256 | disposition |
|---|---:|---:|---:|---|---|
| `architecture/program-facts-g3-00-parity-launcher-runtime-closure-amendment.md` | 934,000 | 14,119 | 0 | `95b1b0f17d5ea180884b401566dc0190f5cb19954e1b65c62d0ce2cfa8f2ab86` | R3.7 stable draft |
| `PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_7_STATE_OPERATIONAL_REVIEW_95b1b0f17d5e.md` | 15,949 | 128 | 0 | `fe7c8bf8e7d473a979895f43b24d0af077ff83fdb9599d43b5706c004b6d7be4` | REPAIR |
| `PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_7_NATIVE_CONTRACT_REVIEW_95b1b0f17d5ea180.md` | 21,964 | 201 | 0 | `4a4ef57b8701b0a9cdd2d97035e4a2d404b523ae0dcf276282e03ae4e6da3533` | REPAIR |

The complete two reviews are design inputs, not PASS lineage. This document
does not assert a material source, build, host, platform, receipt, review, or
mutation-evidence artifact. It grants no execution, fixture-authorship, spawn,
publication, installation, cutover, commit, push, or admission authority.

R3.8 preserves the verified 22-call roster, exact declaration text, frame
codes, two-pass pointee evaluation, nested output model, `poll.nfds=671085`
ceiling, 45 API/profile rows, 16 cells, 720 outcomes, 360 eight-seam rows,
352/352/16 outcome slices, 176/176/8 seam slices, and 2,227 atomic axes.

## 2. Closed non-self operation bodies and identities

R3.8 separates already-constructible evidence bodies from projections and
outcome hashes. No projection contains its enclosing future outcome hash.

```text
vector_linux_outer_evidence_body_r3_8 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),api:S1,
  request_frame:R(vector_exact_native_bytes),result_frame:Q(R(vector_exact_native_bytes)),
  observation_artifacts:A(R(file_identity),1,64,true),
  observation_row_stream:R(content_identity),body_sha256:HEX)

vector_windows_return_result_r3_8 =
O(bool_return:E(0,1),error_valid:B,
  last_error_captured_immediately:I(0,4294967295),result_sha256:HEX)

vector_windows_outer_evidence_body_r3_8 =
O(request:R(vector_windows_rename_request_r3_6),
  result:Q(R(vector_windows_return_result_r3_8)),
  retained_source_handle_file_id_after:R(windows_file_identity),
  source_name:R(vector_windows_name_presence_observation_r3_6),
  destination_name:R(vector_windows_name_presence_observation_r3_6),
  destination_reopen:R(vector_windows_reopen_observation_r3_6),
  destination_parent_file_id_after:R(windows_file_identity),body_sha256:HEX)

vector_linux_observation_projection_r3_8 =
O(outer_evidence_body_sha256:HEX,selector:S1,
  mappings:A(R(vector_native_observation_field_mapping_r3_7),1,32,true),
  actual_projection:R(vector_native_typed_projection_r3_7),
  projection_function:C("LINUX_OUTER_EVIDENCE_TO_PROJECTION_V2"),
  projection_sha256:HEX)

vector_windows_observation_projection_r3_8 =
O(outer_evidence_body_sha256:HEX,
  selector:C("WINDOWS_SOURCE_ABSENT_DESTINATION_FILE_ID_CONTINUITY"),
  mappings:A(R(vector_native_observation_field_mapping_r3_7),8,8,true),
  actual_projection:R(vector_native_typed_projection_r3_7),
  projection_function:C("WINDOWS_OUTER_EVIDENCE_TO_PROJECTION_V2"),
  projection_sha256:HEX)

vector_linux_returned_body_r3_8 =
O(completion_kind:C("RETURNED"),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  call:R(vector_native_call_r3_6),
  declaration_join:R(vector_native_call_declaration_join_r3_7),
  outer_evidence:R(vector_linux_outer_evidence_body_r3_8),
  projection:R(vector_linux_observation_projection_r3_8),
  predicate:R(vector_native_postcondition_predicate_r3_7),
  evaluation:R(vector_native_postcondition_evaluation_r3_7),
  return_status:E("SUCCESS","FAILURE","INTERRUPTED"),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  cell_ordinal:I(0,11),classification:E("API_SEMANTIC_SUCCESS",
    "API_FAILURE_NO_RETRY","RESUME_FROM_EFFECT_NO_REPLAY",
    "RECONCILE_NO_REPLAY","QUARANTINE"),retry_allowed:C(false),
  outcome_sha256:HEX)

vector_linux_no_return_body_r3_8 =
O(completion_kind:C("NO_RETURN"),reason:E("PROCESS_CRASH",
    "SPAWN_UNCERTAIN_CLONE_UNOBSERVABLE_AFTER_CRASH"),api:S1,
  profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE"),
  request_frame:R(vector_exact_native_bytes),result_frame:C(null),
  declaration_join:R(vector_native_call_declaration_join_r3_7),
  crash_seam_ordinal:I(0,7),crash_seam:S1,
  outer_evidence:R(vector_linux_outer_evidence_body_r3_8),
  projection:R(vector_linux_observation_projection_r3_8),
  predicate:R(vector_native_postcondition_predicate_r3_7),
  evaluation:R(vector_native_postcondition_evaluation_r3_7),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  cell_ordinal:I(12,15),classification:E("RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),reconciliation_sha256:HEX)

vector_windows_returned_body_r3_8 =
O(completion_kind:C("RETURNED"),
  outer_evidence:R(vector_windows_outer_evidence_body_r3_8),
  projection:R(vector_windows_observation_projection_r3_8),
  predicate:R(vector_native_postcondition_predicate_r3_7),
  evaluation:R(vector_native_postcondition_evaluation_r3_7),
  return_status:E("SUCCESS","FAILURE","INTERRUPTED"),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  cell_ordinal:I(0,11),classification:E("API_SEMANTIC_SUCCESS",
    "API_FAILURE_NO_RETRY","RESUME_FROM_EFFECT_NO_REPLAY",
    "RECONCILE_NO_REPLAY","QUARANTINE"),retry_allowed:C(false),
  outcome_sha256:HEX)

vector_windows_no_return_body_r3_8 =
O(completion_kind:C("NO_RETURN"),reason:C("PROCESS_CRASH"),
  outer_evidence:R(vector_windows_outer_evidence_body_r3_8),
  crash_seam_ordinal:I(0,7),crash_seam:S1,
  projection:R(vector_windows_observation_projection_r3_8),
  predicate:R(vector_native_postcondition_predicate_r3_7),
  evaluation:R(vector_native_postcondition_evaluation_r3_7),
  observed_poststate:E("EXPECTED_EFFECT","NO_EFFECT","WRONG_EFFECT","UNOBSERVABLE"),
  cell_ordinal:I(12,15),classification:E("RECONCILE_NO_REPLAY","QUARANTINE"),
  retry_allowed:C(false),reconciliation_sha256:HEX)

vector_native_operation_identity_r3_8 =
U(O(platform:C("LINUX"),completion_kind:C("RETURNED"),api:S1,profile:S1,
    request_sha256:HEX,result_sha256:HEX,outcome_sha256:HEX,
    operation_sha256:HEX,operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$")),
  O(platform:C("LINUX"),completion_kind:C("NO_RETURN"),api:S1,profile:S1,
    request_sha256:HEX,result_sha256:C(null),outcome_sha256:HEX,
    operation_sha256:HEX,operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$")),
  O(platform:C("WINDOWS"),completion_kind:C("RETURNED"),
    api:C("SetFileInformationByHandle.FileRenameInfoEx"),profile:S1,
    request_sha256:HEX,result_sha256:HEX,outcome_sha256:HEX,
    operation_sha256:HEX,operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$")),
  O(platform:C("WINDOWS"),completion_kind:C("NO_RETURN"),
    api:C("SetFileInformationByHandle.FileRenameInfoEx"),profile:S1,
    request_sha256:HEX,result_sha256:C(null),outcome_sha256:HEX,
    operation_sha256:HEX,operation_id:S(40,40,"^pfg3vop-[0-9a-f]{32}$")))

vector_linux_returned_outcome_r3_8 =
O(body:R(vector_linux_returned_body_r3_8),
  operation:R(vector_native_operation_identity_r3_8))

vector_linux_no_return_outcome_r3_8 =
O(body:R(vector_linux_no_return_body_r3_8),
  operation:R(vector_native_operation_identity_r3_8))

vector_windows_returned_outcome_r3_8 =
O(body:R(vector_windows_returned_body_r3_8),
  operation:R(vector_native_operation_identity_r3_8))

vector_windows_no_return_outcome_r3_8 =
O(body:R(vector_windows_no_return_body_r3_8),
  operation:R(vector_native_operation_identity_r3_8))

vector_operation_outcome_r3_8 =
U(R(vector_linux_returned_outcome_r3_8),R(vector_linux_no_return_outcome_r3_8),
  R(vector_windows_returned_outcome_r3_8),R(vector_windows_no_return_outcome_r3_8))
```

The outer evidence body hashes use domains
`PROGRAM_FACTS_G3_LINUX_OUTER_EVIDENCE_BODY_V1` and
`PROGRAM_FACTS_G3_WINDOWS_OUTER_EVIDENCE_BODY_V1` and exclude only their own
hash. The Windows result hash is exactly
`SHA-256(CJ({domain:"PROGRAM_FACTS_G3_WINDOWS_RETURN_RESULT_V1",bool_return,
error_valid,last_error_captured_immediately}))`. Returned Windows outer
evidence requires a result; no-return evidence requires result null.

Projection hashes use the already-constructible outer-evidence body hash, never
the enclosing outcome hash. Their mappings resolve actual typed members of that
body exactly once. The four body hashes use distinct domains
`PROGRAM_FACTS_G3_OUTCOME_LINUX_RETURNED_V1`,
`PROGRAM_FACTS_G3_OUTCOME_LINUX_NO_RETURN_V1`,
`PROGRAM_FACTS_G3_OUTCOME_WINDOWS_RETURNED_V1`, and
`PROGRAM_FACTS_G3_OUTCOME_WINDOWS_NO_RETURN_V1` and include every preceding
body member. The four operation domains replace `OUTCOME` with `OPERATION`.
Request and result hashes are exact parsed projections: Linux uses the call
request/result frames; Windows uses request.request_sha256 and the typed result
hash; no-return result is null. `operation_id = "pfg3vop-" ||
operation_sha256[0:32]`. Body and operation values must agree field for field.

## 3. Operative parsed roots and derived occurrence receipts

```text
vector_confirmed_post_operation_body_r3_8 =
O(branch:C("CONFIRMED"),capture_operation_id:S1,
  operations:A(R(vector_operation_outcome_r3_8),1,4096,true),
  terminal_state:C("CONFIRMED"),body_sha256:HEX)

vector_no_spawn_post_operation_body_r3_8 =
O(branch:C("NO_SPAWN"),capture_operation_id:S1,
  operations:A(R(vector_operation_outcome_r3_8),0,4096,true),
  terminal_state:C("NO_SPAWN"),body_sha256:HEX)

vector_uncertain_post_operation_body_r3_8 =
O(branch:C("SPAWN_UNCERTAIN"),capture_operation_id:S1,
  pre_clone_operations:A(R(vector_operation_outcome_r3_8),0,4095,true),
  clone_outcome:R(vector_linux_no_return_outcome_r3_8),
  terminal_state:C("SPAWN_MAY_HAVE_OCCURRED"),body_sha256:HEX)

vector_post_operation_semantic_body_r3_8 =
U(R(vector_confirmed_post_operation_body_r3_8),
  R(vector_no_spawn_post_operation_body_r3_8),
  R(vector_uncertain_post_operation_body_r3_8))

vector_operation_occurrence_r3_8 =
O(occurrence_ordinal:I(0,4095),operation_json_pointer:S1,
  operation:R(vector_native_operation_identity_r3_8),outcome_sha256:HEX,
  occurrence_sha256:HEX)

vector_operation_execution_join_r3_8 =
O(occurrence_ordinal:I(0,4095),operation_json_pointer:S1,
  operation:R(vector_native_operation_identity_r3_8),
  api_profile_ordinal:I(0,44),matrix_ordinal:I(0,719),
  seam_matrix_ordinal:Q(I(0,359)),conformance_result_sha256:HEX,
  evidence_locator:R(vector_native_evidence_locator_r3_7),
  process_invocation_sha256:HEX,build_manifest_sha256:HEX,
  executed_production_binary:R(file_identity),platform_sha256:HEX,join_sha256:HEX)

vector_per_operation_execution_receipt_body_r3_8 =
O(post_operation_body_sha256:HEX,
  occurrences:A(R(vector_operation_occurrence_r3_8),0,4096,true),
  occurrence_count:I(0,4096),occurrence_row_stream:R(content_identity),
  execution_joins:A(R(vector_operation_execution_join_r3_8),0,4096,true),
  execution_join_count:I(0,4096),execution_join_row_stream:R(content_identity),
  body_sha256:HEX)

vector_per_profile_execution_receipt_index_r3_8 =
O(index_ordinal:I(0,4095),post_operation_id:S1,
  post_operation_body_sha256:HEX,receipt_body_sha256:HEX,index_sha256:HEX)

vector_per_profile_execution_receipt_bundle_r3_8 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  receipt_bodies:A(R(vector_per_operation_execution_receipt_body_r3_8),1,4096,true),
  receipt_index:A(R(vector_per_profile_execution_receipt_index_r3_8),1,4096,true),
  receipt_count:I(1,4096),receipt_row_stream:R(content_identity),
  index_row_stream:R(content_identity),bundle_sha256:HEX)

vector_post_operation_envelope_r3_8 =
O(schema_root:C("vector_post_operation_envelope_r3_8"),
  semantic_body:R(vector_post_operation_semantic_body_r3_8),
  semantic_body_canonical_bytes:R(content_identity),
  artifact_parses_exact_body:C(true),post_operation_body_sha256:HEX,
  operation_receipt:R(vector_per_operation_execution_receipt_body_r3_8),
  aggregate_execution_receipt:R(vector_native_execution_receipt_r3_8),
  native_execution_authority:R(vector_native_ffi_authority_r3_8),
  post_operation_sha256:HEX,
  post_operation_id:S(40,40,"^pfg3po8-[0-9a-f]{32}$"))

vector_quarantine_process_basis_r3_8 =
O(root_kind:C("QUARANTINE_PROCESS_BASIS"),
  post_operation:R(vector_post_operation_envelope_r3_8),
  process_basis_sha256:HEX)

vector_spawn_uncertainty_observation_r3_8 =
O(root_kind:C("SPAWN_UNCERTAINTY_OBSERVATION"),
  uncertain_post_operation:R(vector_post_operation_envelope_r3_8),
  clone_outcome:R(vector_linux_no_return_outcome_r3_8),
  equality_to_semantic_body_clone:C(true),observation_sha256:HEX)

vector_effective_root_r3_8 =
U(O(root_kind:C("CONFIRMED"),post_operation:R(vector_post_operation_envelope_r3_8)),
  O(root_kind:C("NO_SPAWN"),post_operation:R(vector_post_operation_envelope_r3_8)),
  O(root_kind:C("SPAWN_UNCERTAIN"),post_operation:R(vector_post_operation_envelope_r3_8)),
  R(vector_quarantine_process_basis_r3_8),
  R(vector_spawn_uncertainty_observation_r3_8))
```

These definitions replace in full the retained confirmed, no-spawn, uncertain,
quarantine-process-basis, and spawn-uncertainty definitions for every R3.8
consumer. No R3.8 root contains `R(file_identity)` as a walker payload. A root
artifact's bytes equal `CF(semantic_body)`, parse exactly the carried body, and
select the displayed schema root.

Semantic body hashes use the branch domains
`PROGRAM_FACTS_G3_POST_OPERATION_BODY_CONFIRMED_V1`,
`PROGRAM_FACTS_G3_POST_OPERATION_BODY_NO_SPAWN_V1`, and
`PROGRAM_FACTS_G3_POST_OPERATION_BODY_SPAWN_UNCERTAIN_V1`. The envelope's
`post_operation_body_sha256` equals that derived body hash.

The canonical walker visits only outcome-bearing members of the parsed
semantic body in canonical member/index order: `/operations/i`,
`/pre_clone_operations/i`, then `/clone_outcome`. It derives, rather than
trusts, occurrence pointer, ordinal, operation, and outcome hash. The uncertain
clone is exactly one Linux `clone3` no-return outcome with reason
`SPAWN_UNCERTAIN_CLONE_UNOBSERVABLE_AFTER_CRASH`; the operative spawn
uncertainty observation carries the same parsed value.

Occurrences and execution joins are exact bijections by ordinal, pointer,
operation, and outcome hash. Every pointer resolves exactly once in the parsed
body. The per-profile bundle index is a bijection to all admitted receipt
bodies; its one PASS bundle review therefore covers `1..4096` bodies without a
review-subject cardinality mismatch.

`post_operation_sha256` hashes domain
`PROGRAM_FACTS_G3_POST_OPERATION_ENVELOPE_V1`, schema root, semantic body and
bytes, body hash, operation receipt, aggregate receipt, and authority. The ID
is `"pfg3po8-" || post_operation_sha256[0:32]`. In every branch, the separately
carried aggregate receipt is parsed-value equal to
`native_execution_authority.execution_receipt`; mismatch rejects before hash.

## 4. Closed symbol compatibility

<!-- BEGIN VECTOR_SYMBOL_KIND_SCHEMA_ROSTER_R3_8 -->
```json
[
{"projection_schema_id":"LINUX_FILE_ID","row_ordinal":0,"symbol_kind":"FILE_ID"},
{"projection_schema_id":"FD_ID","row_ordinal":1,"symbol_kind":"FD"},
{"projection_schema_id":"MOUNT_ID","row_ordinal":2,"symbol_kind":"MOUNT_ID"},
{"projection_schema_id":"PID_ID","row_ordinal":3,"symbol_kind":"PID"},
{"projection_schema_id":"PIDFD_ID","row_ordinal":4,"symbol_kind":"PIDFD"},
{"projection_schema_id":"PROCESS_ID","row_ordinal":5,"symbol_kind":"PROCESS_ID"}
]
```
<!-- END VECTOR_SYMBOL_KIND_SCHEMA_ROSTER_R3_8 -->

```text
vector_symbol_compatibility_row_r3_8 =
O(row_ordinal:I(0,5),symbol_kind:E("FILE_ID","FD","MOUNT_ID","PID","PIDFD",
    "PROCESS_ID"),projection_schema_id:E("LINUX_FILE_ID","FD_ID","MOUNT_ID",
    "PID_ID","PIDFD_ID","PROCESS_ID"),row_sha256:HEX)

vector_fresh_symbol_declaration_r3_8 =
O(symbol_ordinal:I(0,31),name:S1,
  compatibility:R(vector_symbol_compatibility_row_r3_8),
  freshness_universe:R(vector_native_freshness_universe_locator_r3_7),
  declaration_sha256:HEX)

vector_fresh_symbol_binding_r3_8 =
O(symbol_ordinal:I(0,31),declared_symbol_sha256:HEX,
  compatibility_row_sha256:HEX,actual_field_ordinal:I(0,31),
  actual_field_sha256:HEX,actual_value_schema:S1,binding_sha256:HEX)
```

Each compatibility row hash uses domain
`PROGRAM_FACTS_G3_SYMBOL_KIND_SCHEMA_COMPATIBILITY_V1`. Declaration and binding
hashes use distinct `PROGRAM_FACTS_G3_FRESH_SYMBOL_DECLARATION_V3` and
`PROGRAM_FACTS_G3_FRESH_SYMBOL_BINDING_V2` domains. The binding's declaration
hash resolves exactly one declaration; its compatibility hash equals that
declaration's row; and actual schema equals the row's one schema. Cross-kind,
schema, compatibility-row, or declaration substitution rejects.

## 5. Process-bound platform derivation

```text
vector_process_invocation_identity_r3_8 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  capture_operation_id:S1,invocation_nonce:S(32,32,"^[0-9a-f]{32}$"),
  boot_session_identity:S1,process_id_u64:I(1,9007199254740991),
  process_start_ticks_u64:I(1,9007199254740991),
  target_process_handle_u64:Q(S(16,16,"^[0-9a-f]{16}$")),
  executable:R(file_identity),argv_sha256:HEX,environment_sha256:HEX,
  supervisor_process_id_u64:I(1,9007199254740991),invocation_sha256:HEX)

vector_loaded_module_observation_r3_8 =
O(invocation_sha256:HEX,process_id_u64:I(1,9007199254740991),
  process_start_ticks_u64:I(1,9007199254740991),
  target_process_handle_u64:Q(S(16,16,"^[0-9a-f]{16}$")),
  observation_epoch_u64:I(1,9007199254740991),observed_while_process_alive:C(true),
  method:E("LINUX_PROC_PID_MAP_FILES","WINDOWS_PEB_LDR_DATA_AND_FILE_ID"),
  raw_observation:R(content_identity),modules:A(R(vector_native_loaded_module_row_r3_7),2,3,true),
  module_row_stream:R(content_identity),observation_sha256:HEX)

vector_loaded_runtime_receipt_r3_8 =
O(invocation:R(vector_process_invocation_identity_r3_8),
  observation:R(vector_loaded_module_observation_r3_8),
  executed_production_binary:R(file_identity),receipt_sha256:HEX)

vector_registered_platform_policy_slice_r3_8 =
O(slice_kind:C("WINDOWS_CAPABILITY_POLICY"),policy_id:S1,
  registered_path:S1,registered_file_sha256:HEX,row_ordinal:I(0,4294967295),
  byte_offset:I(0,9007199254740991),byte_length:I(1,1048576),
  raw_slice_hex:S(2,2097152,"^[0-9a-f]+$"),raw_slice_sha256:HEX,
  normalized_tokens:S1,registered_row_sha256:HEX)

vector_windows_api_capability_policy_r3_8 =
O(api:C("SetFileInformationByHandle.FileRenameInfoEx"),
  information_class:C("FileRenameInfoEx"),information_class_u32:C(22),
  minimum:R(vector_windows_build_tuple_r3_7),comparison_policy:
    C("LEXICOGRAPHIC_MAJOR_MINOR_BUILD_REVISION"),
  registered_policy_slice:R(vector_registered_platform_policy_slice_r3_8),
  sdk_manifest:R(file_identity),policy_sha256:HEX)

vector_windows_build_observation_r3_8 =
O(invocation_sha256:HEX,source:C("RtlGetVersion"),
  source_loaded_module_sha256:HEX,raw_structure:R(vector_exact_native_bytes),
  observed:R(vector_windows_build_tuple_r3_7),
  capability_policy:R(vector_windows_api_capability_policy_r3_8),
  observed_at_least_pinned_minimum:C(true),observation_sha256:HEX)

vector_linux_mount_observation_r3_8 =
O(invocation_sha256:HEX,operation_epoch_u64:I(1,9007199254740991),
  raw_mountinfo_row:R(vector_exact_native_bytes),mount_id_u64:I(1,9007199254740991),
  parent_mount_id_u64:I(0,9007199254740991),device_major_u32:I(0,4294967295),
  device_minor_u32:I(0,4294967295),filesystem_uuid:S1,
  filesystem_type:E("ext4","xfs","btrfs"),
  mount_options:A(E("rw","ro","dirsync","sync","barrier","nobarrier",
    "data=ordered","data=journal","data=writeback"),1,9,true),
  retained_handles_same_mount:B,observation_sha256:HEX)

vector_linux_storage_topology_r3_8 =
U(O(kind:C("DIRECT_BLOCK_DEVICE"),device_major_u32:I(0,4294967295),
    device_minor_u32:I(0,4294967295),write_cache:E("DISABLED","POWER_SAFE"),
    topology_source:R(content_identity),topology_sha256:HEX),
  O(kind:C("REVIEWED_POWER_SAFE_STACK"),device_major_u32:I(0,4294967295),
    device_minor_u32:I(0,4294967295),ordered_layers:A(S1,1,16,true),
    power_safe_guarantee_source:R(content_identity),topology_sha256:HEX))

vector_linux_durability_event_r3_8 =
O(event_ordinal:I(0,31),invocation_sha256:HEX,
  operation_epoch_u64:I(1,9007199254740991),mount_id_u64:I(1,9007199254740991),
  device_major_u32:I(0,4294967295),device_minor_u32:I(0,4294967295),
  event_kind:E("FILE_FSYNC_COMPLETED","DIRECTORY_FSYNC_COMPLETED",
    "BLOCK_BARRIER_COMPLETED","JOURNAL_COMMIT_OBSERVED"),
  target_identity_sha256:HEX,source_event:R(content_identity),event_sha256:HEX)

vector_linux_durability_observation_r3_8 =
O(invocation:R(vector_process_invocation_identity_r3_8),
  mount:R(vector_linux_mount_observation_r3_8),
  storage:R(vector_linux_storage_topology_r3_8),
  events:A(R(vector_linux_durability_event_r3_8),4,32,true),
  required_event_kinds_present:C(true),derived_capability:E(
    "FUTURE_LINUX_POWER_LOSS","PROCESS_CRASH_ONLY","UNAVAILABLE"),
  power_loss_capability:B,observation_sha256:HEX)

vector_linux_durability_profile_r3_8 =
O(profile_id:S1,filesystem_type:E("ext4","xfs","btrfs"),
  required_mount_options:A(S1,1,9,true),forbidden_mount_options:A(S1,0,9,true),
  permitted_storage_kinds:A(E("DIRECT_BLOCK_DEVICE",
    "REVIEWED_POWER_SAFE_STACK"),1,2,true),
  required_event_kinds:C(["FILE_FSYNC_COMPLETED","DIRECTORY_FSYNC_COMPLETED",
    "BLOCK_BARRIER_COMPLETED","JOURNAL_COMMIT_OBSERVED"]),
  registered_profile_slice:R(vector_native_registered_source_slice_r3_7),
  profile_sha256:HEX)

vector_native_linux_platform_identity_r3_8 =
O(platform:C("LINUX"),profile:E("LINUX_X86_64_LP64_LE",
    "LINUX_AARCH64_LP64_LE"),architecture:E("x86_64","aarch64"),
  kernel_image:R(file_identity),build_manifest_sha256:HEX,
  loaded_runtime:R(vector_loaded_runtime_receipt_r3_8),
  loaded_runtime_review:R(vector_review_artifact_binding_r3_8),
  durability_profile:R(vector_linux_durability_profile_r3_8),
  durability_profile_review:R(vector_review_artifact_binding_r3_8),
  durability_observation:R(vector_linux_durability_observation_r3_8),
  durability_observation_review:R(vector_review_artifact_binding_r3_8),
  power_loss_capability:B,process_crash_capability:C(true),
  accepting_authority:C(false),platform_sha256:HEX)

vector_native_windows_platform_identity_r3_8 =
O(platform:C("WINDOWS"),
  profile:C("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  architecture:C("x86_64"),build_manifest_sha256:HEX,
  loaded_runtime:R(vector_loaded_runtime_receipt_r3_8),
  loaded_runtime_review:R(vector_review_artifact_binding_r3_8),
  capability_policy:R(vector_windows_api_capability_policy_r3_8),
  capability_policy_review:R(vector_review_artifact_binding_r3_8),
  build_observation:R(vector_windows_build_observation_r3_8),
  power_loss_capability:C(false),process_crash_capability:C(true),
  accepting_authority:C(false),platform_sha256:HEX)

vector_native_platform_identity_r3_8 =
U(R(vector_native_linux_platform_identity_r3_8),
  R(vector_native_windows_platform_identity_r3_8))
```

Invocation hash uses domain `PROGRAM_FACTS_G3_PROCESS_INVOCATION_IDENTITY_V1`.
Loaded observation must repeat the exact PID, process-start ticks, target handle,
and invocation hash and occur while that process is alive. Its executable
equals the invocation and outer evidence binary. Linux module roles are exactly
loader/libc; Windows roles Kernel32/NTDLL/UCRT. Per-operation joins repeat the
same invocation hash, preventing cross-process module splices.

The Windows minimum comes only from the registered externally pinned capability
policy slice and reviewed SDK manifest; an observation has no caller-selected
minimum. The selected policy slice kind/profile/path/offset/bytes resolves
exactly once in the build manifest. Observed tuple comparison uses that exact
policy tuple.

Linux power-loss capability is true iff the parsed mount row matches the closed
profile, no forbidden option occurs, storage topology matches the same device,
retained handles are same-mount, and at least one independently observed event
of each required kind has matching invocation, epoch, mount, and device. The
capability is descriptive and never enables authority. Missing or mismatched
operands derive process-crash-only or unavailable. Windows remains process-
crash-only with power-loss false; macOS has no branch.

## 6. PASS-only review roles, bundle cardinality, and complete DAG

```text
vector_review_body_r3_8 =
O(review_role:E("INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW",
    "LAYOUT_ORACLE_REVIEW","IMPLEMENTATION_REVIEW",
    "SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW",
    "SEMANTIC_SCHEMA_REGISTRY_REVIEW","LOADED_RUNTIME_REVIEW",
    "WINDOWS_CAPABILITY_POLICY_REVIEW","LINUX_DURABILITY_PROFILE_REVIEW",
    "LINUX_DURABILITY_OBSERVATION_REVIEW","PER_PROFILE_EXECUTION_BUNDLE_REVIEW",
    "PROFILE_RECEIPT_REVIEW","NATIVE_AUTHORITY_REVIEW"),
  reviewer_principal:S1,subject_identities:A(R(file_identity),1,256,true),
  predecessor_identities:A(R(file_identity),0,256,true),
  subject_author_principals:A(S1,1,256,false),
  reviewer_distinct_from_subject_authors:C(true),self_review:C(false),
  future_subject_count:C(0),disposition:C("PASS_NONAUTHORITATIVE"),
  review_body_sha256:HEX)

vector_review_artifact_binding_r3_8 =
O(artifact:R(file_identity),body:R(vector_review_body_r3_8),
  canonical_body_bytes:R(content_identity),artifact_parses_exact_body:C(true),
  binding_sha256:HEX)

vector_reviewed_execution_bundle_r3_8 =
O(bundle_artifact:R(file_identity),
  bundle:R(vector_per_profile_execution_receipt_bundle_r3_8),
  canonical_bundle_bytes:R(content_identity),artifact_parses_exact_bundle:C(true),
  review:R(vector_review_artifact_binding_r3_8),reviewed_bundle_sha256:HEX)

vector_reviewed_profile_receipt_r3_8 =
O(body_artifact:R(file_identity),body:R(vector_native_profile_receipt_body_r3_8),
  canonical_body_bytes:R(content_identity),artifact_parses_exact_body:C(true),
  review:R(vector_review_artifact_binding_r3_8),reviewed_receipt_sha256:HEX)

vector_evidence_dag_node_r3_8 =
O(node_ordinal:I(0,31),node_kind:S1,artifact_type:S1,
  artifact:R(file_identity),author_principal:S1,
  subject_identities:A(R(file_identity),0,256,true),
  predecessor_identities:A(R(file_identity),0,256,true),node_sha256:HEX)

vector_evidence_dag_r3_8 =
O(nodes:A(R(vector_evidence_dag_node_r3_8),27,27,true),
  edges:A(T(S1,S1),42,42,true),node_count:C(27),edge_count:C(42),
  dag_sha256:HEX)
```

<!-- BEGIN VECTOR_EVIDENCE_DAG_NODE_ROSTER_R3_8 -->
```json
[
{"artifact_type":"SOURCE_INPUT_SET","node_kind":"SOURCE_INPUTS","node_ordinal":0,"predecessors":[]},
{"artifact_type":"REVIEW_R3_8","node_kind":"INPUT_PROVENANCE_REVIEW","node_ordinal":1,"predecessors":["SOURCE_INPUTS"]},
{"artifact_type":"BUILD_PLAN","node_kind":"BUILD_PLAN","node_ordinal":2,"predecessors":["INPUT_PROVENANCE_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"BUILD_PLAN_REVIEW","node_ordinal":3,"predecessors":["BUILD_PLAN"]},
{"artifact_type":"BUILD_RECEIPT","node_kind":"BUILD_RECEIPT","node_ordinal":4,"predecessors":["INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"LAYOUT_ORACLE_REVIEW","node_ordinal":5,"predecessors":["BUILD_RECEIPT"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"IMPLEMENTATION_REVIEW","node_ordinal":6,"predecessors":["BUILD_RECEIPT","LAYOUT_ORACLE_REVIEW"]},
{"artifact_type":"SEMANTIC_SCHEMA_REGISTRY","node_kind":"SEMANTIC_SCHEMA_REGISTRY","node_ordinal":7,"predecessors":["IMPLEMENTATION_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"SEMANTIC_SCHEMA_REGISTRY_REVIEW","node_ordinal":8,"predecessors":["SEMANTIC_SCHEMA_REGISTRY"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"SEMANTIC_DERIVATION_REVIEW","node_ordinal":9,"predecessors":["IMPLEMENTATION_REVIEW","SEMANTIC_SCHEMA_REGISTRY_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"FACILITY_REVIEW","node_ordinal":10,"predecessors":["IMPLEMENTATION_REVIEW"]},
{"artifact_type":"WINDOWS_CAPABILITY_POLICY","node_kind":"WINDOWS_CAPABILITY_POLICY","node_ordinal":11,"predecessors":["INPUT_PROVENANCE_REVIEW","BUILD_RECEIPT"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"WINDOWS_CAPABILITY_POLICY_REVIEW","node_ordinal":12,"predecessors":["WINDOWS_CAPABILITY_POLICY"]},
{"artifact_type":"LINUX_DURABILITY_PROFILE","node_kind":"LINUX_DURABILITY_PROFILE","node_ordinal":13,"predecessors":["INPUT_PROVENANCE_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"LINUX_DURABILITY_PROFILE_REVIEW","node_ordinal":14,"predecessors":["LINUX_DURABILITY_PROFILE"]},
{"artifact_type":"RAW_HOST_EXECUTION_EVIDENCE","node_kind":"RAW_HOST_EXECUTION_EVIDENCE","node_ordinal":15,"predecessors":["BUILD_RECEIPT","SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW","WINDOWS_CAPABILITY_POLICY_REVIEW","LINUX_DURABILITY_PROFILE_REVIEW"]},
{"artifact_type":"LOADED_RUNTIME_RECEIPT","node_kind":"LOADED_RUNTIME_RECEIPT","node_ordinal":16,"predecessors":["RAW_HOST_EXECUTION_EVIDENCE"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"LOADED_RUNTIME_REVIEW","node_ordinal":17,"predecessors":["LOADED_RUNTIME_RECEIPT"]},
{"artifact_type":"LINUX_DURABILITY_OBSERVATION","node_kind":"LINUX_DURABILITY_OBSERVATION","node_ordinal":18,"predecessors":["RAW_HOST_EXECUTION_EVIDENCE","LINUX_DURABILITY_PROFILE_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"LINUX_DURABILITY_OBSERVATION_REVIEW","node_ordinal":19,"predecessors":["LINUX_DURABILITY_OBSERVATION","LOADED_RUNTIME_REVIEW"]},
{"artifact_type":"PER_PROFILE_EXECUTION_RECEIPT_BUNDLE","node_kind":"PER_PROFILE_EXECUTION_RECEIPT_BUNDLE","node_ordinal":20,"predecessors":["RAW_HOST_EXECUTION_EVIDENCE","LOADED_RUNTIME_REVIEW","LINUX_DURABILITY_OBSERVATION_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"PER_PROFILE_EXECUTION_BUNDLE_REVIEW","node_ordinal":21,"predecessors":["PER_PROFILE_EXECUTION_RECEIPT_BUNDLE"]},
{"artifact_type":"PROFILE_RECEIPT_BODY","node_kind":"PROFILE_RECEIPT_BODY","node_ordinal":22,"predecessors":["PER_PROFILE_EXECUTION_BUNDLE_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"PROFILE_RECEIPT_REVIEW","node_ordinal":23,"predecessors":["PROFILE_RECEIPT_BODY","PER_PROFILE_EXECUTION_BUNDLE_REVIEW"]},
{"artifact_type":"REVIEWED_PROFILE_RECEIPT","node_kind":"REVIEWED_PROFILE_RECEIPT","node_ordinal":24,"predecessors":["PROFILE_RECEIPT_REVIEW"]},
{"artifact_type":"REVIEW_R3_8","node_kind":"NATIVE_AUTHORITY_REVIEW","node_ordinal":25,"predecessors":["REVIEWED_PROFILE_RECEIPT","IMPLEMENTATION_REVIEW","SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW"]},
{"artifact_type":"NATIVE_AUTHORITY_JOIN","node_kind":"NONAUTHORITATIVE_AUTHORITY_JOIN","node_ordinal":26,"predecessors":["NATIVE_AUTHORITY_REVIEW"]}
]
```
<!-- END VECTOR_EVIDENCE_DAG_NODE_ROSTER_R3_8 -->

Edges are exactly the flattened predecessor arrays and always move forward.
Each review node has the exact displayed role, one already materialized direct
subject artifact, all direct predecessor identities, future count zero, and
PASS disposition. The per-profile bundle is the sole subject of its review;
its exact index already bijects every receipt body. The profile receipt body is
materialized, then reviewed, and only then wrapped as reviewed; authority is
reviewed before the nonauthoritative join. Registry, loaded runtime, Windows
capability policy, Linux durability profile, and Linux durability observation
have distinct roles and chronological nodes. Artifact bytes equal canonical
bytes and parse exactly the carried body at both wrappers.

## 7. All-false aggregate and authority

```text
vector_native_profile_receipt_body_r3_8 =
O(profile:E("LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE",
    "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"),
  execution_bundle:R(vector_reviewed_execution_bundle_r3_8),
  platform_identity:R(vector_native_platform_identity_r3_8),
  outcome_result_count:E(352,16),seam_result_count:E(176,8),
  outcome_row_stream:R(content_identity),seam_row_stream:R(content_identity),
  authoritative:C(false),production_execution_allowed:C(false),
  spawn_allowed:C(false),durability_authority:C(false),body_sha256:HEX)

vector_native_execution_receipt_r3_8 =
U(O(state:C("UNMATERIALIZED_STABLE_DRAFT"),subject:C(null),
    reviewed_profile_receipts:C(null),aggregate_receipt_sha256:C(null),
    authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),durability_authority:C(false)),
  O(state:C("MATERIALIZED_AGGREGATE_NONAUTHORITATIVE"),subject:R(file_identity),
    reviewed_profile_receipts:A(R(vector_reviewed_profile_receipt_r3_8),3,3,false),
    aggregate_outcome_index_count:C(720),aggregate_seam_index_count:C(360),
    atomic_contract_result_count:C(2227),aggregate_receipt_sha256:HEX,
    authoritative:C(false),production_execution_allowed:C(false),
    spawn_allowed:C(false),durability_authority:C(false)))

vector_native_ffi_authority_r3_8 =
U(O(state:C("UNMATERIALIZED_PROVENANCE"),subject:C(null),
    execution_receipt:R(vector_native_execution_receipt_r3_8),
    authority_join_sha256:C(null),evidence_authoritative:C(false),
    production_execution_allowed:C(false),spawn_allowed:C(false),
    publication_allowed:C(false),cutover_allowed:C(false),
    durability_authority:C(false)),
  O(state:C("MATERIALIZED_REVIEWED_NONAUTHORITATIVE"),subject:R(file_identity),
    execution_receipt:R(vector_native_execution_receipt_r3_8),
    review_dag:R(vector_evidence_dag_r3_8),
    authority_review:R(vector_review_artifact_binding_r3_8),
    authority_join_sha256:HEX,evidence_authoritative:C(false),
    production_execution_allowed:C(false),spawn_allowed:C(false),
    publication_allowed:C(false),cutover_allowed:C(false),
    durability_authority:C(false)))
```

The three profiles remain ordered x86-64 Linux, AArch64 Linux, Windows. Linux
counts are 352/176 each; Windows 16/8. Complete aggregate indices still contain
720/360 rows and the atomic bundle still contains 2,227 results. Every review
is PASS-only but nonauthoritative. Every evidence-authoritative, production-
execution, spawn, publication, cutover, accepting-authority, and durability-
authority value remains false.

## 8. Canonical materialization validator and accepted baseline

The exact validator below is the R3.8 materialized-receipt validator. It accepts
only canonical UTF-8 CJ bytes and returns a diagnostic derived from schema and
semantic checks. Its API receives only subject bytes; no expected-diagnostic
roster, mutation ordinal, or expected result is an argument or global.

<!-- BEGIN R3_8_MATERIALIZATION_VALIDATOR_SOURCE -->
```python
import hashlib
import json

class Rejection(Exception):
    def __init__(self, primary, subcode):
        self.primary = primary
        self.subcode = subcode

def cj(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)

def sha(value):
    data = value if isinstance(value, bytes) else cj(value).encode()
    return hashlib.sha256(data).hexdigest()

def dh(domain, value):
    return sha({"domain":domain, "value":value})

def fid(label):
    return {"path":"/pinned/" + label,"size_bytes":len(label),
            "sha256":sha(label.encode())}

def content(value):
    data = value if isinstance(value, bytes) else cj(value).encode()
    return {"size_bytes":len(data),"sha256":sha(data)}

API_NAMES = ["mkdirat","openat","read","write","pread64","readlinkat",
 "fstat","statx","mount","umount2","pivot_root","prctl","seccomp",
 "landlock_get_abi","landlock_create_ruleset","landlock_add_rule",
 "landlock_restrict_self","close_range","clone3","pidfd_send_signal",
 "poll","unlinkat"]
SYMBOL_COMPATIBILITY = [("FILE_ID","LINUX_FILE_ID"),("FD","FD_ID"),
 ("MOUNT_ID","MOUNT_ID"),("PID","PID_ID"),("PIDFD","PIDFD_ID"),
 ("PROCESS_ID","PROCESS_ID")]
MODULE_ROLES = {"LINUX_X86_64_LP64_LE":["LINUX_LOADER","LINUX_LIBC"],
 "LINUX_AARCH64_LP64_LE":["LINUX_LOADER","LINUX_LIBC"],
 "WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2":
 ["WINDOWS_KERNEL32","WINDOWS_NTDLL","WINDOWS_UCRT"]}
DAG_ROWS = [
 ("SOURCE_INPUTS","SOURCE_INPUT_SET",[]),
 ("INPUT_PROVENANCE_REVIEW","REVIEW_R3_8",["SOURCE_INPUTS"]),
 ("BUILD_PLAN","BUILD_PLAN",["INPUT_PROVENANCE_REVIEW"]),
 ("BUILD_PLAN_REVIEW","REVIEW_R3_8",["BUILD_PLAN"]),
 ("BUILD_RECEIPT","BUILD_RECEIPT",["INPUT_PROVENANCE_REVIEW","BUILD_PLAN_REVIEW"]),
 ("LAYOUT_ORACLE_REVIEW","REVIEW_R3_8",["BUILD_RECEIPT"]),
 ("IMPLEMENTATION_REVIEW","REVIEW_R3_8",["BUILD_RECEIPT","LAYOUT_ORACLE_REVIEW"]),
 ("SEMANTIC_SCHEMA_REGISTRY","SEMANTIC_SCHEMA_REGISTRY",["IMPLEMENTATION_REVIEW"]),
 ("SEMANTIC_SCHEMA_REGISTRY_REVIEW","REVIEW_R3_8",["SEMANTIC_SCHEMA_REGISTRY"]),
 ("SEMANTIC_DERIVATION_REVIEW","REVIEW_R3_8",["IMPLEMENTATION_REVIEW","SEMANTIC_SCHEMA_REGISTRY_REVIEW"]),
 ("FACILITY_REVIEW","REVIEW_R3_8",["IMPLEMENTATION_REVIEW"]),
 ("WINDOWS_CAPABILITY_POLICY","WINDOWS_CAPABILITY_POLICY",["INPUT_PROVENANCE_REVIEW","BUILD_RECEIPT"]),
 ("WINDOWS_CAPABILITY_POLICY_REVIEW","REVIEW_R3_8",["WINDOWS_CAPABILITY_POLICY"]),
 ("LINUX_DURABILITY_PROFILE","LINUX_DURABILITY_PROFILE",["INPUT_PROVENANCE_REVIEW"]),
 ("LINUX_DURABILITY_PROFILE_REVIEW","REVIEW_R3_8",["LINUX_DURABILITY_PROFILE"]),
 ("RAW_HOST_EXECUTION_EVIDENCE","RAW_HOST_EXECUTION_EVIDENCE",["BUILD_RECEIPT","SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW","WINDOWS_CAPABILITY_POLICY_REVIEW","LINUX_DURABILITY_PROFILE_REVIEW"]),
 ("LOADED_RUNTIME_RECEIPT","LOADED_RUNTIME_RECEIPT",["RAW_HOST_EXECUTION_EVIDENCE"]),
 ("LOADED_RUNTIME_REVIEW","REVIEW_R3_8",["LOADED_RUNTIME_RECEIPT"]),
 ("LINUX_DURABILITY_OBSERVATION","LINUX_DURABILITY_OBSERVATION",["RAW_HOST_EXECUTION_EVIDENCE","LINUX_DURABILITY_PROFILE_REVIEW"]),
 ("LINUX_DURABILITY_OBSERVATION_REVIEW","REVIEW_R3_8",["LINUX_DURABILITY_OBSERVATION","LOADED_RUNTIME_REVIEW"]),
 ("PER_PROFILE_EXECUTION_RECEIPT_BUNDLE","PER_PROFILE_EXECUTION_RECEIPT_BUNDLE",["RAW_HOST_EXECUTION_EVIDENCE","LOADED_RUNTIME_REVIEW","LINUX_DURABILITY_OBSERVATION_REVIEW"]),
 ("PER_PROFILE_EXECUTION_BUNDLE_REVIEW","REVIEW_R3_8",["PER_PROFILE_EXECUTION_RECEIPT_BUNDLE"]),
 ("PROFILE_RECEIPT_BODY","PROFILE_RECEIPT_BODY",["PER_PROFILE_EXECUTION_BUNDLE_REVIEW"]),
 ("PROFILE_RECEIPT_REVIEW","REVIEW_R3_8",["PROFILE_RECEIPT_BODY","PER_PROFILE_EXECUTION_BUNDLE_REVIEW"]),
 ("REVIEWED_PROFILE_RECEIPT","REVIEWED_PROFILE_RECEIPT",["PROFILE_RECEIPT_REVIEW"]),
 ("NATIVE_AUTHORITY_REVIEW","REVIEW_R3_8",["REVIEWED_PROFILE_RECEIPT","IMPLEMENTATION_REVIEW","SEMANTIC_DERIVATION_REVIEW","FACILITY_REVIEW"]),
 ("NONAUTHORITATIVE_AUTHORITY_JOIN","NATIVE_AUTHORITY_JOIN",["NATIVE_AUTHORITY_REVIEW"])]

def hash_without(obj, member, domain):
    body = {key:value for key,value in obj.items() if key != member}
    return dh(domain, body)

def make_slice(ordinal, kind, profile, path, offset, text):
    raw = text.encode()
    row = {"slice_kind":kind,"profile":profile,"registered_input_ordinal":ordinal,
           "registered_path":path,"registered_file_sha256":sha(path.encode()),
           "row_ordinal":ordinal,"byte_offset":offset,"byte_length":len(raw),
           "raw_slice_hex":raw.hex(),"raw_slice_sha256":sha(raw),
           "normalized_tokens":text}
    row["registered_row_sha256"] = dh("PROGRAM_FACTS_G3_REGISTERED_SOURCE_ROW_V1",row)
    return row

def make_windows_policy_slice():
    text=("policy SetFileInformationByHandle.FileRenameInfoEx "
          "information_class=22 minimum=10.0.17763.0 "
          "comparison=LEXICOGRAPHIC_MAJOR_MINOR_BUILD_REVISION")
    raw=text.encode()
    row={"slice_kind":"WINDOWS_CAPABILITY_POLICY",
      "policy_id":"windows-file-rename-info-ex-v1",
      "registered_path":"/policy/windows/file-rename-info-ex-v1.policy",
      "registered_file_sha256":sha(raw),"row_ordinal":0,"byte_offset":0,
      "byte_length":len(raw),"raw_slice_hex":raw.hex(),
      "raw_slice_sha256":sha(raw),"normalized_tokens":text}
    row["registered_row_sha256"]=dh(
      "PROGRAM_FACTS_G3_REGISTERED_PLATFORM_POLICY_ROW_V1",row)
    return row

def make_manifest():
    slices = []
    for ordinal, api in enumerate(API_NAMES):
        slices.append(make_slice(ordinal,"DECLARATION_HEADER","COMMON_LINUX",
          "/src/include/linux/syscalls.h",1024+64*ordinal,"long sys_"+api+"();"))
    for ordinal, api in enumerate(API_NAMES):
        slices.append(make_slice(22+ordinal,"X86_64_SYSCALL_TABLE",
          "LINUX_X86_64_LP64_LE","/src/arch/x86/entry/syscalls/syscall_64.tbl",
          4096+48*ordinal,str(1000+ordinal)+" common "+api+" sys_"+api))
    for ordinal, api in enumerate(API_NAMES):
        slices.append(make_slice(44+ordinal,"AARCH64_SYSCALL_TABLE",
          "LINUX_AARCH64_LP64_LE","/src/include/uapi/asm-generic/unistd.h",
          8192+48*ordinal,"__SYSCALL("+str(2000+ordinal)+",sys_"+api+")"))
    for ordinal, api in enumerate(API_NAMES):
        slices.append(make_slice(66+ordinal,"X86_64_UAPI_NUMBER_HEADER",
          "LINUX_X86_64_LP64_LE","/src/arch/x86/include/generated/uapi/asm/unistd_64.h",
          12288+32*ordinal,"#define __NR_"+api+" "+str(1000+ordinal)))
    for ordinal, api in enumerate(API_NAMES):
        slices.append(make_slice(88+ordinal,"AARCH64_UAPI_NUMBER_HEADER",
          "LINUX_AARCH64_LP64_LE","/src/include/uapi/asm-generic/unistd.h",
          16384+32*ordinal,"#define __NR_"+api+" "+str(2000+ordinal)))
    bindings = []
    for ordinal, api in enumerate(API_NAMES):
        maps = []
        for profile, table_index, uapi_index, number in [
          ("LINUX_X86_64_LP64_LE",22+ordinal,66+ordinal,1000+ordinal),
          ("LINUX_AARCH64_LP64_LE",44+ordinal,88+ordinal,2000+ordinal)]:
            mapping = {"profile":profile,"table_slice_sha256":
              slices[table_index]["registered_row_sha256"],"uapi_slice_sha256":
              slices[uapi_index]["registered_row_sha256"],
              "syscall_number_u32":number,"uapi_number_u32":number}
            mapping["mapping_sha256"] = dh("PROGRAM_FACTS_G3_ARCH_MAPPING_V1",mapping)
            maps.append(mapping)
        binding = {"ordinal":ordinal,"api":api,
          "declaration_slice_sha256":slices[ordinal]["registered_row_sha256"],
          "architecture_mappings":maps}
        binding["signature_core_sha256"]=dh(
          "PROGRAM_FACTS_G3_SIGNATURE_CORE_V1",{"api":api,
           "declaration_slice_sha256":binding["declaration_slice_sha256"],
           "architecture_mappings":maps})
        binding["binding_sha256"] = dh("PROGRAM_FACTS_G3_DECLARATION_BINDING_V2",binding)
        bindings.append(binding)
    manifest = {"profile":"LINUX_X86_64_LP64_LE","registered_slices":slices,
      "registered_slice_count":len(slices),"declaration_bindings":bindings,
      "declaration_binding_count":len(bindings),
      "registered_platform_policy_slices":[make_windows_policy_slice()],
      "registered_platform_policy_slice_count":1,
      "production_binary":fid("production")}
    manifest["build_manifest_sha256"] = dh("PROGRAM_FACTS_G3_BUILD_MANIFEST_V3",manifest)
    return manifest

def make_projection():
    slots = []
    for ordinal,(name,kind,schema,value) in enumerate([
      ("parent_id","IDENTITY","LINUX_FILE_ID",sha(b"parent")),
      ("leaf","BYTES","PATH_BYTES_V1","6c65616600"),
      ("presence_before","BOOL","BOOL_V1",True),
      ("presence_after","BOOL","BOOL_V1",False),
      ("mount_rows","ROWS","MOUNT_GRAPH_ROWS_V1",[])]):
        slot = {"slot_kind":"PRESENT","field_ordinal":ordinal,"field_name":name,
                "value_kind":kind,"value_schema":schema,"value":value}
        slot["field_sha256"] = dh("PROGRAM_FACTS_G3_PROJECTION_FIELD_V2",slot)
        slots.append(slot)
    projection = {"selector":"EXACT_DIRECTORY_LEAF_IDENTITY","slots":slots,
                  "complete":True,"missing_field_ordinals":[]}
    projection["projection_sha256"] = dh("PROGRAM_FACTS_G3_TYPED_PROJECTION_V2",projection)
    return projection

def make_symbols(projection):
    compatibility = []
    for ordinal,(kind,schema) in enumerate(SYMBOL_COMPATIBILITY):
        row = {"row_ordinal":ordinal,"symbol_kind":kind,
               "projection_schema_id":schema}
        row["row_sha256"] = dh("PROGRAM_FACTS_G3_SYMBOL_KIND_SCHEMA_COMPATIBILITY_V1",row)
        compatibility.append(row)
    declaration = {"symbol_ordinal":0,"name":"fresh_file_id",
      "compatibility_row_sha256":compatibility[0]["row_sha256"],
      "freshness_universe":{"source":"PRESTATE","field_ordinal":0,
        "field_sha256":projection["slots"][0]["field_sha256"],
        "value_schema":"LINUX_FILE_ID_ROWS_V1"}}
    declaration["declaration_sha256"] = dh("PROGRAM_FACTS_G3_FRESH_SYMBOL_DECLARATION_V3",declaration)
    binding = {"symbol_ordinal":0,"declared_symbol_sha256":declaration["declaration_sha256"],
      "compatibility_row_sha256":compatibility[0]["row_sha256"],
      "actual_field_ordinal":0,"actual_field_sha256":projection["slots"][0]["field_sha256"],
      "actual_value_schema":"LINUX_FILE_ID"}
    binding["binding_sha256"] = dh("PROGRAM_FACTS_G3_FRESH_SYMBOL_BINDING_V2",binding)
    return {"compatibility":compatibility,"declarations":[declaration],"bindings":[binding]}

def make_invocation(profile, ordinal):
    invocation = {"profile":profile,"capture_operation_id":"capture-r3-8",
      "invocation_nonce":("%032x" % (ordinal+1)),"boot_session_identity":"boot-r3-8",
      "process_id_u64":5000+ordinal,"process_start_ticks_u64":900000+ordinal,
      "target_process_handle_u64":None if profile.startswith("LINUX") else "%016x"%(7000+ordinal),
      "executable":fid("production"),"argv_sha256":sha(("argv"+profile).encode()),
      "environment_sha256":sha(b"empty-env"),"supervisor_process_id_u64":4000}
    invocation["invocation_sha256"] = dh("PROGRAM_FACTS_G3_PROCESS_INVOCATION_IDENTITY_V1",invocation)
    return invocation

def make_loaded_runtime(profile, ordinal):
    invocation = make_invocation(profile,ordinal)
    modules=[]
    for role in MODULE_ROLES[profile]:
        module={"module_role":role,"module_file":fid(role.lower()),
                "load_base_u64":"%016x"%(0x100000+len(modules)*0x10000),
                "image_size_u64":65536}
        module["module_row_sha256"]=dh("PROGRAM_FACTS_G3_LOADED_MODULE_ROW_V1",module)
        modules.append(module)
    observation={"invocation_sha256":invocation["invocation_sha256"],
      "process_id_u64":invocation["process_id_u64"],
      "process_start_ticks_u64":invocation["process_start_ticks_u64"],
      "target_process_handle_u64":invocation["target_process_handle_u64"],
      "observation_epoch_u64":1000000+ordinal,"observed_while_process_alive":True,
      "method":"LINUX_PROC_PID_MAP_FILES" if profile.startswith("LINUX") else
        "WINDOWS_PEB_LDR_DATA_AND_FILE_ID","modules":modules}
    observation["observation_sha256"]=dh("PROGRAM_FACTS_G3_LOADED_MODULE_OBSERVATION_V1",observation)
    receipt={"invocation":invocation,"observation":observation,
             "executed_production_binary":fid("production")}
    receipt["receipt_sha256"]=dh("PROGRAM_FACTS_G3_LOADED_RUNTIME_RECEIPT_V1",receipt)
    return receipt

def make_reviews():
    nodes=[]
    for ordinal,(kind,artifact_type,predecessors) in enumerate(DAG_ROWS):
        node={"node_ordinal":ordinal,"node_kind":kind,"artifact_type":artifact_type,
              "artifact":fid("dag-"+kind.lower()),"author_principal":"author-"+str(ordinal),
              "subject_identities":[] if not artifact_type.startswith("REVIEW") else
                [fid("subject-"+kind.lower())],"predecessor_kinds":predecessors}
        node["node_sha256"]=dh("PROGRAM_FACTS_G3_DAG_NODE_V1",node)
        nodes.append(node)
    edges=[[source,row[0]] for row in DAG_ROWS for source in row[2]]
    reviews={"nodes":nodes,"node_count":len(nodes),"edges":edges,
             "edge_count":len(edges),"review_disposition":"PASS_NONAUTHORITATIVE",
             "profile_review_subject_sha256":sha(b"profile-body"),
             "profile_body_has_review_member":False}
    reviews["dag_sha256"]=dh("PROGRAM_FACTS_G3_EVIDENCE_DAG_V2",reviews)
    return reviews

def make_windows_platform(manifest):
    loaded=make_loaded_runtime("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2",2)
    policy={"api":"SetFileInformationByHandle.FileRenameInfoEx",
      "information_class_u32":22,"minimum":{"major":10,"minor":0,"build":17763,"revision":0},
      "comparison_policy":"LEXICOGRAPHIC_MAJOR_MINOR_BUILD_REVISION",
      "registered_policy_slice":manifest["registered_platform_policy_slices"][0],
      "sdk_manifest":fid("windows-sdk")}
    policy["policy_sha256"]=dh("PROGRAM_FACTS_G3_WINDOWS_CAPABILITY_POLICY_V1",policy)
    build={"invocation_sha256":loaded["invocation"]["invocation_sha256"],
      "source":"RtlGetVersion","source_module_sha256":loaded["observation"]["modules"][1]["module_row_sha256"],
      "observed":{"major":10,"minor":0,"build":22621,"revision":1},
      "capability_policy":policy,"observed_at_least_pinned_minimum":True}
    build["observation_sha256"]=dh("PROGRAM_FACTS_G3_WINDOWS_BUILD_OBSERVATION_V2",build)
    return {"profile":"WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2",
      "loaded_runtime":loaded,"loaded_runtime_review_role":"LOADED_RUNTIME_REVIEW",
      "capability_policy":policy,"capability_policy_review_role":"WINDOWS_CAPABILITY_POLICY_REVIEW",
      "build_observation":build,"power_loss_capability":False,
      "process_crash_capability":True,"accepting_authority":False,
      "platform_sha256":dh("PROGRAM_FACTS_G3_WINDOWS_PLATFORM_V2",build)}

def make_linux_platform(profile, ordinal):
    loaded=make_loaded_runtime(profile,ordinal)
    inv=loaded["invocation"]["invocation_sha256"]
    durability_profile={"profile_id":"linux-durable-v1","filesystem_type":"ext4",
      "required_mount_options":["rw","barrier","data=ordered"],
      "forbidden_mount_options":["nobarrier"],
      "permitted_storage_kinds":["DIRECT_BLOCK_DEVICE"],
      "required_event_kinds":["FILE_FSYNC_COMPLETED","DIRECTORY_FSYNC_COMPLETED",
        "BLOCK_BARRIER_COMPLETED","JOURNAL_COMMIT_OBSERVED"]}
    durability_profile["profile_sha256"]=dh("PROGRAM_FACTS_G3_LINUX_DURABILITY_PROFILE_V2",durability_profile)
    mount={"invocation_sha256":inv,"operation_epoch_u64":2000000+ordinal,
      "mount_id_u64":31,"parent_mount_id_u64":1,"device_major_u32":8,
      "device_minor_u32":1,"filesystem_uuid":"uuid-r3-8",
      "filesystem_type":"ext4","mount_options":["rw","barrier","data=ordered"],
      "retained_handles_same_mount":True}
    mount["observation_sha256"]=dh("PROGRAM_FACTS_G3_LINUX_MOUNT_OBSERVATION_V1",mount)
    storage={"kind":"DIRECT_BLOCK_DEVICE","device_major_u32":8,"device_minor_u32":1,
             "write_cache":"POWER_SAFE","topology_source_sha256":sha(b"topology")}
    storage["topology_sha256"]=dh("PROGRAM_FACTS_G3_LINUX_STORAGE_TOPOLOGY_V1",storage)
    events=[]
    for event_ordinal,kind in enumerate(durability_profile["required_event_kinds"]):
        event={"event_ordinal":event_ordinal,"invocation_sha256":inv,
          "operation_epoch_u64":mount["operation_epoch_u64"],"mount_id_u64":31,
          "device_major_u32":8,"device_minor_u32":1,"event_kind":kind,
          "target_identity_sha256":sha((kind+profile).encode()),
          "source_event_sha256":sha(("source-"+kind).encode())}
        event["event_sha256"]=dh("PROGRAM_FACTS_G3_LINUX_DURABILITY_EVENT_V1",event)
        events.append(event)
    observation={"invocation_sha256":inv,"mount":mount,"storage":storage,
      "events":events,"required_event_kinds_present":True,
      "derived_capability":"FUTURE_LINUX_POWER_LOSS","power_loss_capability":True}
    observation["observation_sha256"]=dh("PROGRAM_FACTS_G3_LINUX_DURABILITY_OBSERVATION_V2",observation)
    return {"profile":profile,"loaded_runtime":loaded,
      "loaded_runtime_review_role":"LOADED_RUNTIME_REVIEW",
      "durability_profile":durability_profile,
      "durability_profile_review_role":"LINUX_DURABILITY_PROFILE_REVIEW",
      "durability_observation":observation,
      "durability_observation_review_role":"LINUX_DURABILITY_OBSERVATION_REVIEW",
      "power_loss_capability":True,"process_crash_capability":True,
      "accepting_authority":False,
      "platform_sha256":dh("PROGRAM_FACTS_G3_LINUX_PLATFORM_V2",observation)}

def make_windows_outcome(platform):
    request={"profile":"WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2",
      "root_directory_u64":0,"information_class_u32":22,"flags_u32":0,
      "path_kind":"FULL_ABSOLUTE_UTF16LE",
      "destination_path_binding":{"full_absolute_utf16le_hex":
        "5c005c003f005c0056006f006c0075006d0065007b0031007d005c006400730074000000",
        "destination_parent_file_id_sha256":sha(b"destination-parent")},
      "source_path_binding":{"leaf_reopen_file_id_sha256":sha(b"source-file")},
      "source_file_id_sha256":sha(b"source-file"),
      "destination_parent_file_id_sha256":sha(b"destination-parent"),
      "file_name_length_u32":34,"terminator_hex":"0000",
      "input_buffer_hex":"00"*20+"5c005c003f005c0056006f006c0075006d0065007b0031007d005c00640073007400"+"0000"+"00"*4}
    request["request_sha256"]=dh("PROGRAM_FACTS_G3_WINDOWS_RENAME_REQUEST_V4",request)
    result={"bool_return":1,"error_valid":False,"last_error_captured_immediately":0}
    result["result_sha256"]=dh("PROGRAM_FACTS_G3_WINDOWS_RETURN_RESULT_V1",result)
    outer={"request":request,"result":result,
      "source_presence":"ABSENT","destination_presence":"PRESENT",
      "destination_reopen_file_id_sha256":sha(b"source-file"),
      "retained_source_handle_file_id_sha256":sha(b"source-file"),
      "destination_parent_file_id_after_sha256":sha(b"destination-parent")}
    outer["body_sha256"]=dh("PROGRAM_FACTS_G3_WINDOWS_OUTER_EVIDENCE_BODY_V1",outer)
    projection={"outer_evidence_body_sha256":outer["body_sha256"],
      "selector":"WINDOWS_SOURCE_ABSENT_DESTINATION_FILE_ID_CONTINUITY",
      "actual_projection_sha256":sha(b"windows-projection")}
    projection["projection_sha256"]=dh("PROGRAM_FACTS_G3_WINDOWS_OBSERVATION_PROJECTION_V2",projection)
    body={"completion_kind":"RETURNED","outer_evidence":outer,"projection":projection,
      "return_status":"SUCCESS","observed_poststate":"EXPECTED_EFFECT",
      "cell_ordinal":0,"classification":"API_SEMANTIC_SUCCESS","retry_allowed":False}
    body["outcome_sha256"]=dh("PROGRAM_FACTS_G3_OUTCOME_WINDOWS_RETURNED_V1",body)
    operation={"platform":"WINDOWS","completion_kind":"RETURNED",
      "api":"SetFileInformationByHandle.FileRenameInfoEx",
      "profile":"WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2",
      "request_sha256":request["request_sha256"],"result_sha256":result["result_sha256"],
      "outcome_sha256":body["outcome_sha256"],"operation_domain":
        "PROGRAM_FACTS_G3_OPERATION_WINDOWS_RETURNED_V1"}
    operation["operation_sha256"]=dh(operation["operation_domain"],operation)
    operation["operation_id"]="pfg3vop-"+operation["operation_sha256"][:32]
    return {"body":body,"operation":operation}

def make_clone_outcome(platform):
    request_sha=sha(b"clone3-request-frame")
    outer={"profile":"LINUX_X86_64_LP64_LE","api":"clone3",
      "request_frame_sha256":request_sha,"result_frame_sha256":None,
      "observation_row_stream_sha256":sha(b"clone-observations")}
    outer["body_sha256"]=dh("PROGRAM_FACTS_G3_LINUX_OUTER_EVIDENCE_BODY_V1",outer)
    projection={"outer_evidence_body_sha256":outer["body_sha256"],
      "selector":"EXACT_CHILD_PID_PIDFD_AND_NAMESPACE_STATE",
      "actual_projection_sha256":sha(b"clone-projection")}
    projection["projection_sha256"]=dh("PROGRAM_FACTS_G3_LINUX_OBSERVATION_PROJECTION_V2",projection)
    body={"completion_kind":"NO_RETURN",
      "reason":"SPAWN_UNCERTAIN_CLONE_UNOBSERVABLE_AFTER_CRASH","api":"clone3",
      "profile":"LINUX_X86_64_LP64_LE","request_sha256":request_sha,
      "result_sha256":None,"crash_seam_ordinal":2,"crash_seam":"DURING_CALL",
      "outer_evidence":outer,"projection":projection,
      "observed_poststate":"UNOBSERVABLE","cell_ordinal":15,
      "classification":"RECONCILE_NO_REPLAY","retry_allowed":False}
    body["reconciliation_sha256"]=dh("PROGRAM_FACTS_G3_OUTCOME_LINUX_NO_RETURN_V1",body)
    operation={"platform":"LINUX","completion_kind":"NO_RETURN","api":"clone3",
      "profile":"LINUX_X86_64_LP64_LE","request_sha256":request_sha,
      "result_sha256":None,"outcome_sha256":body["reconciliation_sha256"],
      "operation_domain":"PROGRAM_FACTS_G3_OPERATION_LINUX_NO_RETURN_V1"}
    operation["operation_sha256"]=dh(operation["operation_domain"],operation)
    operation["operation_id"]="pfg3vop-"+operation["operation_sha256"][:32]
    return {"body":body,"operation":operation}

def make_effective_root(platforms, aggregate):
    windows=make_windows_outcome(platforms[2]); clone=make_clone_outcome(platforms[0])
    semantic={"branch":"SPAWN_UNCERTAIN","capture_operation_id":"capture-r3-8",
      "pre_clone_operations":[windows],"clone_outcome":clone,
      "terminal_state":"SPAWN_MAY_HAVE_OCCURRED"}
    semantic["body_sha256"]=dh("PROGRAM_FACTS_G3_POST_OPERATION_BODY_SPAWN_UNCERTAIN_V1",semantic)
    occurrences=[]
    for ordinal,(pointer,outcome) in enumerate([
      ("/pre_clone_operations/0",windows),("/clone_outcome",clone)]):
        row={"occurrence_ordinal":ordinal,"operation_json_pointer":pointer,
          "operation":outcome["operation"],"outcome_sha256":outcome["operation"]["outcome_sha256"]}
        row["occurrence_sha256"]=dh("PROGRAM_FACTS_G3_OPERATION_OCCURRENCE_V1",row)
        occurrences.append(row)
    joins=[]
    for row in occurrences:
        join={"occurrence_ordinal":row["occurrence_ordinal"],
          "operation_json_pointer":row["operation_json_pointer"],
          "operation_sha256":row["operation"]["operation_sha256"],
          "conformance_result_sha256":sha(("conformance"+str(row["occurrence_ordinal"])).encode()),
          "process_invocation_sha256":platforms[2 if row["operation"]["platform"]=="WINDOWS" else 0]["loaded_runtime"]["invocation"]["invocation_sha256"],
          "build_manifest_sha256":aggregate["build_manifest_sha256"],
          "platform_sha256":platforms[2 if row["operation"]["platform"]=="WINDOWS" else 0]["platform_sha256"]}
        join["join_sha256"]=dh("PROGRAM_FACTS_G3_OPERATION_EXECUTION_JOIN_V1",join)
        joins.append(join)
    receipt={"post_operation_body_sha256":semantic["body_sha256"],
      "occurrences":occurrences,"occurrence_count":len(occurrences),
      "execution_joins":joins,"execution_join_count":len(joins)}
    receipt["body_sha256"]=dh("PROGRAM_FACTS_G3_PER_OPERATION_RECEIPT_BODY_V2",receipt)
    authority={"state":"MATERIALIZED_REVIEWED_NONAUTHORITATIVE",
      "execution_receipt_sha256":aggregate["aggregate_receipt_sha256"],
      "evidence_authoritative":False,"production_execution_allowed":False,
      "spawn_allowed":False,"publication_allowed":False,"cutover_allowed":False,
      "durability_authority":False}
    envelope={"schema_root":"vector_post_operation_envelope_r3_8",
      "semantic_body":semantic,"semantic_body_canonical_sha256":sha(cj(semantic).encode()),
      "artifact_parses_exact_body":True,"post_operation_body_sha256":semantic["body_sha256"],
      "operation_receipt":receipt,"aggregate_execution_receipt":aggregate,
      "native_execution_authority":authority}
    envelope["post_operation_sha256"]=dh("PROGRAM_FACTS_G3_POST_OPERATION_ENVELOPE_V1",envelope)
    envelope["post_operation_id"]="pfg3po8-"+envelope["post_operation_sha256"][:32]
    spawn={"root_kind":"SPAWN_UNCERTAINTY_OBSERVATION",
      "uncertain_post_operation":envelope,"clone_outcome":clone,
      "equality_to_semantic_body_clone":True}
    spawn["observation_sha256"]=dh("PROGRAM_FACTS_G3_SPAWN_UNCERTAINTY_OBSERVATION_V3",spawn)
    return {"root_kind":"SPAWN_UNCERTAINTY_OBSERVATION","spawn_uncertainty":spawn}

def make_aggregate(manifest):
    profiles=[]
    for ordinal,(profile,outcomes,seams) in enumerate([
      ("LINUX_X86_64_LP64_LE",352,176),
      ("LINUX_AARCH64_LP64_LE",352,176),
      ("WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2",16,8)]):
        profiles.append({"profile_ordinal":ordinal,"profile":profile,
          "outcome_result_count":outcomes,"seam_result_count":seams,
          "bundle_review_role":"PER_PROFILE_EXECUTION_BUNDLE_REVIEW",
          "profile_review_role":"PROFILE_RECEIPT_REVIEW",
          "body_has_review_member":False})
    atomic=[]
    for ordinal in range(2227):
        row={"result_ordinal":ordinal,"result_kind":
          ("OUTCOME" if ordinal<720 else "OTHER"),"result":"PASS_EXPECTED"}
        row["result_sha256"]=dh("PROGRAM_FACTS_G3_R3_8_ATOMIC_RESULT_V1",row)
        atomic.append(row)
    aggregate={"state":"MATERIALIZED_AGGREGATE_NONAUTHORITATIVE",
      "build_manifest_sha256":manifest["build_manifest_sha256"],
      "reviewed_profile_receipts":profiles,"reviewed_profile_count":3,
      "profile_ordinals":[0,1,2],"aggregate_outcome_index_count":720,
      "aggregate_seam_index_count":360,"atomic_results":atomic,
      "atomic_contract_result_count":2227,"authoritative":False,
      "production_execution_allowed":False,"spawn_allowed":False,
      "durability_authority":False}
    aggregate["aggregate_receipt_sha256"]=dh("PROGRAM_FACTS_G3_NATIVE_AGGREGATE_RECEIPT_V3",aggregate)
    return aggregate

def make_baseline(validator_source_sha256):
    manifest=make_manifest(); projection=make_projection(); symbols=make_symbols(projection)
    platforms=[make_linux_platform("LINUX_X86_64_LP64_LE",0),
      make_linux_platform("LINUX_AARCH64_LP64_LE",1),make_windows_platform(manifest)]
    aggregate=make_aggregate(manifest); reviews=make_reviews()
    call_join={"profile":"LINUX_X86_64_LP64_LE","api":"mkdirat",
      "signature_ordinal":0,"declaration_binding_sha256":manifest["declaration_bindings"][0]["binding_sha256"],
      "signature_core_sha256":manifest["declaration_bindings"][0]["signature_core_sha256"],
      "declaration_slice_sha256":manifest["registered_slices"][0]["registered_row_sha256"],
      "syscall_table_slice_sha256":manifest["registered_slices"][22]["registered_row_sha256"],
      "uapi_number_slice_sha256":manifest["registered_slices"][66]["registered_row_sha256"],
      "syscall_number_u32":1000,"build_manifest_sha256":manifest["build_manifest_sha256"]}
    call_join["join_sha256"]=dh("PROGRAM_FACTS_G3_CALL_DECLARATION_JOIN_V2",call_join)
    relation_atoms=[{"operator":"EQ","operands":[{"kind":"FIELD","source":"ACTUAL","field_ordinal":0},{"kind":"LITERAL","value":sha(b"parent")} ]},
      {"operator":"PRESENT","operands":[{"kind":"FIELD","source":"ACTUAL","field_ordinal":0}]},
      {"operator":"FRESH_AGAINST_ROSTER","operands":[{"kind":"SYMBOL","symbol_ordinal":0},{"kind":"FIELD","source":"PRESTATE","field_ordinal":0}]},
      {"operator":"PREFIX_EQ","operands":[{"kind":"BYTES","value":"6c65616600"},{"kind":"BYTES","value":"6c6561"}]}]
    baseline={"schema_id":"plamen.program_facts.g3.materialization.r3_8",
      "contract_version":8,"validator_source_sha256":validator_source_sha256,
      "manifest":manifest,"call_join":call_join,
      "semantic":{"projection":projection,"relation_atoms":relation_atoms,
                   "no_return_return_terms":[],"symbols":symbols},
      "platforms":platforms,"reviews":reviews,"aggregate":aggregate,
      "effective_root":make_effective_root(platforms,aggregate),
      "authority":{"evidence_authoritative":False,
        "production_execution_allowed":False,"spawn_allowed":False,
        "publication_allowed":False,"cutover_allowed":False,
        "accepting_authority":False,"durability_authority":False}}
    return baseline

def need(condition, primary, subcode):
    if not condition:
        raise Rejection(primary,subcode)

def valid_hex(value):
    return isinstance(value,str) and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def validate_subject(subject_bytes):
    try:
        obj=json.loads(subject_bytes.decode("utf-8"))
    except Exception:
        return ("SCHEMA","INVALID_CANONICAL_JSON")
    if cj(obj).encode()!=subject_bytes:
        return ("SCHEMA","NONCANONICAL_SUBJECT_BYTES")
    try:
        need(obj.get("schema_id")=="plamen.program_facts.g3.materialization.r3_8","SCHEMA","WRONG_SCHEMA_ID")
        need(obj.get("contract_version")==8,"SCHEMA","WRONG_CONTRACT_VERSION")
        manifest=obj["manifest"]; slices=manifest["registered_slices"]
        need(len(slices)==110 and manifest["registered_slice_count"]==110,"NATIVE_PROVENANCE","REGISTERED_SLICE_CARDINALITY")
        expected_kinds=["DECLARATION_HEADER"]*22+["X86_64_SYSCALL_TABLE"]*22+["AARCH64_SYSCALL_TABLE"]*22+["X86_64_UAPI_NUMBER_HEADER"]*22+["AARCH64_UAPI_NUMBER_HEADER"]*22
        expected_profiles=["COMMON_LINUX"]*22+["LINUX_X86_64_LP64_LE"]*22+["LINUX_AARCH64_LP64_LE"]*22+["LINUX_X86_64_LP64_LE"]*22+["LINUX_AARCH64_LP64_LE"]*22
        need([r["slice_kind"] for r in slices]==expected_kinds,"NATIVE_PROVENANCE","SLICE_KIND_ROSTER_MISMATCH")
        need(slices[22]["profile"]=="LINUX_X86_64_LP64_LE","NATIVE_PROVENANCE","X86_TABLE_PROFILE_SPLICE")
        need(slices[44]["profile"]=="LINUX_AARCH64_LP64_LE","NATIVE_PROVENANCE","AARCH64_TABLE_PROFILE_SPLICE")
        need([r["profile"] for r in slices]==expected_profiles,"NATIVE_PROVENANCE","SLICE_PROFILE_ROSTER_MISMATCH")
        need(slices[0]["registered_path"]=="/src/include/linux/syscalls.h","NATIVE_PROVENANCE","WRONG_REGISTERED_SOURCE_FILE")
        need(len({(r["registered_path"],r["byte_offset"]) for r in slices})==len(slices),"NATIVE_PROVENANCE","DUPLICATE_MATCHING_SOURCE_ROWS")
        for index,row in enumerate(slices):
            need(row["row_ordinal"]==index,"NATIVE_PROVENANCE","REGISTERED_ROW_ORDINAL_MISMATCH")
            expected_offset=(1024+64*index if index<22 else 4096+48*(index-22) if index<44 else 8192+48*(index-44) if index<66 else 12288+32*(index-66) if index<88 else 16384+32*(index-88))
            need(row["byte_offset"]==expected_offset,"NATIVE_PROVENANCE","WRONG_REGISTERED_SOURCE_OFFSET")
            need(row["registered_file_sha256"]==sha(row["registered_path"].encode()),"NATIVE_PROVENANCE","UNREGISTERED_SAME_TEXT_SLICE")
            raw=bytes.fromhex(row["raw_slice_hex"])
            need(row["byte_length"]==len(raw),"NATIVE_PROVENANCE","REGISTERED_SOURCE_LENGTH_MISMATCH")
            need(row["raw_slice_sha256"]==sha(raw),"NATIVE_PROVENANCE","REGISTERED_SOURCE_BYTES_MISMATCH")
            need(row["registered_row_sha256"]==hash_without(row,"registered_row_sha256","PROGRAM_FACTS_G3_REGISTERED_SOURCE_ROW_V1"),"NATIVE_PROVENANCE","REGISTERED_ROW_HASH_MISMATCH")
        bindings=manifest["declaration_bindings"]
        need(len(bindings)==manifest["declaration_binding_count"]==22,"NATIVE_PROVENANCE","DECLARATION_BINDING_CARDINALITY")
        for index,binding in enumerate(bindings):
            need(binding["ordinal"]==index and binding["api"]==API_NAMES[index],"NATIVE_PROVENANCE","DECLARATION_BINDING_API_MISMATCH")
            need(binding["declaration_slice_sha256"]==slices[index]["registered_row_sha256"],"NATIVE_PROVENANCE","DECLARATION_SLICE_JOIN_MISMATCH")
            need(len(binding["architecture_mappings"])==2,"NATIVE_PROVENANCE","ARCHITECTURE_MAPPING_CARDINALITY")
            for map_index,mapping in enumerate(binding["architecture_mappings"]):
                profile="LINUX_X86_64_LP64_LE" if map_index==0 else "LINUX_AARCH64_LP64_LE"
                need(mapping["profile"]==profile,"NATIVE_PROVENANCE","ARCHITECTURE_MAPPING_PROFILE_MISMATCH")
                table_index=(22 if map_index==0 else 44)+index; uapi_index=(66 if map_index==0 else 88)+index
                need(mapping["table_slice_sha256"]==slices[table_index]["registered_row_sha256"],"NATIVE_PROVENANCE","TABLE_SLICE_JOIN_MISMATCH")
                need(mapping["uapi_slice_sha256"]==slices[uapi_index]["registered_row_sha256"],"NATIVE_PROVENANCE","UAPI_SLICE_JOIN_MISMATCH")
                mismatch_subcode="X86_UAPI_NUMBER_MISMATCH" if map_index==0 else "AARCH64_UAPI_NUMBER_MISMATCH"
                need(mapping["syscall_number_u32"]==mapping["uapi_number_u32"],"NATIVE_PROVENANCE",mismatch_subcode)
            need(binding["binding_sha256"]==hash_without(binding,"binding_sha256","PROGRAM_FACTS_G3_DECLARATION_BINDING_V2"),"NATIVE_PROVENANCE","DECLARATION_BINDING_HASH_MISMATCH")
        policy_slices=manifest["registered_platform_policy_slices"]
        need(len(policy_slices)==manifest["registered_platform_policy_slice_count"]==1,"NATIVE_PROVENANCE","PLATFORM_POLICY_SLICE_CARDINALITY")
        policy_slice=policy_slices[0]
        need(policy_slice["slice_kind"]=="WINDOWS_CAPABILITY_POLICY" and policy_slice["policy_id"]=="windows-file-rename-info-ex-v1","NATIVE_PROVENANCE","WINDOWS_POLICY_SLICE_KIND_MISMATCH")
        policy_raw=bytes.fromhex(policy_slice["raw_slice_hex"])
        need(policy_slice["byte_offset"]==0 and policy_slice["byte_length"]==len(policy_raw),"NATIVE_PROVENANCE","WINDOWS_POLICY_SLICE_RANGE_MISMATCH")
        need(policy_slice["raw_slice_sha256"]==sha(policy_raw) and policy_slice["registered_file_sha256"]==sha(policy_raw),"NATIVE_PROVENANCE","WINDOWS_POLICY_SLICE_BYTES_MISMATCH")
        need(policy_slice["registered_row_sha256"]==hash_without(policy_slice,"registered_row_sha256","PROGRAM_FACTS_G3_REGISTERED_PLATFORM_POLICY_ROW_V1"),"NATIVE_PROVENANCE","WINDOWS_POLICY_SLICE_HASH_MISMATCH")
        expected_manifest=hash_without(manifest,"build_manifest_sha256","PROGRAM_FACTS_G3_BUILD_MANIFEST_V3")
        need(manifest["build_manifest_sha256"]==expected_manifest,"NATIVE_PROVENANCE","BUILD_MANIFEST_HASH_MISMATCH")
        join=obj["call_join"]; binding=bindings[join["signature_ordinal"]]
        need(join["profile"]=="LINUX_X86_64_LP64_LE","NATIVE_PROVENANCE","CALL_PROFILE_MAPPING_MISMATCH")
        need(join["declaration_binding_sha256"]==binding["binding_sha256"],"NATIVE_PROVENANCE","UNRELATED_DECLARATION_BINDING")
        need(join["signature_core_sha256"]==binding["signature_core_sha256"],"NATIVE_PROVENANCE","CALL_SIGNATURE_ROW_SPLICE")
        need(join["declaration_slice_sha256"]==binding["declaration_slice_sha256"],"NATIVE_PROVENANCE","CALL_DECLARATION_SLICE_MISMATCH")
        need(join["syscall_table_slice_sha256"]==binding["architecture_mappings"][0]["table_slice_sha256"],"NATIVE_PROVENANCE","CALL_TABLE_SLICE_MISMATCH")
        need(join["uapi_number_slice_sha256"]==binding["architecture_mappings"][0]["uapi_slice_sha256"],"NATIVE_PROVENANCE","CALL_UAPI_SLICE_MISMATCH")
        need(join["build_manifest_sha256"]==manifest["build_manifest_sha256"],"NATIVE_PROVENANCE","CALL_MANIFEST_SPLICE")
        need(join["join_sha256"]==hash_without(join,"join_sha256","PROGRAM_FACTS_G3_CALL_DECLARATION_JOIN_V2"),"NATIVE_PROVENANCE","CALL_JOIN_HASH_MISMATCH")

        semantic=obj["semantic"]; projection=semantic["projection"]; slots=projection["slots"]
        missing=[r["field_ordinal"] for r in slots if r["slot_kind"]=="MISSING"]
        need(projection["complete"]==(missing==[]),"PROJECTION_TOTALITY","COMPLETE_MISSING_INCONSISTENT")
        need(projection["missing_field_ordinals"]==missing,"PROJECTION_TOTALITY","MISSING_ORDINALS_NOT_DERIVED")
        need([r["field_ordinal"] for r in slots]==list(range(len(slots))),"PROJECTION_TOTALITY","PROJECTION_SLOT_ORDINAL_MISMATCH")
        need(all(r["slot_kind"]=="PRESENT" for r in slots),"PROJECTION_TOTALITY","PRESENT_MISSING_PARTITION_MISMATCH")
        expected_slot_schemas=["LINUX_FILE_ID","PATH_BYTES_V1","BOOL_V1","BOOL_V1","MOUNT_GRAPH_ROWS_V1"]
        subtype_subcodes=["IDENTITY_SUBTYPE_MISMATCH","BYTES_SUBTYPE_MISMATCH","BOOL_SUBTYPE_MISMATCH","BOOL_SUBTYPE_MISMATCH","ROWS_SUBTYPE_UNREGISTERED"]
        for index,row in enumerate(slots):
            need(row["value_schema"]==expected_slot_schemas[index],"PROJECTION_TYPE",subtype_subcodes[index])
            need(row["field_sha256"]==hash_without(row,"field_sha256","PROGRAM_FACTS_G3_PROJECTION_FIELD_V2"),"PROJECTION_TOTALITY","PROJECTION_FIELD_HASH_MISMATCH")
        need(projection["projection_sha256"]==hash_without(projection,"projection_sha256","PROGRAM_FACTS_G3_TYPED_PROJECTION_V2"),"PROJECTION_TOTALITY","PROJECTION_HASH_MISMATCH")
        atoms=semantic["relation_atoms"]
        need(atoms[0]["operator"]=="EQ" and len(atoms[0]["operands"])==2,"RELATION_OPERATOR","OPERATOR_ARITY_MISMATCH")
        need(atoms[0]["operands"][0]["kind"]=="FIELD" and atoms[0]["operands"][1]["kind"]=="LITERAL","RELATION_OPERATOR","OPERATOR_OPERAND_KIND_MISMATCH")
        need(atoms[3]["operator"]=="PREFIX_EQ" and atoms[3]["operands"][1]["kind"]=="BYTES","RELATION_OPERATOR","OPERATOR_OPERAND_KIND_MISMATCH")
        need(semantic["no_return_return_terms"]==[],"RELATION_OPERATOR","NO_RETURN_RETURN_TERM_UNRESOLVED")
        symbols=semantic["symbols"]; compatibility=symbols["compatibility"]
        need([(r["symbol_kind"],r["projection_schema_id"]) for r in compatibility]==SYMBOL_COMPATIBILITY,"FRESH_SYMBOL","COMPATIBILITY_ROSTER_MISMATCH")
        for row in compatibility:
            need(row["row_sha256"]==hash_without(row,"row_sha256","PROGRAM_FACTS_G3_SYMBOL_KIND_SCHEMA_COMPATIBILITY_V1"),"FRESH_SYMBOL","COMPATIBILITY_ROW_HASH_MISMATCH")
        need(len(symbols["bindings"])==len(symbols["declarations"])==1,"FRESH_SYMBOL","DECLARATION_BINDING_BIJECTION")
        declaration=symbols["declarations"][0]; binding=symbols["bindings"][0]
        need(binding["declared_symbol_sha256"]==declaration["declaration_sha256"],"FRESH_SYMBOL","DECLARATION_SUBSTITUTION")
        need(binding["compatibility_row_sha256"]==declaration["compatibility_row_sha256"],"FRESH_SYMBOL","COMPATIBILITY_ROW_SUBSTITUTION")
        row=next(r for r in compatibility if r["row_sha256"]==binding["compatibility_row_sha256"])
        need(binding["actual_value_schema"]==row["projection_schema_id"],"FRESH_SYMBOL","BINDING_WRONG_SCHEMA")
        need(binding["actual_field_ordinal"]==0,"FRESH_SYMBOL","BINDING_AMBIGUOUS_FIELD")
        need(binding["actual_field_sha256"]==slots[0]["field_sha256"],"FRESH_SYMBOL","BINDING_STALE_FIELD")
        universe=declaration["freshness_universe"]
        need(universe["source"] in ("PRESTATE","REQUEST"),"FRESH_SYMBOL","UNIVERSE_CROSS_SOURCE")
        need(universe["value_schema"]=="LINUX_FILE_ID_ROWS_V1","FRESH_SYMBOL","UNIVERSE_SCHEMA_MISMATCH")

        platforms=obj["platforms"]
        need([p["profile"] for p in platforms]==["LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE","WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"],"AGGREGATE_TOTALITY","CROSS_PROFILE_SPLICE")
        for platform in platforms:
            loaded=platform["loaded_runtime"]; inv=loaded["invocation"]; observation=loaded["observation"]
            need(observation["invocation_sha256"]==inv["invocation_sha256"],"PLATFORM_DERIVATION","LOADED_RUNTIME_INVOCATION_SPLICE")
            need(observation["process_id_u64"]==inv["process_id_u64"],"PLATFORM_DERIVATION","LOADED_RUNTIME_PROCESS_ID_SPLICE")
            need(observation["process_start_ticks_u64"]==inv["process_start_ticks_u64"],"PLATFORM_DERIVATION","LOADED_RUNTIME_PROCESS_START_SPLICE")
            need(observation["target_process_handle_u64"]==inv["target_process_handle_u64"],"PLATFORM_DERIVATION","LOADED_RUNTIME_TARGET_HANDLE_SPLICE")
            need([m["module_role"] for m in observation["modules"]]==MODULE_ROLES[platform["profile"]],"PLATFORM_DERIVATION","LOADED_RUNTIME_MODULE_ROSTER_MISMATCH")
            for module in observation["modules"]:
                need(module["module_row_sha256"]==hash_without(module,"module_row_sha256","PROGRAM_FACTS_G3_LOADED_MODULE_ROW_V1"),"PLATFORM_DERIVATION","LOADED_RUNTIME_MODULE_SPLICE")
            need(loaded["executed_production_binary"]==inv["executable"],"PLATFORM_DERIVATION","PLATFORM_BINARY_SPLICE")
            need(platform["loaded_runtime_review_role"]=="LOADED_RUNTIME_REVIEW","REVIEW_DAG","LOADED_RUNTIME_REVIEW_ROLE_MISMATCH")
        windows=platforms[2]; policy=windows["capability_policy"]; build=windows["build_observation"]
        need(policy["registered_policy_slice"]==policy_slice,"PLATFORM_DERIVATION","WINDOWS_MINIMUM_SOURCE_SPLICE")
        need(policy_slice["normalized_tokens"]=="policy SetFileInformationByHandle.FileRenameInfoEx information_class=22 minimum=10.0.17763.0 comparison=LEXICOGRAPHIC_MAJOR_MINOR_BUILD_REVISION" and tuple(policy["minimum"][k] for k in ("major","minor","build","revision"))==(10,0,17763,0),"PLATFORM_DERIVATION","WINDOWS_MINIMUM_SOURCE_SPLICE")
        need(policy["policy_sha256"]==hash_without(policy,"policy_sha256","PROGRAM_FACTS_G3_WINDOWS_CAPABILITY_POLICY_V1"),"PLATFORM_DERIVATION","WINDOWS_POLICY_HASH_MISMATCH")
        need(all(isinstance(v,int) and not isinstance(v,bool) for v in build["observed"].values()),"PLATFORM_DERIVATION","WINDOWS_BUILD_COMPONENT_NOT_INTEGER")
        observed=tuple(build["observed"][k] for k in ("major","minor","build","revision")); minimum=tuple(policy["minimum"][k] for k in ("major","minor","build","revision"))
        need(build["observed_at_least_pinned_minimum"]==(observed>=minimum) and observed>=minimum,"PLATFORM_DERIVATION","WINDOWS_BUILD_BELOW_MINIMUM")
        need(build["source_module_sha256"]==windows["loaded_runtime"]["observation"]["modules"][1]["module_row_sha256"],"PLATFORM_DERIVATION","WINDOWS_BUILD_SOURCE_MODULE_SPLICE")
        need(windows["power_loss_capability"] is False,"PLATFORM_CEILING","WINDOWS_POWER_LOSS_FORBIDDEN")
        for linux in platforms[:2]:
            profile=linux["durability_profile"]; observation=linux["durability_observation"]
            mount=observation["mount"]; storage=observation["storage"]; events=observation["events"]
            need(mount["filesystem_type"]==profile["filesystem_type"] and all(x in mount["mount_options"] for x in profile["required_mount_options"]) and not any(x in mount["mount_options"] for x in profile["forbidden_mount_options"]),"PLATFORM_DERIVATION","LINUX_FILESYSTEM_MOUNT_PROFILE_SPLICE")
            need(storage["kind"] in profile["permitted_storage_kinds"] and (storage["device_major_u32"],storage["device_minor_u32"])==(mount["device_major_u32"],mount["device_minor_u32"]),"PLATFORM_DERIVATION","LINUX_STORAGE_TOPOLOGY_MISMATCH")
            need(sorted(e["event_kind"] for e in events)==sorted(profile["required_event_kinds"]),"PLATFORM_DERIVATION","LINUX_DURABILITY_EVENT_OMISSION")
            need(all(e["invocation_sha256"]==observation["invocation_sha256"] and e["operation_epoch_u64"]==mount["operation_epoch_u64"] and e["mount_id_u64"]==mount["mount_id_u64"] and (e["device_major_u32"],e["device_minor_u32"])==(mount["device_major_u32"],mount["device_minor_u32"]) for e in events),"PLATFORM_DERIVATION","LINUX_DURABILITY_EVENT_BINDING_MISMATCH")
            need(linux["durability_profile_review_role"]=="LINUX_DURABILITY_PROFILE_REVIEW" and linux["durability_observation_review_role"]=="LINUX_DURABILITY_OBSERVATION_REVIEW","REVIEW_DAG","LINUX_DURABILITY_REVIEW_ROLE_MISMATCH")
            need(observation["required_event_kinds_present"] is True and observation["derived_capability"]=="FUTURE_LINUX_POWER_LOSS" and observation["power_loss_capability"] is True and linux["power_loss_capability"] is True,"PLATFORM_DERIVATION","LINUX_POWER_LOSS_DERIVATION_UNSATISFIED")

        root=obj["effective_root"]
        need(root["root_kind"]=="SPAWN_UNCERTAINTY_OBSERVATION","EFFECTIVE_ROOT_COVERAGE","EFFECTIVE_ROOT_KIND_MISMATCH")
        spawn=root["spawn_uncertainty"]; envelope=spawn["uncertain_post_operation"]
        need(envelope["schema_root"]=="vector_post_operation_envelope_r3_8","EFFECTIVE_ROOT_COVERAGE","POST_OPERATION_SCHEMA_ROOT_MISMATCH")
        semantic_body=envelope["semantic_body"]
        need(semantic_body["branch"]=="SPAWN_UNCERTAIN","EFFECTIVE_ROOT_COVERAGE","SEMANTIC_BODY_BRANCH_MISMATCH")
        need(isinstance(semantic_body["clone_outcome"],dict),"EFFECTIVE_ROOT_COVERAGE","UNCERTAIN_CLONE_UNTYPED")
        clone=semantic_body["clone_outcome"]
        need(clone["body"]["api"]=="clone3" and clone["body"]["reason"]=="SPAWN_UNCERTAIN_CLONE_UNOBSERVABLE_AFTER_CRASH","EFFECTIVE_ROOT_COVERAGE","UNCERTAIN_CLONE_SEMANTICS_MISMATCH")

        for outcome in semantic_body["pre_clone_operations"]+[clone]:
            operation=outcome["operation"]; body=outcome["body"]
            need(operation["operation_id"]=="pfg3vop-"+operation["operation_sha256"][:32],"OPERATION_IDENTITY","OPERATION_ID_PREFIX_MISMATCH")
            expected_domain={("WINDOWS","RETURNED"):"PROGRAM_FACTS_G3_OPERATION_WINDOWS_RETURNED_V1",("WINDOWS","NO_RETURN"):"PROGRAM_FACTS_G3_OPERATION_WINDOWS_NO_RETURN_V1",("LINUX","RETURNED"):"PROGRAM_FACTS_G3_OPERATION_LINUX_RETURNED_V1",("LINUX","NO_RETURN"):"PROGRAM_FACTS_G3_OPERATION_LINUX_NO_RETURN_V1"}[(operation["platform"],operation["completion_kind"])]
            need(operation["operation_domain"]==expected_domain,"OPERATION_IDENTITY","BRANCH_DOMAIN_MISMATCH")
            if operation["completion_kind"]=="NO_RETURN":
                need(operation["result_sha256"] is None,"OPERATION_IDENTITY","NO_RETURN_RESULT_NOT_NULL")
            operation_preimage={key:value for key,value in operation.items() if key not in ("operation_sha256","operation_id")}
            need(operation["operation_sha256"]==dh(operation["operation_domain"],operation_preimage),"OPERATION_IDENTITY","OPERATION_HASH_MISMATCH")
            if operation["platform"]=="WINDOWS":
                outer=body["outer_evidence"]; result=outer["result"]
                need(result["result_sha256"]==hash_without(result,"result_sha256","PROGRAM_FACTS_G3_WINDOWS_RETURN_RESULT_V1"),"OPERATION_IDENTITY","WINDOWS_RESULT_HASH_MISMATCH")
                need(operation["result_sha256"]==result["result_sha256"],"OPERATION_IDENTITY","WINDOWS_OPERATION_RESULT_SPLICE")
                need(body["projection"]["outer_evidence_body_sha256"]==outer["body_sha256"],"PROJECTION_DERIVATION","WINDOWS_OBSERVATION_PROJECTION_SPLICE")
                request=outer["request"]
                need(request["root_directory_u64"]==0,"WINDOWS_RENAME","ROOT_DIRECTORY_NON_NULL")
                need(request["path_kind"]=="FULL_ABSOLUTE_UTF16LE","WINDOWS_RENAME","FULL_PATH_REQUIRED")
                need(bytes.fromhex(request["destination_path_binding"]["full_absolute_utf16le_hex"]).decode("utf-16le").startswith("\\\\?\\Volume{"),"WINDOWS_RENAME","FULL_PATH_REQUIRED")
                name_bytes=bytes.fromhex(request["destination_path_binding"]["full_absolute_utf16le_hex"])
                need(request["file_name_length_u32"]==len(name_bytes)-2,"WINDOWS_RENAME","FILENAME_LENGTH_INCLUDES_TERMINATOR")
                need(request["input_buffer_hex"].endswith("000000000000"),"WINDOWS_RENAME","NONZERO_PADDING_BYTE")
                need(request["source_path_binding"]["leaf_reopen_file_id_sha256"]==request["source_file_id_sha256"],"WINDOWS_RENAME","SOURCE_PATH_HANDLE_MISMATCH")
                need(request["destination_path_binding"]["destination_parent_file_id_sha256"]==request["destination_parent_file_id_sha256"],"WINDOWS_RENAME","DESTINATION_PATH_HANDLE_MISMATCH")
                need(request["request_sha256"]==hash_without(request,"request_sha256","PROGRAM_FACTS_G3_WINDOWS_RENAME_REQUEST_V4"),"OPERATION_IDENTITY","WINDOWS_REQUEST_HASH_MISMATCH")
                need(outer["body_sha256"]==hash_without(outer,"body_sha256","PROGRAM_FACTS_G3_WINDOWS_OUTER_EVIDENCE_BODY_V1"),"OPERATION_IDENTITY","WINDOWS_OUTER_EVIDENCE_HASH_MISMATCH")
                need(body["projection"]["projection_sha256"]==hash_without(body["projection"],"projection_sha256","PROGRAM_FACTS_G3_WINDOWS_OBSERVATION_PROJECTION_V2"),"PROJECTION_DERIVATION","WINDOWS_PROJECTION_HASH_MISMATCH")
                need(body["outcome_sha256"]==hash_without(body,"outcome_sha256","PROGRAM_FACTS_G3_OUTCOME_WINDOWS_RETURNED_V1"),"OPERATION_IDENTITY","WINDOWS_OUTCOME_HASH_MISMATCH")
            else:
                need(body["projection"]["outer_evidence_body_sha256"]==body["outer_evidence"]["body_sha256"],"PROJECTION_DERIVATION","LINUX_OBSERVATION_PROJECTION_SPLICE")
                need(body["outer_evidence"]["body_sha256"]==hash_without(body["outer_evidence"],"body_sha256","PROGRAM_FACTS_G3_LINUX_OUTER_EVIDENCE_BODY_V1"),"OPERATION_IDENTITY","LINUX_OUTER_EVIDENCE_HASH_MISMATCH")
                need(body["projection"]["projection_sha256"]==hash_without(body["projection"],"projection_sha256","PROGRAM_FACTS_G3_LINUX_OBSERVATION_PROJECTION_V2"),"PROJECTION_DERIVATION","LINUX_PROJECTION_HASH_MISMATCH")
                need(body["reconciliation_sha256"]==hash_without(body,"reconciliation_sha256","PROGRAM_FACTS_G3_OUTCOME_LINUX_NO_RETURN_V1"),"OPERATION_IDENTITY","LINUX_OUTCOME_HASH_MISMATCH")

        need(spawn["clone_outcome"]==clone and spawn["equality_to_semantic_body_clone"] is True,"EFFECTIVE_ROOT_COVERAGE","UNCERTAIN_CLONE_OUTER_MISMATCH")
        need(semantic_body["body_sha256"]==hash_without(semantic_body,"body_sha256","PROGRAM_FACTS_G3_POST_OPERATION_BODY_SPAWN_UNCERTAIN_V1"),"OPERATION_IDENTITY","OUTCOME_HASH_SEMANTIC_SELF_REFERENCE")
        receipt=envelope.get("operation_receipt")
        need(isinstance(receipt,dict),"EFFECTIVE_ROOT_COVERAGE","POST_OPERATION_RECEIPT_MISSING")
        derived=[("/pre_clone_operations/"+str(i),outcome) for i,outcome in enumerate(semantic_body["pre_clone_operations"])]+[("/clone_outcome",clone)]
        occurrences=receipt["occurrences"]
        need(len(occurrences)==receipt["occurrence_count"]==len(derived),"EFFECTIVE_ROOT_COVERAGE","EFFECTIVE_OCCURRENCE_OMISSION")
        need([r["occurrence_ordinal"] for r in occurrences]==list(range(len(derived))),"EFFECTIVE_ROOT_COVERAGE","EFFECTIVE_OCCURRENCE_DUPLICATE")
        for occurrence,(pointer,outcome) in zip(occurrences,derived):
            need(occurrence["operation_json_pointer"]==pointer,"EFFECTIVE_ROOT_COVERAGE","OCCURRENCE_POINTER_NONRESOLVING")
            need(occurrence["operation"]==outcome["operation"],"OPERATION_IDENTITY","CROSS_BRANCH_IDENTITY_SPLICE")
        joins=receipt["execution_joins"]
        need(len(joins)==receipt["execution_join_count"]==len(occurrences),"EFFECTIVE_ROOT_COVERAGE","EXECUTION_JOIN_OMISSION")
        for occurrence,join in zip(occurrences,joins):
            need(join["operation_sha256"]==occurrence["operation"]["operation_sha256"],"EFFECTIVE_ROOT_COVERAGE","UNRELATED_CONFORMANCE_RESULT")
        need(receipt["body_sha256"]==hash_without(receipt,"body_sha256","PROGRAM_FACTS_G3_PER_OPERATION_RECEIPT_BODY_V2"),"EFFECTIVE_ROOT_COVERAGE","EXECUTION_RECEIPT_HASH_MISMATCH")
        need(envelope["post_operation_body_sha256"]==semantic_body["body_sha256"],"EFFECTIVE_ROOT_COVERAGE","POST_OPERATION_BODY_HASH_MISMATCH")
        need(envelope["aggregate_execution_receipt"]["aggregate_receipt_sha256"]==envelope["native_execution_authority"]["execution_receipt_sha256"],"EFFECTIVE_ROOT_COVERAGE","AUTHORITY_RECEIPT_SPLICE")
        envelope_preimage={key:value for key,value in envelope.items() if key not in ("post_operation_sha256","post_operation_id")}
        need(envelope["post_operation_sha256"]==dh("PROGRAM_FACTS_G3_POST_OPERATION_ENVELOPE_V1",envelope_preimage) and envelope["post_operation_id"]=="pfg3po8-"+envelope["post_operation_sha256"][:32],"EFFECTIVE_ROOT_COVERAGE","POST_OPERATION_ID_MISMATCH")

        reviews=obj["reviews"]
        need(reviews["review_disposition"]=="PASS_NONAUTHORITATIVE","REVIEW_PASS_ONLY","REPAIR_REVIEW_REJECTED")
        need(reviews["profile_review_subject_sha256"]==sha(b"profile-body"),"REVIEW_PASS_ONLY","REVIEW_SUBJECT_MISMATCH")
        need(reviews["profile_body_has_review_member"] is False,"REVIEW_ACYCLICITY","PROFILE_RECEIPT_SELF_REFERENCE")
        need(len(reviews["nodes"])==reviews["node_count"]==27,"REVIEW_DAG","REQUIRED_NODE_OMISSION")
        expected_edges=[[source,row[0]] for row in DAG_ROWS for source in row[2]]
        need(reviews["edges"]==expected_edges and reviews["edge_count"]==42,"REVIEW_DAG","REQUIRED_EDGE_OMISSION")
        host=next(n for n in reviews["nodes"] if n["node_kind"]=="PER_PROFILE_EXECUTION_RECEIPT_BUNDLE")
        need(host["artifact_type"]=="PER_PROFILE_EXECUTION_RECEIPT_BUNDLE","REVIEW_DAG","HOST_RECEIPT_TYPE_MISMATCH")
        need([(n["node_kind"],n["artifact_type"],n["predecessor_kinds"]) for n in reviews["nodes"]]==DAG_ROWS,"REVIEW_DAG","DAG_NODE_ROSTER_MISMATCH")
        aggregate=obj["aggregate"]; profiles=aggregate["reviewed_profile_receipts"]
        need(len(profiles)==aggregate["reviewed_profile_count"]==3,"AGGREGATE_TOTALITY","AGGREGATE_PROFILE_OMISSION")
        need([p["profile_ordinal"] for p in profiles]==[0,1,2],"AGGREGATE_TOTALITY","AGGREGATE_PROFILE_DUPLICATE")
        need(aggregate["profile_ordinals"]==[0,1,2],"AGGREGATE_TOTALITY","AGGREGATE_PROFILE_DUPLICATE")
        need([p["profile"] for p in profiles]==["LINUX_X86_64_LP64_LE","LINUX_AARCH64_LP64_LE","WINDOWS_X64_FILE_RENAME_INFO_ABSOLUTE_NULL_V2"],"AGGREGATE_TOTALITY","CROSS_PROFILE_SPLICE")
        need(len(aggregate["atomic_results"])==aggregate["atomic_contract_result_count"]==2227,"ATOMIC_RESULT","ATOMIC_DENOMINATOR_MISMATCH")
        for row in aggregate["atomic_results"]:
            need(row["result_sha256"]==hash_without(row,"result_sha256","PROGRAM_FACTS_G3_R3_8_ATOMIC_RESULT_V1"),"ATOMIC_RESULT","RESULT_HASH_SELF_REFERENCE")
        need(all(value is False for value in obj["authority"].values()),"AUTHORITY_CEILING","ENABLING_FIELD_TRUE")
        return ("ACCEPTED","MATERIALIZATION_BASELINE_VALID")
    except (KeyError,TypeError,ValueError,StopIteration):
        return ("SCHEMA","MISSING_OR_WRONG_TYPED_MEMBER")
    except Rejection as rejection:
        return (rejection.primary,rejection.subcode)
```
<!-- END R3_8_MATERIALIZATION_VALIDATOR_SOURCE -->

The baseline artifact is the exact canonical UTF-8 `CJ(make_baseline(
validator_source_sha256))` output of this source. It is a parsed instance of the
same materialization subject accepted by `validate_subject`, with 110 registered
slices, 22 declaration bindings, three platform profiles, the operative spawn-
uncertainty root, two derived occurrences and joins, the complete 27-node/
42-edge review graph, three profile rows, and 2,227 atomic results. It is
contract-test material only and every enabling/authority member is false.

## 9. Real JSON-Patch mutation construction

This source is test orchestration, not part of the validator. It receives the
already serialized-and-parsed accepted baseline and returns exactly 67
single-operation JSON Patch specifications. Every path resolves against the
real R3.8 materialization schema; `add` targets are absent or array insertion
positions, `replace` targets exist, and `remove` targets exist. Expected
diagnostics are retained here only for post-invocation comparison and are never
visible to `validate_subject`.

<!-- BEGIN R3_8_MUTATION_SPEC_SOURCE -->
```python
import copy

def build_mutation_specs(baseline):
    specs=[]
    zero="0"*64
    opfx=("/effective_root/spawn_uncertainty/uncertain_post_operation/"
          "semantic_body/pre_clone_operations/0")
    clonefx=("/effective_root/spawn_uncertainty/uncertain_post_operation/"
             "semantic_body/clone_outcome")
    def add(family,ordinal,tier,op,path,value,primary,subcode):
        specs.append({"family":family,"ordinal":ordinal,
          "validation_tier":tier,"patch":{"op":op,"path":path,
          **({} if op=="remove" else {"value":copy.deepcopy(value)})},
          "expected_primary":primary,"expected_subcode":subcode})

    family="SIGNATURE_DEPENDENCY_NEGATIVE"
    add(family,0,"ROSTER_GATE","replace","/manifest/registered_slices/0/registered_file_sha256",zero,"NATIVE_PROVENANCE","UNREGISTERED_SAME_TEXT_SLICE")
    add(family,1,"ROSTER_GATE","replace","/manifest/registered_slices/0/registered_path","/vendor/copy/syscalls.h","NATIVE_PROVENANCE","WRONG_REGISTERED_SOURCE_FILE")
    add(family,2,"ROSTER_GATE","replace","/manifest/registered_slices/0/byte_offset",1025,"NATIVE_PROVENANCE","WRONG_REGISTERED_SOURCE_OFFSET")
    add(family,3,"ROSTER_GATE","replace","/manifest/registered_slices/1/byte_offset",1024,"NATIVE_PROVENANCE","DUPLICATE_MATCHING_SOURCE_ROWS")
    add(family,4,"SEMANTIC_JOIN","replace","/call_join/declaration_binding_sha256",zero,"NATIVE_PROVENANCE","UNRELATED_DECLARATION_BINDING")
    add(family,5,"SEMANTIC_JOIN","replace","/manifest/registered_slices/22/profile","LINUX_AARCH64_LP64_LE","NATIVE_PROVENANCE","X86_TABLE_PROFILE_SPLICE")
    add(family,6,"SEMANTIC_JOIN","replace","/manifest/registered_slices/44/profile","LINUX_X86_64_LP64_LE","NATIVE_PROVENANCE","AARCH64_TABLE_PROFILE_SPLICE")
    add(family,7,"SEMANTIC_JOIN","replace","/manifest/declaration_bindings/0/architecture_mappings/0/uapi_number_u32",1001,"NATIVE_PROVENANCE","X86_UAPI_NUMBER_MISMATCH")
    add(family,8,"SEMANTIC_JOIN","replace","/manifest/declaration_bindings/0/architecture_mappings/1/uapi_number_u32",2001,"NATIVE_PROVENANCE","AARCH64_UAPI_NUMBER_MISMATCH")
    add(family,9,"SEMANTIC_JOIN","replace","/call_join/profile","LINUX_AARCH64_LP64_LE","NATIVE_PROVENANCE","CALL_PROFILE_MAPPING_MISMATCH")
    add(family,10,"HASH_GATE","replace","/call_join/syscall_table_slice_sha256",zero,"NATIVE_PROVENANCE","CALL_TABLE_SLICE_MISMATCH")
    add(family,11,"HASH_GATE","replace","/call_join/uapi_number_slice_sha256",zero,"NATIVE_PROVENANCE","CALL_UAPI_SLICE_MISMATCH")
    add(family,12,"HASH_GATE","replace","/call_join/declaration_slice_sha256",zero,"NATIVE_PROVENANCE","CALL_DECLARATION_SLICE_MISMATCH")
    add(family,13,"HASH_GATE","replace","/call_join/build_manifest_sha256",zero,"NATIVE_PROVENANCE","CALL_MANIFEST_SPLICE")
    add(family,14,"HASH_GATE","replace","/call_join/signature_core_sha256",zero,"NATIVE_PROVENANCE","CALL_SIGNATURE_ROW_SPLICE")
    add(family,15,"SCHEMA","replace","/semantic/projection/slots/0/value_schema","WINDOWS_FILE_ID","PROJECTION_TYPE","IDENTITY_SUBTYPE_MISMATCH")
    add(family,16,"SCHEMA","replace","/semantic/projection/slots/4/value_schema","ARBITRARY_JSON_ROWS","PROJECTION_TYPE","ROWS_SUBTYPE_UNREGISTERED")
    add(family,17,"SCHEMA","replace","/semantic/relation_atoms/0/operands",[copy.deepcopy(baseline["semantic"]["relation_atoms"][0]["operands"][0])],"RELATION_OPERATOR","OPERATOR_ARITY_MISMATCH")
    add(family,18,"SCHEMA","replace","/semantic/relation_atoms/3/operands/1/kind","ROWS","RELATION_OPERATOR","OPERATOR_OPERAND_KIND_MISMATCH")
    add(family,19,"SEMANTIC_JOIN","add","/semantic/no_return_return_terms/0",{"kind":"RETURN_STATUS"},"RELATION_OPERATOR","NO_RETURN_RETURN_TERM_UNRESOLVED")

    family="WINDOWS_RENAME_NEGATIVE"
    request=opfx+"/body/outer_evidence/request"
    add(family,0,"SCHEMA","replace",request+"/root_directory_u64",1,"WINDOWS_RENAME","ROOT_DIRECTORY_NON_NULL")
    add(family,1,"SCHEMA","replace",request+"/path_kind","RELATIVE_LEAF","WINDOWS_RENAME","FULL_PATH_REQUIRED")
    add(family,2,"SEMANTIC_JOIN","replace",request+"/file_name_length_u32",36,"WINDOWS_RENAME","FILENAME_LENGTH_INCLUDES_TERMINATOR")
    old_padding=baseline["effective_root"]["spawn_uncertainty"]["uncertain_post_operation"]["semantic_body"]["pre_clone_operations"][0]["body"]["outer_evidence"]["request"]["input_buffer_hex"]
    add(family,3,"SEMANTIC_JOIN","replace",request+"/input_buffer_hex",old_padding[:-2]+"01","WINDOWS_RENAME","NONZERO_PADDING_BYTE")
    add(family,4,"HASH_GATE","replace",opfx+"/body/projection/outer_evidence_body_sha256",zero,"PROJECTION_DERIVATION","WINDOWS_OBSERVATION_PROJECTION_SPLICE")
    add(family,5,"SEMANTIC_JOIN","remove","/platforms/2/loaded_runtime/observation/modules/2",None,"PLATFORM_DERIVATION","LOADED_RUNTIME_MODULE_ROSTER_MISMATCH")
    add(family,6,"HASH_GATE","replace","/platforms/2/loaded_runtime/observation/modules/1/module_file/sha256",zero,"PLATFORM_DERIVATION","LOADED_RUNTIME_MODULE_SPLICE")
    add(family,7,"SEMANTIC_JOIN","replace","/platforms/0/durability_observation/mount/filesystem_type","xfs","PLATFORM_DERIVATION","LINUX_FILESYSTEM_MOUNT_PROFILE_SPLICE")
    add(family,8,"SCHEMA","replace","/platforms/2/build_observation/observed/build","22621","PLATFORM_DERIVATION","WINDOWS_BUILD_COMPONENT_NOT_INTEGER")
    add(family,9,"SEMANTIC_JOIN","replace","/platforms/2/build_observation/observed_at_least_pinned_minimum",False,"PLATFORM_DERIVATION","WINDOWS_BUILD_BELOW_MINIMUM")
    add(family,10,"HASH_GATE","replace","/platforms/2/build_observation/source_module_sha256",zero,"PLATFORM_DERIVATION","WINDOWS_BUILD_SOURCE_MODULE_SPLICE")
    add(family,11,"SEMANTIC_JOIN","replace","/platforms/0/durability_observation/required_event_kinds_present",False,"PLATFORM_DERIVATION","LINUX_POWER_LOSS_DERIVATION_UNSATISFIED")
    add(family,12,"SEMANTIC_JOIN","replace",request+"/source_path_binding/leaf_reopen_file_id_sha256",zero,"WINDOWS_RENAME","SOURCE_PATH_HANDLE_MISMATCH")
    add(family,13,"SEMANTIC_JOIN","replace",request+"/destination_path_binding/destination_parent_file_id_sha256",zero,"WINDOWS_RENAME","DESTINATION_PATH_HANDLE_MISMATCH")
    add(family,14,"HASH_GATE","replace","/platforms/2/loaded_runtime/executed_production_binary/sha256",zero,"PLATFORM_DERIVATION","PLATFORM_BINARY_SPLICE")

    family="CROSS_SCHEMA_NEGATIVE"
    add(family,0,"SEMANTIC_JOIN","replace","/semantic/projection/complete",False,"PROJECTION_TOTALITY","COMPLETE_MISSING_INCONSISTENT")
    add(family,1,"SEMANTIC_JOIN","replace","/semantic/projection/missing_field_ordinals",[0],"PROJECTION_TOTALITY","MISSING_ORDINALS_NOT_DERIVED")
    add(family,2,"SEMANTIC_JOIN","replace","/semantic/projection/slots/1/field_ordinal",0,"PROJECTION_TOTALITY","PROJECTION_SLOT_ORDINAL_MISMATCH")
    add(family,3,"SEMANTIC_JOIN","replace","/semantic/projection/slots/0/slot_kind","MISSING_PRESENT_OVERLAP","PROJECTION_TOTALITY","PRESENT_MISSING_PARTITION_MISMATCH")
    add(family,4,"SEMANTIC_JOIN","remove","/semantic/symbols/bindings/0",None,"FRESH_SYMBOL","DECLARATION_BINDING_BIJECTION")
    add(family,5,"SEMANTIC_JOIN","add","/semantic/symbols/bindings/1",copy.deepcopy(baseline["semantic"]["symbols"]["bindings"][0]),"FRESH_SYMBOL","DECLARATION_BINDING_BIJECTION")
    add(family,6,"SEMANTIC_JOIN","replace","/semantic/symbols/bindings/0/actual_field_ordinal",1,"FRESH_SYMBOL","BINDING_AMBIGUOUS_FIELD")
    add(family,7,"SCHEMA","replace","/semantic/symbols/bindings/0/actual_value_schema","PIDFD_ID","FRESH_SYMBOL","BINDING_WRONG_SCHEMA")
    add(family,8,"HASH_GATE","replace","/semantic/symbols/bindings/0/actual_field_sha256",zero,"FRESH_SYMBOL","BINDING_STALE_FIELD")
    add(family,9,"SEMANTIC_JOIN","replace","/semantic/symbols/declarations/0/freshness_universe/source","ACTUAL","FRESH_SYMBOL","UNIVERSE_CROSS_SOURCE")
    add(family,10,"SCHEMA","replace","/semantic/symbols/declarations/0/freshness_universe/value_schema","ARBITRARY_ROWS","FRESH_SYMBOL","UNIVERSE_SCHEMA_MISMATCH")
    operation=baseline["effective_root"]["spawn_uncertainty"]["uncertain_post_operation"]["semantic_body"]["pre_clone_operations"][0]["operation"]
    add(family,11,"SCHEMA","replace",opfx+"/operation/operation_id","pfg3vnc-"+operation["operation_sha256"][:32],"OPERATION_IDENTITY","OPERATION_ID_PREFIX_MISMATCH")
    add(family,12,"HASH_GATE","replace",opfx+"/operation/operation_domain","PROGRAM_FACTS_G3_OPERATION_LINUX_RETURNED_V1","OPERATION_IDENTITY","BRANCH_DOMAIN_MISMATCH")
    add(family,13,"SCHEMA","replace",clonefx+"/operation/result_sha256",zero,"OPERATION_IDENTITY","NO_RETURN_RESULT_NOT_NULL")
    bad_hash=operation["operation_sha256"][:32]+("0"*32 if operation["operation_sha256"][32:]!="0"*32 else "1"*32)
    add(family,14,"HASH_GATE","replace",opfx+"/operation/operation_sha256",bad_hash,"OPERATION_IDENTITY","OPERATION_HASH_MISMATCH")
    receipt="/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt"
    add(family,15,"SEMANTIC_JOIN","replace",receipt+"/occurrences/0/operation/completion_kind","NO_RETURN","OPERATION_IDENTITY","CROSS_BRANCH_IDENTITY_SPLICE")
    add(family,16,"SCHEMA","replace",clonefx,"UNOBSERVABLE_AFTER_CRASH","EFFECTIVE_ROOT_COVERAGE","UNCERTAIN_CLONE_UNTYPED")
    add(family,17,"SEMANTIC_JOIN","replace",receipt+"/occurrence_count",1,"EFFECTIVE_ROOT_COVERAGE","EFFECTIVE_OCCURRENCE_OMISSION")
    add(family,18,"SEMANTIC_JOIN","replace",receipt+"/occurrences/1/occurrence_ordinal",0,"EFFECTIVE_ROOT_COVERAGE","EFFECTIVE_OCCURRENCE_DUPLICATE")
    add(family,19,"SEMANTIC_JOIN","replace",receipt+"/execution_join_count",1,"EFFECTIVE_ROOT_COVERAGE","EXECUTION_JOIN_OMISSION")
    add(family,20,"HASH_GATE","replace",receipt+"/execution_joins/0/operation_sha256",zero,"EFFECTIVE_ROOT_COVERAGE","UNRELATED_CONFORMANCE_RESULT")
    add(family,21,"SCHEMA","remove",receipt,None,"EFFECTIVE_ROOT_COVERAGE","POST_OPERATION_RECEIPT_MISSING")
    add(family,22,"SCHEMA","replace","/reviews/review_disposition","REPAIR","REVIEW_PASS_ONLY","REPAIR_REVIEW_REJECTED")
    add(family,23,"SEMANTIC_JOIN","replace","/reviews/profile_review_subject_sha256",zero,"REVIEW_PASS_ONLY","REVIEW_SUBJECT_MISMATCH")
    add(family,24,"SCHEMA","replace","/reviews/profile_body_has_review_member",True,"REVIEW_ACYCLICITY","PROFILE_RECEIPT_SELF_REFERENCE")
    add(family,25,"ROSTER_GATE","replace","/reviews/node_count",26,"REVIEW_DAG","REQUIRED_NODE_OMISSION")
    add(family,26,"ROSTER_GATE","replace","/reviews/edge_count",41,"REVIEW_DAG","REQUIRED_EDGE_OMISSION")
    add(family,27,"SCHEMA","replace","/reviews/nodes/20/artifact_type","PROFILE_RECEIPT_BODY","REVIEW_DAG","HOST_RECEIPT_TYPE_MISMATCH")
    add(family,28,"SEMANTIC_JOIN","replace","/aggregate/reviewed_profile_count",2,"AGGREGATE_TOTALITY","AGGREGATE_PROFILE_OMISSION")
    add(family,29,"SEMANTIC_JOIN","replace","/aggregate/profile_ordinals",[0,1,1],"AGGREGATE_TOTALITY","AGGREGATE_PROFILE_DUPLICATE")
    add(family,30,"SEMANTIC_JOIN","replace","/platforms/2/profile","LINUX_X86_64_LP64_LE","AGGREGATE_TOTALITY","CROSS_PROFILE_SPLICE")
    add(family,31,"HASH_GATE","replace","/aggregate/atomic_results/0/result_sha256",zero,"ATOMIC_RESULT","RESULT_HASH_SELF_REFERENCE")
    return specs
```
<!-- END R3_8_MUTATION_SPEC_SOURCE -->


The accepted baseline and the expanded real-mutation roster are frozen by the
following identities. The roster preserves every R3.7 family/ordinal and its
legacy pointer and diagnostic while binding it to an actual R3.8 path,
precondition, JSON Patch operation, complete mutated canonical subject, and
independent expected result.

<!-- BEGIN R3_8_ACCEPTED_BASELINE_AND_ROSTER_IDENTITY -->
```json
{"all_authority_and_enabling_false":true,"atomic_contract_result_count":2227,"baseline_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","baseline_size_bytes":830508,"baseline_validation":["ACCEPTED","MATERIALIZATION_BASELINE_VALID"],"dag_edge_count":42,"dag_node_count":27,"declaration_binding_count":22,"mutation_count":67,"mutation_family_counts":[20,15,32],"mutation_roster_canonical_sha256":"45500582e4127f6622773c6dabb820af6f0d7f1c0ba295e3a930659078ef674a","mutation_roster_canonical_size_bytes":72033,"mutation_roster_stream_sha256":"e7c360ed9730d9dde9c38130a1a5fa15da2f1a53d52de10df76b42516ea6b0aa","mutation_roster_stream_size_bytes":72032,"mutation_spec_source_sha256":"fb00a7e838b416e8a37167bb96fedee76057b454fcd78f3db6ed94a2b32b6db1","mutation_spec_source_size_bytes":11136,"platform_count":3,"profile_count":3,"registered_platform_policy_slice_count":1,"registered_slice_count":110,"schema_id":"plamen.program_facts.g3.r3_8.materialization_identity","validator_source_sha256":"830c5520545b817e6fd5d4ff26b8dfcfe124e5704fcd0d67722bc13fbf7b976b","validator_source_size_bytes":54888}
```
<!-- END R3_8_ACCEPTED_BASELINE_AND_ROSTER_IDENTITY -->

<!-- BEGIN VECTOR_R3_8_REAL_MUTATION_ROSTER -->
```json
[
{"atom_sha256":"0558d1613bf85b9f8364603e1fa07931d02d715756cfe0edc753175b0112b1c4","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"UNREGISTERED_SAME_TEXT_SLICE","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":0,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"UNREGISTERED_SAME_TEXT_SLICE","legacy_subject_pointer":"/manifest/registered_slices/declaration/registered","mutated_subject_sha256":"f53597ed786d93578b933712a4a31b46245f035643f55ae30fb5ba61f5e4bcf1","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-0558d1613bf85b9f8364603e1fa07931","ordinal":0,"patch":{"op":"replace","path":"/manifest/registered_slices/0/registered_file_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/manifest/registered_slices/0/registered_file_sha256","precondition_value_sha256":"99a79283b0f8a23e383e5c6d5170072b03d8e9274be32365242a1209445658d7","precondition_value_size_bytes":66,"validation_tier":"ROSTER_GATE"},
{"atom_sha256":"352d379237fc7304f050c884d91a6882961d01582aafaa40a16ff01c89c1edaf","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"WRONG_REGISTERED_SOURCE_FILE","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":1,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"WRONG_REGISTERED_SOURCE_FILE","legacy_subject_pointer":"/manifest/registered_slices/declaration/registered_path","mutated_subject_sha256":"2ba1e116d1ff56c43a8f816a15739f117a8f9d1add825d464a971e36f423d07d","mutated_subject_size_bytes":830502,"mutation_id":"pfg3m8-352d379237fc7304f050c884d91a6882","ordinal":1,"patch":{"op":"replace","path":"/manifest/registered_slices/0/registered_path","value":"/vendor/copy/syscalls.h"},"precondition_pointer":"/manifest/registered_slices/0/registered_path","precondition_value_sha256":"bd450ce42d8f7d4929f9396161504a9a67e1d5e2c2524f2695acfde5591704e2","precondition_value_size_bytes":31,"validation_tier":"ROSTER_GATE"},
{"atom_sha256":"a7f1b8ac6563cbdd692c4a06a6686b107d38a0279232297d890422c6418e0a78","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"WRONG_REGISTERED_SOURCE_OFFSET","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":2,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"WRONG_REGISTERED_SOURCE_OFFSET","legacy_subject_pointer":"/manifest/registered_slices/declaration/byte_offset","mutated_subject_sha256":"2cb0d49c95a73c802f770f9d0057d18c739ec84bda120db54d692f00eda79936","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-a7f1b8ac6563cbdd692c4a06a6686b10","ordinal":2,"patch":{"op":"replace","path":"/manifest/registered_slices/0/byte_offset","value":1025},"precondition_pointer":"/manifest/registered_slices/0/byte_offset","precondition_value_sha256":"e39eef82f61b21e2e7f762fcc4307358f165757f2e77ec855d6992f7e0191932","precondition_value_size_bytes":4,"validation_tier":"ROSTER_GATE"},
{"atom_sha256":"fc47ce7c8e56f0961affdd2b0c25c5e317d831e39fe31516b0072b767adfe2b6","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"DUPLICATE_MATCHING_SOURCE_ROWS","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":3,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"DUPLICATE_MATCHING_SOURCE_ROWS","legacy_subject_pointer":"/manifest/registered_slices/declaration/matching_row_count","mutated_subject_sha256":"692ba9010937b6482d2e64d129dc3f8ba41193621e39adf86137eacd4eb628a9","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-fc47ce7c8e56f0961affdd2b0c25c5e3","ordinal":3,"patch":{"op":"replace","path":"/manifest/registered_slices/1/byte_offset","value":1024},"precondition_pointer":"/manifest/registered_slices/1/byte_offset","precondition_value_sha256":"9dacbde326501c9f63debf4311ae5e2bc047636edc4ee9d9ce828bcdf4a7f25d","precondition_value_size_bytes":4,"validation_tier":"ROSTER_GATE"},
{"atom_sha256":"8dd2a49156917ab76389d18ead3e04b27153036cc5eb02d7e8af8a2ae246976a","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"UNRELATED_DECLARATION_BINDING","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":4,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"UNRELATED_DECLARATION_BINDING","legacy_subject_pointer":"/call/declaration_join/declaration_binding_sha256","mutated_subject_sha256":"85fbd67cdc39def16165a95391773477e4b05807ca0a3e7813d2bfa409ea6324","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-8dd2a49156917ab76389d18ead3e04b2","ordinal":4,"patch":{"op":"replace","path":"/call_join/declaration_binding_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/call_join/declaration_binding_sha256","precondition_value_sha256":"cb6b19e932cb8658768db29fbc28ce0f533a6e01436570ba4e522a1f83f62313","precondition_value_size_bytes":66,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"ffa2a39555d59571885b90ebb20e2d374ca23e7d4491ddbd7746ff9d68bd1a9d","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"X86_TABLE_PROFILE_SPLICE","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":5,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"X86_TABLE_PROFILE_SPLICE","legacy_subject_pointer":"/manifest/x86_64_table/profile","mutated_subject_sha256":"844b3099d39d567bcf8439a3b3531500757a9a68aab8f16b87531fdbb1d89315","mutated_subject_size_bytes":830509,"mutation_id":"pfg3m8-ffa2a39555d59571885b90ebb20e2d37","ordinal":5,"patch":{"op":"replace","path":"/manifest/registered_slices/22/profile","value":"LINUX_AARCH64_LP64_LE"},"precondition_pointer":"/manifest/registered_slices/22/profile","precondition_value_sha256":"1f2f4278cff8a058dc0e0e11cc858b45bcc14ed6205071b1cf1250fc0a54e2e7","precondition_value_size_bytes":22,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"c1989a6272f3d7acb2a7a43a5236d6f8dab83f2cee9a4a2a7abfd17e6a232696","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"AARCH64_TABLE_PROFILE_SPLICE","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":6,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"AARCH64_TABLE_PROFILE_SPLICE","legacy_subject_pointer":"/manifest/aarch64_table/profile","mutated_subject_sha256":"c5d3b713203204105242641ada72aad443a8c054a9019bff86334e8385063169","mutated_subject_size_bytes":830507,"mutation_id":"pfg3m8-c1989a6272f3d7acb2a7a43a5236d6f8","ordinal":6,"patch":{"op":"replace","path":"/manifest/registered_slices/44/profile","value":"LINUX_X86_64_LP64_LE"},"precondition_pointer":"/manifest/registered_slices/44/profile","precondition_value_sha256":"14f0166d4b59852b1bd92a21bcd6ebbecacbcbabd266f5699e47149fede1b3cd","precondition_value_size_bytes":23,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"f6c6366642116dc9c501741f2b2d799d6d97f215e267dadade66c969a6c34ff4","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"X86_UAPI_NUMBER_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":7,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"X86_UAPI_NUMBER_MISMATCH","legacy_subject_pointer":"/manifest/x86_64_mapping/numbers_equal","mutated_subject_sha256":"82e8ee37453bf64dba614a41330e6a81cb013277853d8eef24742bfcfd205df4","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-f6c6366642116dc9c501741f2b2d799d","ordinal":7,"patch":{"op":"replace","path":"/manifest/declaration_bindings/0/architecture_mappings/0/uapi_number_u32","value":1001},"precondition_pointer":"/manifest/declaration_bindings/0/architecture_mappings/0/uapi_number_u32","precondition_value_sha256":"40510175845988f13f6162ed8526f0b09f73384467fa855e1e79b44a56562a58","precondition_value_size_bytes":4,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"50518f7bd82a22160e4fbcda3fb274d9978e02718ac6af7023bdaa7a2a1b9ff4","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"AARCH64_UAPI_NUMBER_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":8,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"AARCH64_UAPI_NUMBER_MISMATCH","legacy_subject_pointer":"/manifest/aarch64_mapping/numbers_equal","mutated_subject_sha256":"89a239da6e068b0492436541afb6fde48507e9ab773c6ebe0b33dec0c76cf0d7","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-50518f7bd82a22160e4fbcda3fb274d9","ordinal":8,"patch":{"op":"replace","path":"/manifest/declaration_bindings/0/architecture_mappings/1/uapi_number_u32","value":2001},"precondition_pointer":"/manifest/declaration_bindings/0/architecture_mappings/1/uapi_number_u32","precondition_value_sha256":"81a83544cf93c245178cbc1620030f1123f435af867c79d87135983c52ab39d9","precondition_value_size_bytes":4,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"adac6f96683271b90bd0fbc9a57d780c5088837ea5b36f1ea57af6aa4bc66f8f","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"CALL_PROFILE_MAPPING_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":9,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"CALL_PROFILE_MAPPING_MISMATCH","legacy_subject_pointer":"/call/declaration_join/profile","mutated_subject_sha256":"b690eb2b00e185a19311309b0f292d04c3e1c2fa302c6b908e6b204d1d7fd4ee","mutated_subject_size_bytes":830509,"mutation_id":"pfg3m8-adac6f96683271b90bd0fbc9a57d780c","ordinal":9,"patch":{"op":"replace","path":"/call_join/profile","value":"LINUX_AARCH64_LP64_LE"},"precondition_pointer":"/call_join/profile","precondition_value_sha256":"1f2f4278cff8a058dc0e0e11cc858b45bcc14ed6205071b1cf1250fc0a54e2e7","precondition_value_size_bytes":22,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"62629b15755572978864547d3b25a41f6c98e1e5d9ea2850f7569f2a0df567b9","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"CALL_TABLE_SLICE_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":10,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"CALL_TABLE_SLICE_MISMATCH","legacy_subject_pointer":"/call/declaration_join/syscall_table_slice_sha256","mutated_subject_sha256":"b9941d25f0e4256914ffc9b5a227bd52835f643f2f7828ff21b987eac93a458d","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-62629b15755572978864547d3b25a41f","ordinal":10,"patch":{"op":"replace","path":"/call_join/syscall_table_slice_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/call_join/syscall_table_slice_sha256","precondition_value_sha256":"ddf37ee8e672e09dad663a58c1653b7ef5ad1852a8dd04b12310b4f32681182e","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"bbe5db93d3907c78f19b5e37bc4582e6c4cb069919108e90c52f087e557f3d27","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"CALL_UAPI_SLICE_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":11,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"CALL_UAPI_SLICE_MISMATCH","legacy_subject_pointer":"/call/declaration_join/uapi_number_slice_sha256","mutated_subject_sha256":"084be0fe65e100d1e4e53f9d1e2de75d20bd3a47edb54ff7521d9efee210b961","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-bbe5db93d3907c78f19b5e37bc4582e6","ordinal":11,"patch":{"op":"replace","path":"/call_join/uapi_number_slice_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/call_join/uapi_number_slice_sha256","precondition_value_sha256":"fa989e17a8a50533df85a39502d42ffb35dfbe505997ca71dcfff37bcd703e56","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"7e0f4fbfe65e29eb4e16eece652d14c4fe7b6ba8874b5ad478d324530c5a3d90","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"CALL_DECLARATION_SLICE_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":12,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"CALL_DECLARATION_SLICE_MISMATCH","legacy_subject_pointer":"/call/declaration_join/declaration_slice_sha256","mutated_subject_sha256":"0cef2fe6a6afa1f901595c4c59997521926f829c524f49b814dc45292476723f","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-7e0f4fbfe65e29eb4e16eece652d14c4","ordinal":12,"patch":{"op":"replace","path":"/call_join/declaration_slice_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/call_join/declaration_slice_sha256","precondition_value_sha256":"892715cb8722156e2e81c867c3116cb49e025a1d1ca868ff70a0c3b2c54499b3","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"0be92b32f93105f613e465274c954e473d936a911b025a55dded45bbd7d19e1e","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"CALL_MANIFEST_SPLICE","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":13,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"CALL_MANIFEST_SPLICE","legacy_subject_pointer":"/call/declaration_join/build_manifest_sha256","mutated_subject_sha256":"3ea5b5fe6d1e732ae94ff91a0673467d85b80d74e8dd87afeab10cb154efb394","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-0be92b32f93105f613e465274c954e47","ordinal":13,"patch":{"op":"replace","path":"/call_join/build_manifest_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/call_join/build_manifest_sha256","precondition_value_sha256":"a1cf7cba78fd88de3d70c93fb06d9f4e3c7c9a839907773eb918a013aad8ebe8","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"59dccc1584cd452df3fb06f01fabfcf033a1da8d815c378a088f667e44092703","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"NATIVE_PROVENANCE","expected_subcode":"CALL_SIGNATURE_ROW_SPLICE","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":14,"legacy_expected_primary":"NATIVE_PROVENANCE","legacy_expected_subcode":"CALL_SIGNATURE_ROW_SPLICE","legacy_subject_pointer":"/call/declaration_join/signature_core_row_sha256","mutated_subject_sha256":"b034953196037bba74fe2734e7ef09c26bf123439b8109aaa7d9183bffd8d012","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-59dccc1584cd452df3fb06f01fabfcf0","ordinal":14,"patch":{"op":"replace","path":"/call_join/signature_core_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/call_join/signature_core_sha256","precondition_value_sha256":"72c18ec69f7550a107413a9b314edc003ecdf47954300aa165bfc9b029260edb","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"5ef28ce73e4845173a6483d92250535af14d0602ae85916cba363af3cc125f0d","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PROJECTION_TYPE","expected_subcode":"IDENTITY_SUBTYPE_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":15,"legacy_expected_primary":"PROJECTION_TYPE","legacy_expected_subcode":"IDENTITY_SUBTYPE_MISMATCH","legacy_subject_pointer":"/projection/identity/value_schema","mutated_subject_sha256":"df2c0d1374b85942993e103b9fe6bc12477999a2b43fb26b3ce8fa1fd5ccfa2a","mutated_subject_size_bytes":830510,"mutation_id":"pfg3m8-5ef28ce73e4845173a6483d92250535a","ordinal":15,"patch":{"op":"replace","path":"/semantic/projection/slots/0/value_schema","value":"WINDOWS_FILE_ID"},"precondition_pointer":"/semantic/projection/slots/0/value_schema","precondition_value_sha256":"e8e56eac85e3307e92a65bc7f909601cb3afd863dce7ba636ddc752eaad389df","precondition_value_size_bytes":15,"validation_tier":"SCHEMA"},
{"atom_sha256":"b6730317d482ff853ca71a5eb50dda65af02d4853f7daf10fb82e445213271e0","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PROJECTION_TYPE","expected_subcode":"ROWS_SUBTYPE_UNREGISTERED","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":16,"legacy_expected_primary":"PROJECTION_TYPE","legacy_expected_subcode":"ROWS_SUBTYPE_UNREGISTERED","legacy_subject_pointer":"/projection/rows/value_schema","mutated_subject_sha256":"014cda0088ba97bcf71da7e5b999e5350f6b248ff9ca504dcd40e87bae7bf3dc","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-b6730317d482ff853ca71a5eb50dda65","ordinal":16,"patch":{"op":"replace","path":"/semantic/projection/slots/4/value_schema","value":"ARBITRARY_JSON_ROWS"},"precondition_pointer":"/semantic/projection/slots/4/value_schema","precondition_value_sha256":"ebe25130fbeaa904a3f513b83621705eb3e8ea3b1fa2b174233838410bcb982a","precondition_value_size_bytes":21,"validation_tier":"SCHEMA"},
{"atom_sha256":"5135267d8b77030698fe911b9724a59bd65c92caaa93054a27a8eb387fce5735","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"RELATION_OPERATOR","expected_subcode":"OPERATOR_ARITY_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":17,"legacy_expected_primary":"RELATION_OPERATOR","legacy_expected_subcode":"OPERATOR_ARITY_MISMATCH","legacy_subject_pointer":"/predicate/atoms/eq/operand_count","mutated_subject_sha256":"7c841749dfbe22d592f665c06b590673abd2d9dfb833d56d263bae3b8901a506","mutated_subject_size_bytes":830414,"mutation_id":"pfg3m8-5135267d8b77030698fe911b9724a59b","ordinal":17,"patch":{"op":"replace","path":"/semantic/relation_atoms/0/operands","value":[{"field_ordinal":0,"kind":"FIELD","source":"ACTUAL"}]},"precondition_pointer":"/semantic/relation_atoms/0/operands","precondition_value_sha256":"35d5fca8245f8761f42f36c58dbeae5928cf676729d213409da5d26041095e75","precondition_value_size_bytes":148,"validation_tier":"SCHEMA"},
{"atom_sha256":"5160855c07f0c199cb8e4b30ecdd7a1b854af09d64b0f6691204fec7226e5a79","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"RELATION_OPERATOR","expected_subcode":"OPERATOR_OPERAND_KIND_MISMATCH","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":18,"legacy_expected_primary":"RELATION_OPERATOR","legacy_expected_subcode":"OPERATOR_OPERAND_KIND_MISMATCH","legacy_subject_pointer":"/predicate/atoms/prefix/right_kind","mutated_subject_sha256":"9f267ca7032f822419b6c13b2f2213a06c6d320de7dbcb763907dc8cd4fed6d2","mutated_subject_size_bytes":830507,"mutation_id":"pfg3m8-5160855c07f0c199cb8e4b30ecdd7a1b","ordinal":18,"patch":{"op":"replace","path":"/semantic/relation_atoms/3/operands/1/kind","value":"ROWS"},"precondition_pointer":"/semantic/relation_atoms/3/operands/1/kind","precondition_value_sha256":"208a7d40146cfa3a4b423da90ba2c43eea58c75d9c1865e25fdc44e5aafa9908","precondition_value_size_bytes":7,"validation_tier":"SCHEMA"},
{"atom_sha256":"bfc0e64b52f17b54dfaa0f3a24c1ccbe410700d1e01ee7271da17ad83ba5fb38","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"RELATION_OPERATOR","expected_subcode":"NO_RETURN_RETURN_TERM_UNRESOLVED","family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":19,"legacy_expected_primary":"RELATION_OPERATOR","legacy_expected_subcode":"NO_RETURN_RETURN_TERM_UNRESOLVED","legacy_subject_pointer":"/no_return/predicate/return_term_count","mutated_subject_sha256":"56b2e80af39b071128bc068c0bb91deafefe3225322babc3cb06c6e4eedc71a9","mutated_subject_size_bytes":830532,"mutation_id":"pfg3m8-bfc0e64b52f17b54dfaa0f3a24c1ccbe","ordinal":19,"patch":{"op":"add","path":"/semantic/no_return_return_terms/0","value":{"kind":"RETURN_STATUS"}},"precondition_pointer":"/semantic/no_return_return_terms","precondition_value_sha256":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945","precondition_value_size_bytes":2,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"ea2685adeb34464d3bdf7f676f26b69c124d58ff7f2bea5c4542426955901a0a","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"WINDOWS_RENAME","expected_subcode":"ROOT_DIRECTORY_NON_NULL","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":20,"legacy_expected_primary":"WINDOWS_RENAME","legacy_expected_subcode":"ROOT_DIRECTORY_NON_NULL","legacy_subject_pointer":"/windows/request/root_directory_u64","mutated_subject_sha256":"b64604ab753b801168d71e2c2f04fa41097c93d79ee0081f3640cd5c913e0715","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-ea2685adeb34464d3bdf7f676f26b69c","ordinal":0,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/root_directory_u64","value":1},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/root_directory_u64","precondition_value_sha256":"5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9","precondition_value_size_bytes":1,"validation_tier":"SCHEMA"},
{"atom_sha256":"5cc16302b4433a8b1517a93f94cb7ac194ff22a9bb95055fe0ad6ba8d88ea7ba","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"WINDOWS_RENAME","expected_subcode":"FULL_PATH_REQUIRED","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":21,"legacy_expected_primary":"WINDOWS_RENAME","legacy_expected_subcode":"FULL_PATH_REQUIRED","legacy_subject_pointer":"/windows/request/path_kind","mutated_subject_sha256":"35a31cfbd3d2697fb6bad5a0c283e4311d497d967a63f31395274dae40151454","mutated_subject_size_bytes":830500,"mutation_id":"pfg3m8-5cc16302b4433a8b1517a93f94cb7ac1","ordinal":1,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/path_kind","value":"RELATIVE_LEAF"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/path_kind","precondition_value_sha256":"e2ea5d834ba83437513a7e86817f9418bab85883a27d0d8c31f62aa806bb4c28","precondition_value_size_bytes":23,"validation_tier":"SCHEMA"},
{"atom_sha256":"e4e17922886a9ba2bdaf01b65fa05ddb98b0aeabdc35173b0379f3388d238a13","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"WINDOWS_RENAME","expected_subcode":"FILENAME_LENGTH_INCLUDES_TERMINATOR","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":22,"legacy_expected_primary":"WINDOWS_RENAME","legacy_expected_subcode":"FILENAME_LENGTH_INCLUDES_TERMINATOR","legacy_subject_pointer":"/windows/request/length_excludes_terminator","mutated_subject_sha256":"328d4944fd6a6301f0b8e23b372a4a688f616c2264f8182972a1bdc3064e0940","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-e4e17922886a9ba2bdaf01b65fa05ddb","ordinal":2,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/file_name_length_u32","value":36},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/file_name_length_u32","precondition_value_sha256":"86e50149658661312a9e0b35558d84f6c6d3da797f552a9657fe0558ca40cdef","precondition_value_size_bytes":2,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"b54ec3057a526298ecd6146f78cadc0eabb22ed93c478f8b4abbc59d4cde25ad","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"WINDOWS_RENAME","expected_subcode":"NONZERO_PADDING_BYTE","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":23,"legacy_expected_primary":"WINDOWS_RENAME","legacy_expected_subcode":"NONZERO_PADDING_BYTE","legacy_subject_pointer":"/windows/request/all_padding_zero","mutated_subject_sha256":"1574a53ccbc5c05f9af9a8d355f61b86c4bde891a5f68d3a5f07eeb1b4272c3f","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-b54ec3057a526298ecd6146f78cadc0e","ordinal":3,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/input_buffer_hex","value":"00000000000000000000000000000000000000005c005c003f005c0056006f006c0075006d0065007b0031007d005c00640073007400000000000001"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/input_buffer_hex","precondition_value_sha256":"b4da86cdfb1f8fe1b69fa9647705581c56a3e3d6d5c875609e4a35fb1d32bb66","precondition_value_size_bytes":122,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"aba17a9bd9d865c0cbdcb8acaf55d73f45036db38cbbec09150370d8e9a2bf57","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PROJECTION_DERIVATION","expected_subcode":"WINDOWS_OBSERVATION_PROJECTION_SPLICE","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":24,"legacy_expected_primary":"PROJECTION_DERIVATION","legacy_expected_subcode":"WINDOWS_OBSERVATION_PROJECTION_SPLICE","legacy_subject_pointer":"/windows/projection/source_observation_sha256","mutated_subject_sha256":"841509d96bd3d92f9bc0aa17f5ad53f4784d4aa0a45a60f5f64211256ec29185","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-aba17a9bd9d865c0cbdcb8acaf55d73f","ordinal":4,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/projection/outer_evidence_body_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/projection/outer_evidence_body_sha256","precondition_value_sha256":"b1b3ad1ed523c8a96256612dc21c97a48de9d1f638366cd5a4e1dc57577754aa","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"4d03c1fb13d8d2857e0cfb0aa31267368dc75b1581256085444fe59efaba1168","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PLATFORM_DERIVATION","expected_subcode":"LOADED_RUNTIME_MODULE_ROSTER_MISMATCH","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":25,"legacy_expected_primary":"PLATFORM_DERIVATION","legacy_expected_subcode":"LOADED_RUNTIME_MODULE_OMISSION","legacy_subject_pointer":"/windows/loaded_runtime/module_roles","mutated_subject_sha256":"fcf6c9fca36b9c26967f315aadfba0f464465658a7619f5f1215f3edd9fce374","mutated_subject_size_bytes":830194,"mutation_id":"pfg3m8-4d03c1fb13d8d2857e0cfb0aa3126736","ordinal":5,"patch":{"op":"remove","path":"/platforms/2/loaded_runtime/observation/modules/2"},"precondition_pointer":"/platforms/2/loaded_runtime/observation/modules/2","precondition_value_sha256":"0d1aa02ca421ae3698a14e94c7ddbd73973d718192a10758e1cd405717340cdd","precondition_value_size_bytes":313,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"c9650039f0801dd8a24095218ab0fe870d8f468a8d382a82cc4c961978d64857","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PLATFORM_DERIVATION","expected_subcode":"LOADED_RUNTIME_MODULE_SPLICE","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":26,"legacy_expected_primary":"PLATFORM_DERIVATION","legacy_expected_subcode":"LOADED_RUNTIME_MODULE_SPLICE","legacy_subject_pointer":"/windows/loaded_runtime/ntdll_file","mutated_subject_sha256":"42cda8d9071639d3504732bd1b895ba792eaeb6e9908b53343a64e8dbf4f6c89","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-c9650039f0801dd8a24095218ab0fe87","ordinal":6,"patch":{"op":"replace","path":"/platforms/2/loaded_runtime/observation/modules/1/module_file/sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/platforms/2/loaded_runtime/observation/modules/1/module_file/sha256","precondition_value_sha256":"7049d9e9cfffd5617fcfd3b9e16c7916d99afd1f299e1103a7ff6d764165664a","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"26e69f1accafb0f7e5347a6d3adf1bb0c7d243ec2ce632d2d693e7858562829c","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PLATFORM_DERIVATION","expected_subcode":"LINUX_FILESYSTEM_MOUNT_PROFILE_SPLICE","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":27,"legacy_expected_primary":"PLATFORM_DERIVATION","legacy_expected_subcode":"LINUX_FILESYSTEM_MOUNT_PROFILE_SPLICE","legacy_subject_pointer":"/linux/durability/profile/filesystem_mount_join","mutated_subject_sha256":"5bb97ffc12f5890f232f9ad146f83a7865ea35d561b75c1331ca58ee0e1d346f","mutated_subject_size_bytes":830507,"mutation_id":"pfg3m8-26e69f1accafb0f7e5347a6d3adf1bb0","ordinal":7,"patch":{"op":"replace","path":"/platforms/0/durability_observation/mount/filesystem_type","value":"xfs"},"precondition_pointer":"/platforms/0/durability_observation/mount/filesystem_type","precondition_value_sha256":"c07d1a0724004283402caaa880a47e57d947fcf15189a7b0a5a4add091ae56c7","precondition_value_size_bytes":6,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"c3de581fd74d5721b57a477f512c3e64370ca4906cadc07aee6938f76da5b639","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PLATFORM_DERIVATION","expected_subcode":"WINDOWS_BUILD_COMPONENT_NOT_INTEGER","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":28,"legacy_expected_primary":"PLATFORM_DERIVATION","legacy_expected_subcode":"WINDOWS_BUILD_COMPONENT_NOT_INTEGER","legacy_subject_pointer":"/windows/build/observed/build","mutated_subject_sha256":"6ee8f352bb356a2447dc474cd91a6051e85b85a6eca5fc989fba3e85d6ad9761","mutated_subject_size_bytes":830510,"mutation_id":"pfg3m8-c3de581fd74d5721b57a477f512c3e64","ordinal":8,"patch":{"op":"replace","path":"/platforms/2/build_observation/observed/build","value":"22621"},"precondition_pointer":"/platforms/2/build_observation/observed/build","precondition_value_sha256":"36b212ef149cc79e63eb109177f831812969fa8e86f9c09b405448276b0ec76f","precondition_value_size_bytes":5,"validation_tier":"SCHEMA"},
{"atom_sha256":"0fdb01c44ed2b2498cdfeb9af46d1d472116a37894718fb5032bffc56656143e","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PLATFORM_DERIVATION","expected_subcode":"WINDOWS_BUILD_BELOW_MINIMUM","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":29,"legacy_expected_primary":"PLATFORM_DERIVATION","legacy_expected_subcode":"WINDOWS_BUILD_BELOW_MINIMUM","legacy_subject_pointer":"/windows/build/observed_at_least_minimum","mutated_subject_sha256":"1f4295d93e058d6c0de0256756912c1932935bd58779c0ab60a238bb1eaf8bcc","mutated_subject_size_bytes":830509,"mutation_id":"pfg3m8-0fdb01c44ed2b2498cdfeb9af46d1d47","ordinal":9,"patch":{"op":"replace","path":"/platforms/2/build_observation/observed_at_least_pinned_minimum","value":false},"precondition_pointer":"/platforms/2/build_observation/observed_at_least_pinned_minimum","precondition_value_sha256":"b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b","precondition_value_size_bytes":4,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"193dbe8d4d8c0fe93c1462e7b62d598e97ab68aac37010b7ba85efd29779128c","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PLATFORM_DERIVATION","expected_subcode":"WINDOWS_BUILD_SOURCE_MODULE_SPLICE","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":30,"legacy_expected_primary":"PLATFORM_DERIVATION","legacy_expected_subcode":"WINDOWS_BUILD_SOURCE_MODULE_SPLICE","legacy_subject_pointer":"/windows/build/source_module_sha256","mutated_subject_sha256":"edde06cc18ab05a96b7949d9d6f0bd37539d84fc457c285a7fe00c44dd2658fe","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-193dbe8d4d8c0fe93c1462e7b62d598e","ordinal":10,"patch":{"op":"replace","path":"/platforms/2/build_observation/source_module_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/platforms/2/build_observation/source_module_sha256","precondition_value_sha256":"96b5e9340f3a6b2e858e7fd8bd49ef0fa7d1e9f77bd120835846c9738ad42602","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"32325b1d37a1b5e237a9f76273d9cb12cec3ae154958094eac2fa5458a28edf0","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PLATFORM_DERIVATION","expected_subcode":"LINUX_POWER_LOSS_DERIVATION_UNSATISFIED","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":31,"legacy_expected_primary":"PLATFORM_DERIVATION","legacy_expected_subcode":"LINUX_POWER_LOSS_DERIVATION_UNSATISFIED","legacy_subject_pointer":"/linux/durability/derivation_inputs_all_satisfied","mutated_subject_sha256":"7728c5e9b8be6da50feb72f6d3ca53cd4a0d7c6009d4735b9f7b1eaabebec805","mutated_subject_size_bytes":830509,"mutation_id":"pfg3m8-32325b1d37a1b5e237a9f76273d9cb12","ordinal":11,"patch":{"op":"replace","path":"/platforms/0/durability_observation/required_event_kinds_present","value":false},"precondition_pointer":"/platforms/0/durability_observation/required_event_kinds_present","precondition_value_sha256":"b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b","precondition_value_size_bytes":4,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"ca08332b13b47ffbdd060b1dfd4f15f286c3ac1b13bf7678edd14970134d86f5","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"WINDOWS_RENAME","expected_subcode":"SOURCE_PATH_HANDLE_MISMATCH","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":32,"legacy_expected_primary":"WINDOWS_RENAME","legacy_expected_subcode":"SOURCE_PATH_HANDLE_MISMATCH","legacy_subject_pointer":"/windows/request/source_path_binding_matches_handle","mutated_subject_sha256":"cb6314e9313047241fc418cd9711c77c0bdaccb9db4d65f8281bb0c8a467bedf","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-ca08332b13b47ffbdd060b1dfd4f15f2","ordinal":12,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/source_path_binding/leaf_reopen_file_id_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/source_path_binding/leaf_reopen_file_id_sha256","precondition_value_sha256":"276f997c7a438c8545a8dad6519aacbe08931987f1663372d3c9dfa6b5abf804","precondition_value_size_bytes":66,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"d8fd177b3d005c52f812114bcc0ae896e629cf97c6e3dae887baf411dc0a4143","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"WINDOWS_RENAME","expected_subcode":"DESTINATION_PATH_HANDLE_MISMATCH","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":33,"legacy_expected_primary":"WINDOWS_RENAME","legacy_expected_subcode":"DESTINATION_PATH_HANDLE_MISMATCH","legacy_subject_pointer":"/windows/request/destination_path_binding_matches_handle","mutated_subject_sha256":"8a418111e064d183d94ef6e1c56f19e40b4ffdd09b4012a1bf2b8f78a5d02872","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-d8fd177b3d005c52f812114bcc0ae896","ordinal":13,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/destination_path_binding/destination_parent_file_id_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/body/outer_evidence/request/destination_path_binding/destination_parent_file_id_sha256","precondition_value_sha256":"b1076d6297eadde60165431d24065cb7e5486754d25cd4d0d0624bbfc2da9858","precondition_value_size_bytes":66,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"bcab9d4d34daa6846c17dbdfdfb78dbfd451be417bbed92e081b23e9fc96eb29","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PLATFORM_DERIVATION","expected_subcode":"PLATFORM_BINARY_SPLICE","family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":34,"legacy_expected_primary":"PLATFORM_DERIVATION","legacy_expected_subcode":"PLATFORM_BINARY_SPLICE","legacy_subject_pointer":"/windows/evidence/executed_production_binary","mutated_subject_sha256":"2995e662da4200b6d3a03d6b3d7fe2c07450445421037b7086cca52cab3778f9","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-bcab9d4d34daa6846c17dbdfdfb78dbf","ordinal":14,"patch":{"op":"replace","path":"/platforms/2/loaded_runtime/executed_production_binary/sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/platforms/2/loaded_runtime/executed_production_binary/sha256","precondition_value_sha256":"b3f44b057ca6cbceee6de0ca8a289afc904cc59da3ac93e6fb376c80bc3a4054","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"d0b0ab909f59b3860a5d7dd886fcade1919df0d756d8db9f78e586d0ca838905","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PROJECTION_TOTALITY","expected_subcode":"COMPLETE_MISSING_INCONSISTENT","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":35,"legacy_expected_primary":"PROJECTION_TOTALITY","legacy_expected_subcode":"COMPLETE_MISSING_INCONSISTENT","legacy_subject_pointer":"/projection/complete","mutated_subject_sha256":"2d9b46b14b5d192883b3802b2729cb2435958df04d59575cf17b0ab61a831089","mutated_subject_size_bytes":830509,"mutation_id":"pfg3m8-d0b0ab909f59b3860a5d7dd886fcade1","ordinal":0,"patch":{"op":"replace","path":"/semantic/projection/complete","value":false},"precondition_pointer":"/semantic/projection/complete","precondition_value_sha256":"b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b","precondition_value_size_bytes":4,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"5a8d82911ac086dad1a38d81aad84338af2313e7beefa413fbb2d6440d33c6ff","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PROJECTION_TOTALITY","expected_subcode":"MISSING_ORDINALS_NOT_DERIVED","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":36,"legacy_expected_primary":"PROJECTION_TOTALITY","legacy_expected_subcode":"MISSING_ORDINALS_NOT_DERIVED","legacy_subject_pointer":"/projection/missing_field_ordinals","mutated_subject_sha256":"92becd2e62c2e25444a55d850014ed97518482dfb0e35aac71cc6813e0cc2d6c","mutated_subject_size_bytes":830509,"mutation_id":"pfg3m8-5a8d82911ac086dad1a38d81aad84338","ordinal":1,"patch":{"op":"replace","path":"/semantic/projection/missing_field_ordinals","value":[0]},"precondition_pointer":"/semantic/projection/missing_field_ordinals","precondition_value_sha256":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945","precondition_value_size_bytes":2,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"a9bf3d6cd19cecc2bae678465015d9933a35598af606829b5932369bffe8f9b9","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PROJECTION_TOTALITY","expected_subcode":"PROJECTION_SLOT_ORDINAL_MISMATCH","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":37,"legacy_expected_primary":"PROJECTION_TOTALITY","legacy_expected_subcode":"DUPLICATE_PROJECTION_SLOT","legacy_subject_pointer":"/projection/slot_ordinals","mutated_subject_sha256":"95499ed2573b65be951cd197f0137b9c2ac419236087067cf2bc00b9c5edf6e7","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-a9bf3d6cd19cecc2bae678465015d993","ordinal":2,"patch":{"op":"replace","path":"/semantic/projection/slots/1/field_ordinal","value":0},"precondition_pointer":"/semantic/projection/slots/1/field_ordinal","precondition_value_sha256":"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b","precondition_value_size_bytes":1,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"01dc69a6e117e66f7ba9968ddfe4888d98af01080708a407ff0714221f64a0d3","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"PROJECTION_TOTALITY","expected_subcode":"PRESENT_MISSING_PARTITION_MISMATCH","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":38,"legacy_expected_primary":"PROJECTION_TOTALITY","legacy_expected_subcode":"PRESENT_MISSING_OVERLAP","legacy_subject_pointer":"/projection/present_missing_disjoint","mutated_subject_sha256":"3166ccb4505532cbe97c4840740b09c93cc46eac3721b1065f4bb773c660b76b","mutated_subject_size_bytes":830524,"mutation_id":"pfg3m8-01dc69a6e117e66f7ba9968ddfe4888d","ordinal":3,"patch":{"op":"replace","path":"/semantic/projection/slots/0/slot_kind","value":"MISSING_PRESENT_OVERLAP"},"precondition_pointer":"/semantic/projection/slots/0/slot_kind","precondition_value_sha256":"9da8908141cb75e8f2d25d0439109c850d2bbe1f22175aecd6147ae783344e33","precondition_value_size_bytes":9,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"8be8e3b8b8d8742ea23a8a5b0f8b5987475cccd341168b1d7699b581b8840985","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"FRESH_SYMBOL","expected_subcode":"DECLARATION_BINDING_BIJECTION","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":39,"legacy_expected_primary":"FRESH_SYMBOL","legacy_expected_subcode":"BINDING_OMISSION","legacy_subject_pointer":"/fresh_symbols/binding_ordinals","mutated_subject_sha256":"17af98e5708acb7d24e36d9858ce39c7e062879637055e8178d00dca2777d774","mutated_subject_size_bytes":830066,"mutation_id":"pfg3m8-8be8e3b8b8d8742ea23a8a5b0f8b5987","ordinal":4,"patch":{"op":"remove","path":"/semantic/symbols/bindings/0"},"precondition_pointer":"/semantic/symbols/bindings/0","precondition_value_sha256":"7dc1c369362fdd051fdb867d7e5da5ab1346ee07c785b4e21f6c419de0b71bca","precondition_value_size_bytes":442,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"289ea814c3d60125077f23b1aa4e122a521258684a06cfa757f90fdb7127e97c","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"FRESH_SYMBOL","expected_subcode":"DECLARATION_BINDING_BIJECTION","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":40,"legacy_expected_primary":"FRESH_SYMBOL","legacy_expected_subcode":"BINDING_DUPLICATE","legacy_subject_pointer":"/fresh_symbols/binding_ordinals","mutated_subject_sha256":"475bd5f298d9f6b1f45caffe1cbe7dad87d3b9c31c67b3c683223b6a9aa3b27c","mutated_subject_size_bytes":830951,"mutation_id":"pfg3m8-289ea814c3d60125077f23b1aa4e122a","ordinal":5,"patch":{"op":"add","path":"/semantic/symbols/bindings/1","value":{"actual_field_ordinal":0,"actual_field_sha256":"6ff89a73049d120664884e83cc1c4dcbcf5585fcdbb4cd4dbd657b2a6e0176ce","actual_value_schema":"LINUX_FILE_ID","binding_sha256":"cb064f4aaca40fcaff5bfeb26b22108b515b742fdd0fc04e08b7b2ffa371c98d","compatibility_row_sha256":"7b2e642d16cda122e990dd67c725c652408855164a1a3b399d66f363f0d2ebf0","declared_symbol_sha256":"4aae9e35d0c650864f37ffef45e9d6e2a6a6f85b5c0a515cd5f0aacebec94e19","symbol_ordinal":0}},"precondition_pointer":"/semantic/symbols/bindings","precondition_value_sha256":"e29f857709c7bc412cc0ae5296450e58e38def2992c35721624c0d7fc43a6876","precondition_value_size_bytes":444,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"ac1a9c913477628bca0468ea8c95d3afb4476d5cd8a34124b9fbe3e305947eee","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"FRESH_SYMBOL","expected_subcode":"BINDING_AMBIGUOUS_FIELD","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":41,"legacy_expected_primary":"FRESH_SYMBOL","legacy_expected_subcode":"BINDING_AMBIGUOUS_FIELD","legacy_subject_pointer":"/fresh_symbols/actual_field_ordinal","mutated_subject_sha256":"b31193b1bf63622a4bdc851429a2614fda32bb4079e007316644f3d372ebf2fd","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-ac1a9c913477628bca0468ea8c95d3af","ordinal":6,"patch":{"op":"replace","path":"/semantic/symbols/bindings/0/actual_field_ordinal","value":1},"precondition_pointer":"/semantic/symbols/bindings/0/actual_field_ordinal","precondition_value_sha256":"5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9","precondition_value_size_bytes":1,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"f357a4c79cc42d6f0f84af76ff259455fbed0674a184ef5166b0add7b456d510","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"FRESH_SYMBOL","expected_subcode":"BINDING_WRONG_SCHEMA","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":42,"legacy_expected_primary":"FRESH_SYMBOL","legacy_expected_subcode":"BINDING_WRONG_KIND","legacy_subject_pointer":"/fresh_symbols/actual_value_schema","mutated_subject_sha256":"b967bef5c4e7a724cbddd28fbee7df1691df99a75935d2dd053636b9bb3e32c7","mutated_subject_size_bytes":830503,"mutation_id":"pfg3m8-f357a4c79cc42d6f0f84af76ff259455","ordinal":7,"patch":{"op":"replace","path":"/semantic/symbols/bindings/0/actual_value_schema","value":"PIDFD_ID"},"precondition_pointer":"/semantic/symbols/bindings/0/actual_value_schema","precondition_value_sha256":"e8e56eac85e3307e92a65bc7f909601cb3afd863dce7ba636ddc752eaad389df","precondition_value_size_bytes":15,"validation_tier":"SCHEMA"},
{"atom_sha256":"88790e677dd1d68011a5fe6f828c05559717abd37d07cea419177bf691eba4b5","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"FRESH_SYMBOL","expected_subcode":"BINDING_STALE_FIELD","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":43,"legacy_expected_primary":"FRESH_SYMBOL","legacy_expected_subcode":"BINDING_STALE_FIELD","legacy_subject_pointer":"/fresh_symbols/actual_field_sha256","mutated_subject_sha256":"42f2fa78ac5b999ced0f6af06ffcf363f387cd169b36a3e81134cd36ec0d6315","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-88790e677dd1d68011a5fe6f828c0555","ordinal":8,"patch":{"op":"replace","path":"/semantic/symbols/bindings/0/actual_field_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/semantic/symbols/bindings/0/actual_field_sha256","precondition_value_sha256":"f65fa46e95d8d853c9c66aade8ab0818745aeab16fc86375af8fa46410d16821","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"3e0fb5f1ab241316c46bf6cb5946d33f55025d5cc22d75880ea2e22d4de20f39","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"FRESH_SYMBOL","expected_subcode":"UNIVERSE_CROSS_SOURCE","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":44,"legacy_expected_primary":"FRESH_SYMBOL","legacy_expected_subcode":"UNIVERSE_CROSS_SOURCE","legacy_subject_pointer":"/fresh_symbols/universe/source","mutated_subject_sha256":"23408ab7020bd012183b036d685246c6800d542e8717b23ec0eb89e5abbd1263","mutated_subject_size_bytes":830506,"mutation_id":"pfg3m8-3e0fb5f1ab241316c46bf6cb5946d33f","ordinal":9,"patch":{"op":"replace","path":"/semantic/symbols/declarations/0/freshness_universe/source","value":"ACTUAL"},"precondition_pointer":"/semantic/symbols/declarations/0/freshness_universe/source","precondition_value_sha256":"caa97dc82777bb0d712ed630fa5d434f682cc70712b9cda8d0db452a59b131bb","precondition_value_size_bytes":10,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"cc416c716e94cc45141de0a2488480ab212d09ee9f83c581b469448ed54bf4b0","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"FRESH_SYMBOL","expected_subcode":"UNIVERSE_SCHEMA_MISMATCH","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":45,"legacy_expected_primary":"FRESH_SYMBOL","legacy_expected_subcode":"UNIVERSE_SCHEMA_MISMATCH","legacy_subject_pointer":"/fresh_symbols/universe/value_schema","mutated_subject_sha256":"3ae568b812f4c9725a5870f8d2d79c1d1dfd74c8a8a5ecb6089ed88e2c198566","mutated_subject_size_bytes":830501,"mutation_id":"pfg3m8-cc416c716e94cc45141de0a2488480ab","ordinal":10,"patch":{"op":"replace","path":"/semantic/symbols/declarations/0/freshness_universe/value_schema","value":"ARBITRARY_ROWS"},"precondition_pointer":"/semantic/symbols/declarations/0/freshness_universe/value_schema","precondition_value_sha256":"77afc8012d51dc2d79cd7b90f65b5d9346688bab5ba2cf64523ec4f2fd3740d8","precondition_value_size_bytes":23,"validation_tier":"SCHEMA"},
{"atom_sha256":"af274ef061dd3e0436fb8f2070d464b71bb450c3d996e97d19002b80345c3c34","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"OPERATION_IDENTITY","expected_subcode":"OPERATION_ID_PREFIX_MISMATCH","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":46,"legacy_expected_primary":"OPERATION_IDENTITY","legacy_expected_subcode":"OPERATION_ID_PREFIX_MISMATCH","legacy_subject_pointer":"/operation/operation_id","mutated_subject_sha256":"81f739e665a794b752bd29ebe26d3c3fcce8944fb8883c9a847506121c08f299","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-af274ef061dd3e0436fb8f2070d464b7","ordinal":11,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/operation/operation_id","value":"pfg3vnc-21800a78b72e2650483b54c9e5a91996"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/operation/operation_id","precondition_value_sha256":"0a573794b584b86e1590551fefe93eb9b09be52561051591e63d581eb2149b9d","precondition_value_size_bytes":42,"validation_tier":"SCHEMA"},
{"atom_sha256":"d0baff1107bdbe854688e92a9cb251aa8cf06d9bbf57c79b95cbbdbb96475fc9","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"OPERATION_IDENTITY","expected_subcode":"BRANCH_DOMAIN_MISMATCH","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":47,"legacy_expected_primary":"OPERATION_IDENTITY","legacy_expected_subcode":"BRANCH_DOMAIN_MISMATCH","legacy_subject_pointer":"/operation/domain","mutated_subject_sha256":"6dbc9bd932caa596712d2b15fed900597363967ff383fc47b3942ad1c1210a2c","mutated_subject_size_bytes":830506,"mutation_id":"pfg3m8-d0baff1107bdbe854688e92a9cb251aa","ordinal":12,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/operation/operation_domain","value":"PROGRAM_FACTS_G3_OPERATION_LINUX_RETURNED_V1"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/operation/operation_domain","precondition_value_sha256":"a7b2188818e9eb55a35dc2c1be69dcabecf6c47b1dbd7c0106f8be87fd95f108","precondition_value_size_bytes":48,"validation_tier":"HASH_GATE"},
{"atom_sha256":"ff32d07cbe2aad4d118d8b93295b01aa020891b8348cac75860bc417e6a47e54","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"OPERATION_IDENTITY","expected_subcode":"NO_RETURN_RESULT_NOT_NULL","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":48,"legacy_expected_primary":"OPERATION_IDENTITY","legacy_expected_subcode":"NO_RETURN_RESULT_NOT_NULL","legacy_subject_pointer":"/operation/no_return/result_sha256","mutated_subject_sha256":"dded14d9926e7a2c143605f9519a534d4ad2ba8d7b4dadf5a56c5930430e2305","mutated_subject_size_bytes":830570,"mutation_id":"pfg3m8-ff32d07cbe2aad4d118d8b93295b01aa","ordinal":13,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/clone_outcome/operation/result_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/clone_outcome/operation/result_sha256","precondition_value_sha256":"74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b","precondition_value_size_bytes":4,"validation_tier":"SCHEMA"},
{"atom_sha256":"4659de0ac8f3d4350ce39f872232884fb8a6351ddbf60221ce5e5ed487d40516","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"OPERATION_IDENTITY","expected_subcode":"OPERATION_HASH_MISMATCH","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":49,"legacy_expected_primary":"OPERATION_IDENTITY","legacy_expected_subcode":"OPERATION_HASH_MISMATCH","legacy_subject_pointer":"/operation/operation_sha256","mutated_subject_sha256":"7288433091c61b2d307483a094fe8053a32d4c97046861ce6224cad1a88eb7cc","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-4659de0ac8f3d4350ce39f872232884f","ordinal":14,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/operation/operation_sha256","value":"21800a78b72e2650483b54c9e5a9199600000000000000000000000000000000"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/pre_clone_operations/0/operation/operation_sha256","precondition_value_sha256":"b63bbadc2e71197bfbf868fe856c128b96b0bb22d1653925a648aeccf6dd77a1","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"5d3223464bb18a4a983da3340fd8305e03c68a66e237630afe371ae1945ae11b","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"OPERATION_IDENTITY","expected_subcode":"CROSS_BRANCH_IDENTITY_SPLICE","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":50,"legacy_expected_primary":"OPERATION_IDENTITY","legacy_expected_subcode":"CROSS_BRANCH_IDENTITY_SPLICE","legacy_subject_pointer":"/occurrence/operation/completion_kind","mutated_subject_sha256":"bac0e81cf7f302fd271e20e13d6429036908be6e64574c0354b7a49eae3d0902","mutated_subject_size_bytes":830509,"mutation_id":"pfg3m8-5d3223464bb18a4a983da3340fd8305e","ordinal":15,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/occurrences/0/operation/completion_kind","value":"NO_RETURN"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/occurrences/0/operation/completion_kind","precondition_value_sha256":"c8de41b5f628808bf3393fd5f5156f92e4938144165f0658a855181a4bd0880b","precondition_value_size_bytes":10,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"d2d5bccb7f5663a788a7401da90705249b7cf4a58a78dd9582f1c184fcc4e125","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"EFFECTIVE_ROOT_COVERAGE","expected_subcode":"UNCERTAIN_CLONE_UNTYPED","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":51,"legacy_expected_primary":"EFFECTIVE_ROOT_COVERAGE","legacy_expected_subcode":"UNCERTAIN_CLONE_UNTYPED","legacy_subject_pointer":"/spawn_uncertain/uncertain_clone_outcome/type","mutated_subject_sha256":"a7c011e68d6b64074f1f6cdab886692656e3dcb99be074ed2975e4cd69442d41","mutated_subject_size_bytes":828805,"mutation_id":"pfg3m8-d2d5bccb7f5663a788a7401da9070524","ordinal":16,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/clone_outcome","value":"UNOBSERVABLE_AFTER_CRASH"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/semantic_body/clone_outcome","precondition_value_sha256":"20f90131f1092a6c1be6c76fd1b22c3c2a7f326aec09c7a665c0dffb7ac092a8","precondition_value_size_bytes":1729,"validation_tier":"SCHEMA"},
{"atom_sha256":"409ab7cd536ea85b9e293aed91beb886782bcf4d6d6e7a146963d5bff93b32f5","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"EFFECTIVE_ROOT_COVERAGE","expected_subcode":"EFFECTIVE_OCCURRENCE_OMISSION","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":52,"legacy_expected_primary":"EFFECTIVE_ROOT_COVERAGE","legacy_expected_subcode":"EFFECTIVE_OCCURRENCE_OMISSION","legacy_subject_pointer":"/per_operation/occurrence_count","mutated_subject_sha256":"f9d4d683b98fa116c32b7b79e0db4c80a029b5fe55d288102f659f917b73ac30","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-409ab7cd536ea85b9e293aed91beb886","ordinal":17,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/occurrence_count","value":1},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/occurrence_count","precondition_value_sha256":"d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35","precondition_value_size_bytes":1,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"5ec1bad339de4cdc5d2cf34233657835f54d44462e0f4d6937a613bdd4f59bd1","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"EFFECTIVE_ROOT_COVERAGE","expected_subcode":"EFFECTIVE_OCCURRENCE_DUPLICATE","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":53,"legacy_expected_primary":"EFFECTIVE_ROOT_COVERAGE","legacy_expected_subcode":"EFFECTIVE_OCCURRENCE_DUPLICATE","legacy_subject_pointer":"/per_operation/occurrence_ordinals","mutated_subject_sha256":"98095e0a900051949f531df029f05c5a926e84e6eb8ed7904b394312e11adffd","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-5ec1bad339de4cdc5d2cf34233657835","ordinal":18,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/occurrences/1/occurrence_ordinal","value":0},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/occurrences/1/occurrence_ordinal","precondition_value_sha256":"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b","precondition_value_size_bytes":1,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"4bb5eafe2cde9540023274de71ec2b80f38a14efc04ef68d816de5ecb8362ba5","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"EFFECTIVE_ROOT_COVERAGE","expected_subcode":"EXECUTION_JOIN_OMISSION","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":54,"legacy_expected_primary":"EFFECTIVE_ROOT_COVERAGE","legacy_expected_subcode":"EXECUTION_JOIN_OMISSION","legacy_subject_pointer":"/per_operation/execution_join_count","mutated_subject_sha256":"dca12c7ae3623a838100053d303abb45538d30d9110da18f1e7d2dab8f3fc0e4","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-4bb5eafe2cde9540023274de71ec2b80","ordinal":19,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/execution_join_count","value":1},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/execution_join_count","precondition_value_sha256":"d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35","precondition_value_size_bytes":1,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"c05d20418ee454c87787c7bbdd6c144277e06c18e5a04cc268cea3166a1287e0","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"EFFECTIVE_ROOT_COVERAGE","expected_subcode":"UNRELATED_CONFORMANCE_RESULT","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":55,"legacy_expected_primary":"EFFECTIVE_ROOT_COVERAGE","legacy_expected_subcode":"UNRELATED_CONFORMANCE_RESULT","legacy_subject_pointer":"/per_operation/joins/0/conformance_result_sha256","mutated_subject_sha256":"36b2ba3f969d0755730302058ecb0845d0aea2dc1237cfdcf64a624040125744","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-c05d20418ee454c87787c7bbdd6c1442","ordinal":20,"patch":{"op":"replace","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/execution_joins/0/operation_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt/execution_joins/0/operation_sha256","precondition_value_sha256":"b63bbadc2e71197bfbf868fe856c128b96b0bb22d1653925a648aeccf6dd77a1","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"},
{"atom_sha256":"9be6542a6b4a82577236a2412705c12212a25f509ea8124c61ec431cd8270f0f","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"EFFECTIVE_ROOT_COVERAGE","expected_subcode":"POST_OPERATION_RECEIPT_MISSING","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":56,"legacy_expected_primary":"EFFECTIVE_ROOT_COVERAGE","legacy_expected_subcode":"POST_OPERATION_RECEIPT_MISSING","legacy_subject_pointer":"/post_operation/per_operation_execution_receipt_present","mutated_subject_sha256":"fe03ddb58bc0f9e617ce25fa538768440be487a5d3c82c2b66a31098b0f9de5d","mutated_subject_size_bytes":827385,"mutation_id":"pfg3m8-9be6542a6b4a82577236a2412705c122","ordinal":21,"patch":{"op":"remove","path":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt"},"precondition_pointer":"/effective_root/spawn_uncertainty/uncertain_post_operation/operation_receipt","precondition_value_sha256":"0cfc5b25507dd04d3c4a4be477838a392a02bf01dbf3996c95a9c6d494e048a6","precondition_value_size_bytes":3102,"validation_tier":"SCHEMA"},
{"atom_sha256":"5d2ef20387ed19776410e6497689c0751a549fb6f944a53f0edf1e5151db99cc","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"REVIEW_PASS_ONLY","expected_subcode":"REPAIR_REVIEW_REJECTED","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":57,"legacy_expected_primary":"REVIEW_PASS_ONLY","legacy_expected_subcode":"REPAIR_REVIEW_REJECTED","legacy_subject_pointer":"/reviews/profile/disposition","mutated_subject_sha256":"52d6673c7427706ab328688f935d6211ca4e1854514f8a91d7196f74388f875e","mutated_subject_size_bytes":830493,"mutation_id":"pfg3m8-5d2ef20387ed19776410e6497689c075","ordinal":22,"patch":{"op":"replace","path":"/reviews/review_disposition","value":"REPAIR"},"precondition_pointer":"/reviews/review_disposition","precondition_value_sha256":"99640bde331a65b3bde4caeeca5f744900f05f001ccb5d834cec670f63ba1d58","precondition_value_size_bytes":23,"validation_tier":"SCHEMA"},
{"atom_sha256":"615ed184e8d6d1776c531db96b96c5b8a392da75c374002ea842cc8052394297","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"REVIEW_PASS_ONLY","expected_subcode":"REVIEW_SUBJECT_MISMATCH","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":58,"legacy_expected_primary":"REVIEW_PASS_ONLY","legacy_expected_subcode":"REVIEW_SUBJECT_MISMATCH","legacy_subject_pointer":"/reviews/profile/subject_identity","mutated_subject_sha256":"85b5738027a3df50704915cb255798b4d1f2d7f6fd8dc8685eb3643aa6b4ec12","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-615ed184e8d6d1776c531db96b96c5b8","ordinal":23,"patch":{"op":"replace","path":"/reviews/profile_review_subject_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/reviews/profile_review_subject_sha256","precondition_value_sha256":"ab499d0ab1ca12341ab992fc04128bc01ed062f18b4112b43d2bffd2bc3ff521","precondition_value_size_bytes":66,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"75edf57c2887e48d564d2a8001f65e56c8af25bdf0fac61054cfa507b951bc74","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"REVIEW_ACYCLICITY","expected_subcode":"PROFILE_RECEIPT_SELF_REFERENCE","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":59,"legacy_expected_primary":"REVIEW_ACYCLICITY","legacy_expected_subcode":"PROFILE_RECEIPT_SELF_REFERENCE","legacy_subject_pointer":"/profile_receipt/body/contains_receipt_review","mutated_subject_sha256":"d9e7044f2ecc52313449e6259490e4fc4a5a3aa78066082cd6a9d7c309273737","mutated_subject_size_bytes":830507,"mutation_id":"pfg3m8-75edf57c2887e48d564d2a8001f65e56","ordinal":24,"patch":{"op":"replace","path":"/reviews/profile_body_has_review_member","value":true},"precondition_pointer":"/reviews/profile_body_has_review_member","precondition_value_sha256":"fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa","precondition_value_size_bytes":5,"validation_tier":"SCHEMA"},
{"atom_sha256":"d10ad9f9c2c5e34daac4f8961984c7f3db1e05b068ac10a43e997e88a6ac15f0","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"REVIEW_DAG","expected_subcode":"REQUIRED_NODE_OMISSION","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":60,"legacy_expected_primary":"REVIEW_DAG","legacy_expected_subcode":"REQUIRED_NODE_OMISSION","legacy_subject_pointer":"/evidence_dag/node_count","mutated_subject_sha256":"11bacea6e61d5b092041a83823dc780e062a34240a63a38178ad5d1cd6e102d2","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-d10ad9f9c2c5e34daac4f8961984c7f3","ordinal":25,"patch":{"op":"replace","path":"/reviews/node_count","value":26},"precondition_pointer":"/reviews/node_count","precondition_value_sha256":"670671cd97404156226e507973f2ab8330d3022ca96e0c93bdbdb320c41adcaf","precondition_value_size_bytes":2,"validation_tier":"ROSTER_GATE"},
{"atom_sha256":"878b82f3a2edf4ff5971d775e37fb0abd924131634bcc1ac845f25cb9763d406","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"REVIEW_DAG","expected_subcode":"REQUIRED_EDGE_OMISSION","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":61,"legacy_expected_primary":"REVIEW_DAG","legacy_expected_subcode":"REQUIRED_EDGE_OMISSION","legacy_subject_pointer":"/evidence_dag/edge_count","mutated_subject_sha256":"f3e4f4ca41b8dbc491e626ca8b23f1222569b9eb37dc98b4b4ff734298b9b93a","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-878b82f3a2edf4ff5971d775e37fb0ab","ordinal":26,"patch":{"op":"replace","path":"/reviews/edge_count","value":41},"precondition_pointer":"/reviews/edge_count","precondition_value_sha256":"73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049","precondition_value_size_bytes":2,"validation_tier":"ROSTER_GATE"},
{"atom_sha256":"d4b944e7e9243fe4b0c8356685577e178938ea4a46abccd2ca3e2f754645ed04","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"REVIEW_DAG","expected_subcode":"HOST_RECEIPT_TYPE_MISMATCH","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":62,"legacy_expected_primary":"REVIEW_DAG","legacy_expected_subcode":"HOST_RECEIPT_TYPE_MISMATCH","legacy_subject_pointer":"/evidence_dag/HOST_EXECUTION_RECEIPT/artifact_type","mutated_subject_sha256":"07216da1427bea5c71c1f2c1581a7288c0dc439d0cbf70beb264977982d4d5df","mutated_subject_size_bytes":830492,"mutation_id":"pfg3m8-d4b944e7e9243fe4b0c8356685577e17","ordinal":27,"patch":{"op":"replace","path":"/reviews/nodes/20/artifact_type","value":"PROFILE_RECEIPT_BODY"},"precondition_pointer":"/reviews/nodes/20/artifact_type","precondition_value_sha256":"a807856f971eb819d4dad785cf2fd3aada06b22d232e1c2061b604f4fae8bc49","precondition_value_size_bytes":38,"validation_tier":"SCHEMA"},
{"atom_sha256":"9dab7d2e159445d72bd8dd9a3523ad8e5c3445c2165c11bbd814a797909aff94","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"AGGREGATE_TOTALITY","expected_subcode":"AGGREGATE_PROFILE_OMISSION","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":63,"legacy_expected_primary":"AGGREGATE_TOTALITY","legacy_expected_subcode":"AGGREGATE_PROFILE_OMISSION","legacy_subject_pointer":"/aggregate/reviewed_profile_count","mutated_subject_sha256":"4e474f1851e034f5e4ddbd6c4ed0ce194a241b0617744bd04daabfa8a2b89a66","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-9dab7d2e159445d72bd8dd9a3523ad8e","ordinal":28,"patch":{"op":"replace","path":"/aggregate/reviewed_profile_count","value":2},"precondition_pointer":"/aggregate/reviewed_profile_count","precondition_value_sha256":"4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce","precondition_value_size_bytes":1,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"4e206a2f54f2bb5205daf093cc9a03fbe5784f87f32b86eddef9253225119476","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"AGGREGATE_TOTALITY","expected_subcode":"AGGREGATE_PROFILE_DUPLICATE","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":64,"legacy_expected_primary":"AGGREGATE_TOTALITY","legacy_expected_subcode":"AGGREGATE_PROFILE_DUPLICATE","legacy_subject_pointer":"/aggregate/profile_ordinals","mutated_subject_sha256":"e14d8fa8cceac6cb2872676a5db71afe505061a30b59270836d24e35c04603f7","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-4e206a2f54f2bb5205daf093cc9a03fb","ordinal":29,"patch":{"op":"replace","path":"/aggregate/profile_ordinals","value":[0,1,1]},"precondition_pointer":"/aggregate/profile_ordinals","precondition_value_sha256":"434026bd98ff2d8a2fb346c89ae9de006d1e2a6862832b6b3cd86e51de36d5c5","precondition_value_size_bytes":7,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"8ea099c89b8d90966dc713f40a98fc82fd49f4abe5764bf2fb602f71449e17dd","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"AGGREGATE_TOTALITY","expected_subcode":"CROSS_PROFILE_SPLICE","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":65,"legacy_expected_primary":"AGGREGATE_TOTALITY","legacy_expected_subcode":"CROSS_PROFILE_SPLICE","legacy_subject_pointer":"/aggregate/windows/profile","mutated_subject_sha256":"75e1ebf9157d277ebc0c6a78d95cec0a5b4f1e06b02f8ddd2fb642b1c8f69282","mutated_subject_size_bytes":830483,"mutation_id":"pfg3m8-8ea099c89b8d90966dc713f40a98fc82","ordinal":30,"patch":{"op":"replace","path":"/platforms/2/profile","value":"LINUX_X86_64_LP64_LE"},"precondition_pointer":"/platforms/2/profile","precondition_value_sha256":"7a519aec00dd404608390d6c456d80f6e8223054845e91983c04df2762913045","precondition_value_size_bytes":47,"validation_tier":"SEMANTIC_JOIN"},
{"atom_sha256":"09d1bbd253e72f37afbb0c5d130e57f3e2cc464be2214f300a6807681f25c972","baseline_subject_sha256":"e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467","expected_primary":"ATOMIC_RESULT","expected_subcode":"RESULT_HASH_SELF_REFERENCE","family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":66,"legacy_expected_primary":"ATOMIC_RESULT","legacy_expected_subcode":"RESULT_HASH_SELF_REFERENCE","legacy_subject_pointer":"/atomic/result_hash_preimage_includes_result_hash","mutated_subject_sha256":"5f8d897dca1055f906ac5ccc69b27da6edefd722a5e3431c1bfe97db1ff39a2a","mutated_subject_size_bytes":830508,"mutation_id":"pfg3m8-09d1bbd253e72f37afbb0c5d130e57f3","ordinal":31,"patch":{"op":"replace","path":"/aggregate/atomic_results/0/result_sha256","value":"0000000000000000000000000000000000000000000000000000000000000000"},"precondition_pointer":"/aggregate/atomic_results/0/result_sha256","precondition_value_sha256":"3adf61b21268baec25bbe31115c2b558e05e8fe3e7ddbb21b4923eb9ab1f95d1","precondition_value_size_bytes":66,"validation_tier":"HASH_GATE"}
]
```
<!-- END VECTOR_R3_8_REAL_MUTATION_ROSTER -->


The following bijection additionally freezes every entire predecessor compact
row, including its precondition and mutated values. It proves no-loss
preservation independently of human-readable labels.

<!-- BEGIN R3_8_LEGACY_NO_LOSS_IDENTITY -->
```json
{"legacy_compact_roster_sha256":"818c18e1eea64b97b12a76e4a79a2a8b81ac8497eb6b1d9b8e26537c6d36d03a","legacy_compact_roster_size_bytes":10979,"mapping_canonical_sha256":"091eab06f3a30d541feb3fa8e8262dee308a80fa78fa7d425a80820f9e889011","mapping_canonical_size_bytes":20385,"mapping_count":67}
```
<!-- END R3_8_LEGACY_NO_LOSS_IDENTITY -->

<!-- BEGIN VECTOR_R3_8_LEGACY_NO_LOSS_MAP -->
```json
[
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":0,"legacy_row_sha256":"d377aecc041955135184d04bfbfb990788279d0d237a0ff206c3470d447f16cb","ordinal":0,"r3_8_atom_sha256":"0558d1613bf85b9f8364603e1fa07931d02d715756cfe0edc753175b0112b1c4","r3_8_mutation_id":"pfg3m8-0558d1613bf85b9f8364603e1fa07931"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":1,"legacy_row_sha256":"df82638a1c115ca7701f8bddd9ab3cbeafea173e044c7a737ece9fd02e9ecd7e","ordinal":1,"r3_8_atom_sha256":"352d379237fc7304f050c884d91a6882961d01582aafaa40a16ff01c89c1edaf","r3_8_mutation_id":"pfg3m8-352d379237fc7304f050c884d91a6882"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":2,"legacy_row_sha256":"fbf1a0665945c4667c9384ad689186053da58f0ec575c7e8b9e351a473886443","ordinal":2,"r3_8_atom_sha256":"a7f1b8ac6563cbdd692c4a06a6686b107d38a0279232297d890422c6418e0a78","r3_8_mutation_id":"pfg3m8-a7f1b8ac6563cbdd692c4a06a6686b10"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":3,"legacy_row_sha256":"3df0f948df20d49f54a8558ba89a63249722a814eeaa53394ec87bae306deb0f","ordinal":3,"r3_8_atom_sha256":"fc47ce7c8e56f0961affdd2b0c25c5e317d831e39fe31516b0072b767adfe2b6","r3_8_mutation_id":"pfg3m8-fc47ce7c8e56f0961affdd2b0c25c5e3"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":4,"legacy_row_sha256":"a90b5f3665f38e907783d06c09ae96cd117eb1b73be3b6129c7138ef246915b6","ordinal":4,"r3_8_atom_sha256":"8dd2a49156917ab76389d18ead3e04b27153036cc5eb02d7e8af8a2ae246976a","r3_8_mutation_id":"pfg3m8-8dd2a49156917ab76389d18ead3e04b2"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":5,"legacy_row_sha256":"1997018aef9f6cbd22602976d9d4210208174f66784c3e4aaffe9333d1374f1b","ordinal":5,"r3_8_atom_sha256":"ffa2a39555d59571885b90ebb20e2d374ca23e7d4491ddbd7746ff9d68bd1a9d","r3_8_mutation_id":"pfg3m8-ffa2a39555d59571885b90ebb20e2d37"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":6,"legacy_row_sha256":"7467bcf61696272433503d55d90782b991b5fd2f3cd25961ab20603c6e521287","ordinal":6,"r3_8_atom_sha256":"c1989a6272f3d7acb2a7a43a5236d6f8dab83f2cee9a4a2a7abfd17e6a232696","r3_8_mutation_id":"pfg3m8-c1989a6272f3d7acb2a7a43a5236d6f8"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":7,"legacy_row_sha256":"b1eca870a9dd1845c90208a3f8036e8c68326daddb417c899d1633a50c88a1bc","ordinal":7,"r3_8_atom_sha256":"f6c6366642116dc9c501741f2b2d799d6d97f215e267dadade66c969a6c34ff4","r3_8_mutation_id":"pfg3m8-f6c6366642116dc9c501741f2b2d799d"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":8,"legacy_row_sha256":"2305f9b374aaa0042417096e8c7dc91b4c8106f914d3147803cfb3650f1d44a1","ordinal":8,"r3_8_atom_sha256":"50518f7bd82a22160e4fbcda3fb274d9978e02718ac6af7023bdaa7a2a1b9ff4","r3_8_mutation_id":"pfg3m8-50518f7bd82a22160e4fbcda3fb274d9"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":9,"legacy_row_sha256":"9d81a12d8a3a8e6602f99f1f405e06dafd008f9a786fd684e3877b7182d87b78","ordinal":9,"r3_8_atom_sha256":"adac6f96683271b90bd0fbc9a57d780c5088837ea5b36f1ea57af6aa4bc66f8f","r3_8_mutation_id":"pfg3m8-adac6f96683271b90bd0fbc9a57d780c"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":10,"legacy_row_sha256":"17f9b64e4ce8baecef3110ad42117bb00c61cfb98f1e60a3816dc3314f1e5ea0","ordinal":10,"r3_8_atom_sha256":"62629b15755572978864547d3b25a41f6c98e1e5d9ea2850f7569f2a0df567b9","r3_8_mutation_id":"pfg3m8-62629b15755572978864547d3b25a41f"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":11,"legacy_row_sha256":"c81acb5db7710a7a5bae1fe90d3d26254bc92d12e25a497824ac8ba0c2d57a20","ordinal":11,"r3_8_atom_sha256":"bbe5db93d3907c78f19b5e37bc4582e6c4cb069919108e90c52f087e557f3d27","r3_8_mutation_id":"pfg3m8-bbe5db93d3907c78f19b5e37bc4582e6"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":12,"legacy_row_sha256":"fec9fd04288e8bfaeddacfc142bcaa6714e1bc9a233837ce6c8aa7c72542548a","ordinal":12,"r3_8_atom_sha256":"7e0f4fbfe65e29eb4e16eece652d14c4fe7b6ba8874b5ad478d324530c5a3d90","r3_8_mutation_id":"pfg3m8-7e0f4fbfe65e29eb4e16eece652d14c4"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":13,"legacy_row_sha256":"335ccc012f4ac96887210d56451bc032cd6a1b969f463d25ea174006917a830e","ordinal":13,"r3_8_atom_sha256":"0be92b32f93105f613e465274c954e473d936a911b025a55dded45bbd7d19e1e","r3_8_mutation_id":"pfg3m8-0be92b32f93105f613e465274c954e47"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":14,"legacy_row_sha256":"ae77405f169db6ebe4e1833127b6aaaaf7c281b093c0a7e267ab90b42ba22882","ordinal":14,"r3_8_atom_sha256":"59dccc1584cd452df3fb06f01fabfcf033a1da8d815c378a088f667e44092703","r3_8_mutation_id":"pfg3m8-59dccc1584cd452df3fb06f01fabfcf0"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":15,"legacy_row_sha256":"c3edd6be63d470f9c84b5c2a76d9c4675853d4d6135430ef3d4a9fa21d6e78c6","ordinal":15,"r3_8_atom_sha256":"5ef28ce73e4845173a6483d92250535af14d0602ae85916cba363af3cc125f0d","r3_8_mutation_id":"pfg3m8-5ef28ce73e4845173a6483d92250535a"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":16,"legacy_row_sha256":"636bbe9ed26da9a43f8bddb1b37b3bed97ef6e4edfcef8a2f2c8ebfab962ea57","ordinal":16,"r3_8_atom_sha256":"b6730317d482ff853ca71a5eb50dda65af02d4853f7daf10fb82e445213271e0","r3_8_mutation_id":"pfg3m8-b6730317d482ff853ca71a5eb50dda65"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":17,"legacy_row_sha256":"3e966bd78b34a96bd9a139b8a6eec580b877cc141c4422d1da8e31efd9386af9","ordinal":17,"r3_8_atom_sha256":"5135267d8b77030698fe911b9724a59bd65c92caaa93054a27a8eb387fce5735","r3_8_mutation_id":"pfg3m8-5135267d8b77030698fe911b9724a59b"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":18,"legacy_row_sha256":"e183e9509f76f8ec70e1261bb1bde44909a15d02d407851572eca1be0d87b398","ordinal":18,"r3_8_atom_sha256":"5160855c07f0c199cb8e4b30ecdd7a1b854af09d64b0f6691204fec7226e5a79","r3_8_mutation_id":"pfg3m8-5160855c07f0c199cb8e4b30ecdd7a1b"},
{"family":"SIGNATURE_DEPENDENCY_NEGATIVE","global_ordinal":19,"legacy_row_sha256":"25e000002ed614276a7fbddd61cb56149900d7e5d4e7080f44dabd1e25d15286","ordinal":19,"r3_8_atom_sha256":"bfc0e64b52f17b54dfaa0f3a24c1ccbe410700d1e01ee7271da17ad83ba5fb38","r3_8_mutation_id":"pfg3m8-bfc0e64b52f17b54dfaa0f3a24c1ccbe"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":20,"legacy_row_sha256":"34a4dc50405db8d47eaf72493ce84329b66c2fdceaaae0f024d279f48894340f","ordinal":0,"r3_8_atom_sha256":"ea2685adeb34464d3bdf7f676f26b69c124d58ff7f2bea5c4542426955901a0a","r3_8_mutation_id":"pfg3m8-ea2685adeb34464d3bdf7f676f26b69c"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":21,"legacy_row_sha256":"640cb9b9a6a931e9c425e96512ffe87ffc0a4a8f00fec4d304b3e0cd9eb3eb1b","ordinal":1,"r3_8_atom_sha256":"5cc16302b4433a8b1517a93f94cb7ac194ff22a9bb95055fe0ad6ba8d88ea7ba","r3_8_mutation_id":"pfg3m8-5cc16302b4433a8b1517a93f94cb7ac1"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":22,"legacy_row_sha256":"2c52148fc2599f9acdb27b1104d4b3a58362b60c4dacdd0568eb923f1a48c4f4","ordinal":2,"r3_8_atom_sha256":"e4e17922886a9ba2bdaf01b65fa05ddb98b0aeabdc35173b0379f3388d238a13","r3_8_mutation_id":"pfg3m8-e4e17922886a9ba2bdaf01b65fa05ddb"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":23,"legacy_row_sha256":"bd17ed4425456b4ae7d1848a8876675154d18db11ebd75968cafab2ae0dc30b8","ordinal":3,"r3_8_atom_sha256":"b54ec3057a526298ecd6146f78cadc0eabb22ed93c478f8b4abbc59d4cde25ad","r3_8_mutation_id":"pfg3m8-b54ec3057a526298ecd6146f78cadc0e"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":24,"legacy_row_sha256":"3b6ebce0d394a2b567715fad2b1a76a29a9310ce4876a8ec27765bf9b2a11ee6","ordinal":4,"r3_8_atom_sha256":"aba17a9bd9d865c0cbdcb8acaf55d73f45036db38cbbec09150370d8e9a2bf57","r3_8_mutation_id":"pfg3m8-aba17a9bd9d865c0cbdcb8acaf55d73f"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":25,"legacy_row_sha256":"a4e54759b95b84d4d420b08e666a807bbd43a855b5eb0273f5b02e86c7e9bed1","ordinal":5,"r3_8_atom_sha256":"4d03c1fb13d8d2857e0cfb0aa31267368dc75b1581256085444fe59efaba1168","r3_8_mutation_id":"pfg3m8-4d03c1fb13d8d2857e0cfb0aa3126736"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":26,"legacy_row_sha256":"5e9945a6e8b89fca3ec829249e4f2fbc8d622fdbb90ec783678cd1a9eb81afeb","ordinal":6,"r3_8_atom_sha256":"c9650039f0801dd8a24095218ab0fe870d8f468a8d382a82cc4c961978d64857","r3_8_mutation_id":"pfg3m8-c9650039f0801dd8a24095218ab0fe87"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":27,"legacy_row_sha256":"36bea5d94d5ef6c7182bf611c6e584081e75a7d67e6c4bf719b33450c84fa6fb","ordinal":7,"r3_8_atom_sha256":"26e69f1accafb0f7e5347a6d3adf1bb0c7d243ec2ce632d2d693e7858562829c","r3_8_mutation_id":"pfg3m8-26e69f1accafb0f7e5347a6d3adf1bb0"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":28,"legacy_row_sha256":"0d88da4b11999e316b1008613ea85650bfa4241d38e751dcb7792bdb1f1f1878","ordinal":8,"r3_8_atom_sha256":"c3de581fd74d5721b57a477f512c3e64370ca4906cadc07aee6938f76da5b639","r3_8_mutation_id":"pfg3m8-c3de581fd74d5721b57a477f512c3e64"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":29,"legacy_row_sha256":"5085deb42ec9df9055494d7d5b6b15fb3613cb75eac461850c6cae54c63a2512","ordinal":9,"r3_8_atom_sha256":"0fdb01c44ed2b2498cdfeb9af46d1d472116a37894718fb5032bffc56656143e","r3_8_mutation_id":"pfg3m8-0fdb01c44ed2b2498cdfeb9af46d1d47"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":30,"legacy_row_sha256":"830616b3b582f4472ad360978eba014731936ff907ddb8c40316d976654464a5","ordinal":10,"r3_8_atom_sha256":"193dbe8d4d8c0fe93c1462e7b62d598e97ab68aac37010b7ba85efd29779128c","r3_8_mutation_id":"pfg3m8-193dbe8d4d8c0fe93c1462e7b62d598e"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":31,"legacy_row_sha256":"fd8b6e801ff92a68c537d313cba97c9ce4bc62fb6c6986e9fee299d9bf333205","ordinal":11,"r3_8_atom_sha256":"32325b1d37a1b5e237a9f76273d9cb12cec3ae154958094eac2fa5458a28edf0","r3_8_mutation_id":"pfg3m8-32325b1d37a1b5e237a9f76273d9cb12"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":32,"legacy_row_sha256":"26cfe8ee7ffa4c7ec83ab6b042045d3a2fcd38bd46a51e8f590532f5d4e87a8c","ordinal":12,"r3_8_atom_sha256":"ca08332b13b47ffbdd060b1dfd4f15f286c3ac1b13bf7678edd14970134d86f5","r3_8_mutation_id":"pfg3m8-ca08332b13b47ffbdd060b1dfd4f15f2"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":33,"legacy_row_sha256":"f3eae802d0d8c5b3b84dd0444994db54248372f17b3cf11929ec7288333057a6","ordinal":13,"r3_8_atom_sha256":"d8fd177b3d005c52f812114bcc0ae896e629cf97c6e3dae887baf411dc0a4143","r3_8_mutation_id":"pfg3m8-d8fd177b3d005c52f812114bcc0ae896"},
{"family":"WINDOWS_RENAME_NEGATIVE","global_ordinal":34,"legacy_row_sha256":"12abe93af7ce6063b5283b32dcd267064aa8aaf1ade01790783888cb1b90781a","ordinal":14,"r3_8_atom_sha256":"bcab9d4d34daa6846c17dbdfdfb78dbfd451be417bbed92e081b23e9fc96eb29","r3_8_mutation_id":"pfg3m8-bcab9d4d34daa6846c17dbdfdfb78dbf"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":35,"legacy_row_sha256":"05ac8e321c4fc624bb55927dff2d9a68b45e69b3e1c6f9c142a8f58e147750fc","ordinal":0,"r3_8_atom_sha256":"d0b0ab909f59b3860a5d7dd886fcade1919df0d756d8db9f78e586d0ca838905","r3_8_mutation_id":"pfg3m8-d0b0ab909f59b3860a5d7dd886fcade1"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":36,"legacy_row_sha256":"fd8016eb084ef695288a9db1f05fa09b6c8249f8431b62660dfe2c0a94cb1ad5","ordinal":1,"r3_8_atom_sha256":"5a8d82911ac086dad1a38d81aad84338af2313e7beefa413fbb2d6440d33c6ff","r3_8_mutation_id":"pfg3m8-5a8d82911ac086dad1a38d81aad84338"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":37,"legacy_row_sha256":"3fad992dcf2e65bbc525fb8abf6b60a081cf2fc9e95b788ceebaba59b3ab8e33","ordinal":2,"r3_8_atom_sha256":"a9bf3d6cd19cecc2bae678465015d9933a35598af606829b5932369bffe8f9b9","r3_8_mutation_id":"pfg3m8-a9bf3d6cd19cecc2bae678465015d993"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":38,"legacy_row_sha256":"d860d9dea1506ced61e40d43c30d9b033207f0f5572b7392e1da78333116364f","ordinal":3,"r3_8_atom_sha256":"01dc69a6e117e66f7ba9968ddfe4888d98af01080708a407ff0714221f64a0d3","r3_8_mutation_id":"pfg3m8-01dc69a6e117e66f7ba9968ddfe4888d"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":39,"legacy_row_sha256":"c2eefeff2a6e098ed763e85defe46ff48bbc07fe352af8208741d82e19a62c7b","ordinal":4,"r3_8_atom_sha256":"8be8e3b8b8d8742ea23a8a5b0f8b5987475cccd341168b1d7699b581b8840985","r3_8_mutation_id":"pfg3m8-8be8e3b8b8d8742ea23a8a5b0f8b5987"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":40,"legacy_row_sha256":"c91009287775fd8d8f3b8c5b43e1622d185e3d31e479e75cd1a7c1833a660bde","ordinal":5,"r3_8_atom_sha256":"289ea814c3d60125077f23b1aa4e122a521258684a06cfa757f90fdb7127e97c","r3_8_mutation_id":"pfg3m8-289ea814c3d60125077f23b1aa4e122a"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":41,"legacy_row_sha256":"84c367b70abdab79f4ca6df5f1e3342c992b60db8f75ed3fa6a1b0cdba70446a","ordinal":6,"r3_8_atom_sha256":"ac1a9c913477628bca0468ea8c95d3afb4476d5cd8a34124b9fbe3e305947eee","r3_8_mutation_id":"pfg3m8-ac1a9c913477628bca0468ea8c95d3af"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":42,"legacy_row_sha256":"07f123d45b55203dc373b0d039d10bc776d46f70e27607852080572a274e539a","ordinal":7,"r3_8_atom_sha256":"f357a4c79cc42d6f0f84af76ff259455fbed0674a184ef5166b0add7b456d510","r3_8_mutation_id":"pfg3m8-f357a4c79cc42d6f0f84af76ff259455"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":43,"legacy_row_sha256":"c727df89d2b090631a8f7e64cd30ebab72989e61c5ac469b339ac2fbed0ec25b","ordinal":8,"r3_8_atom_sha256":"88790e677dd1d68011a5fe6f828c05559717abd37d07cea419177bf691eba4b5","r3_8_mutation_id":"pfg3m8-88790e677dd1d68011a5fe6f828c0555"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":44,"legacy_row_sha256":"787f52d2b9642fcba9df3fdb89c37007e76114a9bf67e166758d02425891fb99","ordinal":9,"r3_8_atom_sha256":"3e0fb5f1ab241316c46bf6cb5946d33f55025d5cc22d75880ea2e22d4de20f39","r3_8_mutation_id":"pfg3m8-3e0fb5f1ab241316c46bf6cb5946d33f"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":45,"legacy_row_sha256":"093a6eca5b9ad1832a8c29e75dab7ad56a5e17d1e1ff6a68060ee170ad57121f","ordinal":10,"r3_8_atom_sha256":"cc416c716e94cc45141de0a2488480ab212d09ee9f83c581b469448ed54bf4b0","r3_8_mutation_id":"pfg3m8-cc416c716e94cc45141de0a2488480ab"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":46,"legacy_row_sha256":"37ea275705b342fd27dbb81a0082e41d51f8b188c6646e23a3c0077eb582c16e","ordinal":11,"r3_8_atom_sha256":"af274ef061dd3e0436fb8f2070d464b71bb450c3d996e97d19002b80345c3c34","r3_8_mutation_id":"pfg3m8-af274ef061dd3e0436fb8f2070d464b7"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":47,"legacy_row_sha256":"80ce1ac7773e96ba9f62f78dbe1f69a306379f5abe7c471f1303f3f265af44fa","ordinal":12,"r3_8_atom_sha256":"d0baff1107bdbe854688e92a9cb251aa8cf06d9bbf57c79b95cbbdbb96475fc9","r3_8_mutation_id":"pfg3m8-d0baff1107bdbe854688e92a9cb251aa"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":48,"legacy_row_sha256":"19d0f56ee3474bf67cd66fc4bca14ae26a77b77db110e1947f8069f83fa7eba2","ordinal":13,"r3_8_atom_sha256":"ff32d07cbe2aad4d118d8b93295b01aa020891b8348cac75860bc417e6a47e54","r3_8_mutation_id":"pfg3m8-ff32d07cbe2aad4d118d8b93295b01aa"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":49,"legacy_row_sha256":"9b6b0bd61c1aa882fa456de7bbf54f3195c70e0aa63bbd8780384a4e690e410e","ordinal":14,"r3_8_atom_sha256":"4659de0ac8f3d4350ce39f872232884fb8a6351ddbf60221ce5e5ed487d40516","r3_8_mutation_id":"pfg3m8-4659de0ac8f3d4350ce39f872232884f"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":50,"legacy_row_sha256":"2f3aa5b1b06189a0881cad62ec0c552ecf767909d68044cd4c9eb9a10a7ac4b1","ordinal":15,"r3_8_atom_sha256":"5d3223464bb18a4a983da3340fd8305e03c68a66e237630afe371ae1945ae11b","r3_8_mutation_id":"pfg3m8-5d3223464bb18a4a983da3340fd8305e"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":51,"legacy_row_sha256":"e51191a6f8f071e5706ec1026d113916479f3b7b76f78ff9101da1752b9c3e76","ordinal":16,"r3_8_atom_sha256":"d2d5bccb7f5663a788a7401da90705249b7cf4a58a78dd9582f1c184fcc4e125","r3_8_mutation_id":"pfg3m8-d2d5bccb7f5663a788a7401da9070524"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":52,"legacy_row_sha256":"c2121064faa4a2d2097dfe8876d3b8d4d5ca48c0028f9c57f8c84eaf215cfdc0","ordinal":17,"r3_8_atom_sha256":"409ab7cd536ea85b9e293aed91beb886782bcf4d6d6e7a146963d5bff93b32f5","r3_8_mutation_id":"pfg3m8-409ab7cd536ea85b9e293aed91beb886"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":53,"legacy_row_sha256":"10fd03147c8ce109c991ba36149784e4951781b4c5dc3cd73348e5a4e5a2a144","ordinal":18,"r3_8_atom_sha256":"5ec1bad339de4cdc5d2cf34233657835f54d44462e0f4d6937a613bdd4f59bd1","r3_8_mutation_id":"pfg3m8-5ec1bad339de4cdc5d2cf34233657835"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":54,"legacy_row_sha256":"f425a6951cf80ab4a0158f7b74221cae81f2e30afbde6abb57ee3a138877dc4a","ordinal":19,"r3_8_atom_sha256":"4bb5eafe2cde9540023274de71ec2b80f38a14efc04ef68d816de5ecb8362ba5","r3_8_mutation_id":"pfg3m8-4bb5eafe2cde9540023274de71ec2b80"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":55,"legacy_row_sha256":"f37d50b8200dda08752dd0dcac82cbc5a4b96bf0da4e6d4e3627d3dfde57e344","ordinal":20,"r3_8_atom_sha256":"c05d20418ee454c87787c7bbdd6c144277e06c18e5a04cc268cea3166a1287e0","r3_8_mutation_id":"pfg3m8-c05d20418ee454c87787c7bbdd6c1442"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":56,"legacy_row_sha256":"8c5b6f1aea966905c84fe04900214eb47f3f226d9f6bead810b5864ad20b3e52","ordinal":21,"r3_8_atom_sha256":"9be6542a6b4a82577236a2412705c12212a25f509ea8124c61ec431cd8270f0f","r3_8_mutation_id":"pfg3m8-9be6542a6b4a82577236a2412705c122"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":57,"legacy_row_sha256":"9703c90120260fc2d018602b03f662e5a6ebe131468b4560c73e7f065cf0b3e4","ordinal":22,"r3_8_atom_sha256":"5d2ef20387ed19776410e6497689c0751a549fb6f944a53f0edf1e5151db99cc","r3_8_mutation_id":"pfg3m8-5d2ef20387ed19776410e6497689c075"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":58,"legacy_row_sha256":"d702787b459b43082261e6738c126466eb5b5ce383274ddc8e767cb3d8fbeee7","ordinal":23,"r3_8_atom_sha256":"615ed184e8d6d1776c531db96b96c5b8a392da75c374002ea842cc8052394297","r3_8_mutation_id":"pfg3m8-615ed184e8d6d1776c531db96b96c5b8"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":59,"legacy_row_sha256":"f703ac76fae96a239600fd8ed1635b238aa907c5f326a8834abd77e1d1052a52","ordinal":24,"r3_8_atom_sha256":"75edf57c2887e48d564d2a8001f65e56c8af25bdf0fac61054cfa507b951bc74","r3_8_mutation_id":"pfg3m8-75edf57c2887e48d564d2a8001f65e56"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":60,"legacy_row_sha256":"00f8d321f559511556e295be9e66887f73c8fb90d26ed1006e1ab37e9b528f68","ordinal":25,"r3_8_atom_sha256":"d10ad9f9c2c5e34daac4f8961984c7f3db1e05b068ac10a43e997e88a6ac15f0","r3_8_mutation_id":"pfg3m8-d10ad9f9c2c5e34daac4f8961984c7f3"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":61,"legacy_row_sha256":"a5778bed4f3672a030e1fad91543d1aaa07243fd9536a8268daf70e7dcfee869","ordinal":26,"r3_8_atom_sha256":"878b82f3a2edf4ff5971d775e37fb0abd924131634bcc1ac845f25cb9763d406","r3_8_mutation_id":"pfg3m8-878b82f3a2edf4ff5971d775e37fb0ab"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":62,"legacy_row_sha256":"90826f9ec984a76d612dc27c1e624741a58c0daa7207af895aeafa7748921ebc","ordinal":27,"r3_8_atom_sha256":"d4b944e7e9243fe4b0c8356685577e178938ea4a46abccd2ca3e2f754645ed04","r3_8_mutation_id":"pfg3m8-d4b944e7e9243fe4b0c8356685577e17"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":63,"legacy_row_sha256":"269763bc5d31d861188fd8de1cb1e7216118def731c8b9b653d52efcc4e2c4e7","ordinal":28,"r3_8_atom_sha256":"9dab7d2e159445d72bd8dd9a3523ad8e5c3445c2165c11bbd814a797909aff94","r3_8_mutation_id":"pfg3m8-9dab7d2e159445d72bd8dd9a3523ad8e"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":64,"legacy_row_sha256":"b6ac97daed798d609f7dd271a11f1d199b9edcf6becba926eb3506f8477daade","ordinal":29,"r3_8_atom_sha256":"4e206a2f54f2bb5205daf093cc9a03fbe5784f87f32b86eddef9253225119476","r3_8_mutation_id":"pfg3m8-4e206a2f54f2bb5205daf093cc9a03fb"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":65,"legacy_row_sha256":"30f6ad31b938bb1f49378a0fffc14d20bf51d796e622633bade727fe90a8b5a3","ordinal":30,"r3_8_atom_sha256":"8ea099c89b8d90966dc713f40a98fc82fd49f4abe5764bf2fb602f71449e17dd","r3_8_mutation_id":"pfg3m8-8ea099c89b8d90966dc713f40a98fc82"},
{"family":"CROSS_SCHEMA_NEGATIVE","global_ordinal":66,"legacy_row_sha256":"2022717fc090dfed2cb916e80be091f5653d4884863f058d0faacf5e21d6ff70","ordinal":31,"r3_8_atom_sha256":"09d1bbd253e72f37afbb0c5d130e57f3e2cc464be2214f300a6807681f25c972","r3_8_mutation_id":"pfg3m8-09d1bbd253e72f37afbb0c5d130e57f3"}
]
```
<!-- END VECTOR_R3_8_LEGACY_NO_LOSS_MAP -->

## 10. Deterministic construction, execution, and independence self-check

This checker reads only this contract and its three frozen predecessor/review
inputs. It writes no file, imports no launcher or provider, and performs no
native operation. It constructs the exact baseline, proves acceptance, applies
each real patch once, validates the complete mutated bytes, and proves that
scrambling every expected diagnostic cannot affect validator output.

<!-- BEGIN R3_8_DETERMINISTIC_SELF_CHECK -->
```python
import copy
import hashlib
import inspect
import json
import re
import sys
from pathlib import Path

subject=Path(sys.argv[1]).resolve()
raw=subject.read_bytes()
assert raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw
assert b"\t" not in raw
text=raw.decode("utf-8")
assert all(not line.endswith((" ","\t")) for line in text.splitlines())
assert "Status: `CONTRACT_ONLY_NON_LINEAGE_STABLE_DRAFT_PENDING_LATE_BOUND_CROSSCHECK_BRIDGE_R3_8`" in text

def extract(name,language):
    match=re.search(rf"<!-- BEGIN {name} -->\n```{language}\n(.*?)\n```\n<!-- END {name} -->",text,re.S)
    assert match,name
    return match.group(1)

def extract_json(name):
    return json.loads(extract(name,"json"))

def cj(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False)

def digest(data):
    return hashlib.sha256(data).hexdigest()

project=subject.parent.parent
predecessor=subject.parent/"program-facts-g3-00-parity-launcher-runtime-closure-amendment.md"
review_dir=project/"review_fixtures"/"program_facts_runtime_gate3"/"g3_00_schema_launcher"
state_review=review_dir/"PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_7_STATE_OPERATIONAL_REVIEW_95b1b0f17d5e.md"
native_review=review_dir/"PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_7_NATIVE_CONTRACT_REVIEW_95b1b0f17d5ea180.md"
for path,size,sha256 in [
 (predecessor,934000,"95b1b0f17d5ea180884b401566dc0190f5cb19954e1b65c62d0ce2cfa8f2ab86"),
 (state_review,15949,"fe7c8bf8e7d473a979895f43b24d0af077ff83fdb9599d43b5706c004b6d7be4"),
 (native_review,21964,"4a4ef57b8701b0a9cdd2d97035e4a2d404b523ae0dcf276282e03ae4e6da3533")]:
    data=path.read_bytes()
    assert len(data)==size and digest(data)==sha256 and b"\r" not in data

validator_source=extract("R3_8_MATERIALIZATION_VALIDATOR_SOURCE","python")+"\n"
assert len(validator_source.encode())==54888
assert digest(validator_source.encode())=="830c5520545b817e6fd5d4ff26b8dfcfe124e5704fcd0d67722bc13fbf7b976b"
for forbidden in ("expected_primary","expected_subcode",
                  "VECTOR_R3_8_REAL_MUTATION_ROSTER","build_mutation_specs"):
    assert forbidden not in validator_source
validator_namespace={}
exec(compile(validator_source,"<r3_8_validator>","exec"),validator_namespace)
validate=validator_namespace["validate_subject"]
assert list(inspect.signature(validate).parameters)==["subject_bytes"]

baseline_bytes=validator_namespace["cj"](
    validator_namespace["make_baseline"](digest(validator_source.encode()))).encode()
assert len(baseline_bytes)==830508
assert digest(baseline_bytes)=="e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467"
assert validate(baseline_bytes)==("ACCEPTED","MATERIALIZATION_BASELINE_VALID")
baseline=json.loads(baseline_bytes)
assert validator_namespace["cj"](baseline).encode()==baseline_bytes

identity=extract_json("R3_8_ACCEPTED_BASELINE_AND_ROSTER_IDENTITY")
assert identity=={
 "all_authority_and_enabling_false":True,
 "atomic_contract_result_count":2227,"baseline_sha256":digest(baseline_bytes),
 "baseline_size_bytes":len(baseline_bytes),
 "baseline_validation":["ACCEPTED","MATERIALIZATION_BASELINE_VALID"],
 "dag_edge_count":42,"dag_node_count":27,"declaration_binding_count":22,
 "mutation_count":67,"mutation_family_counts":[20,15,32],
 "mutation_roster_canonical_sha256":"45500582e4127f6622773c6dabb820af6f0d7f1c0ba295e3a930659078ef674a",
 "mutation_roster_canonical_size_bytes":72033,
 "mutation_roster_stream_sha256":"e7c360ed9730d9dde9c38130a1a5fa15da2f1a53d52de10df76b42516ea6b0aa",
 "mutation_roster_stream_size_bytes":72032,
 "mutation_spec_source_sha256":"fb00a7e838b416e8a37167bb96fedee76057b454fcd78f3db6ed94a2b32b6db1",
 "mutation_spec_source_size_bytes":11136,"platform_count":3,
 "profile_count":3,"registered_platform_policy_slice_count":1,
 "registered_slice_count":110,
 "schema_id":"plamen.program_facts.g3.r3_8.materialization_identity",
 "validator_source_sha256":digest(validator_source.encode()),
 "validator_source_size_bytes":len(validator_source.encode())}

dag=extract_json("VECTOR_EVIDENCE_DAG_NODE_ROSTER_R3_8")
assert len(dag)==27 and [row["node_ordinal"] for row in dag]==list(range(27))
assert len(cj(dag).encode())==4099 and digest(cj(dag).encode())=="7616c7dbf74f50493305b3f103655da4359f2a37008b994e2915d8429f2b263a"
ordinal={row["node_kind"]:row["node_ordinal"] for row in dag}
edges=[(source,row["node_kind"]) for row in dag for source in row["predecessors"]]
assert len(ordinal)==27 and len(edges)==len(set(edges))==42
assert all(ordinal[source]<ordinal[target] for source,target in edges)
assert ordinal["PROFILE_RECEIPT_BODY"]<ordinal["PROFILE_RECEIPT_REVIEW"]<ordinal["REVIEWED_PROFILE_RECEIPT"]
assert ordinal["NATIVE_AUTHORITY_REVIEW"]<ordinal["NONAUTHORITATIVE_AUTHORITY_JOIN"]

compatibility=extract_json("VECTOR_SYMBOL_KIND_SCHEMA_ROSTER_R3_8")
assert [(row["symbol_kind"],row["projection_schema_id"]) for row in compatibility]==[
 ("FILE_ID","LINUX_FILE_ID"),("FD","FD_ID"),("MOUNT_ID","MOUNT_ID"),
 ("PID","PID_ID"),("PIDFD","PIDFD_ID"),("PROCESS_ID","PROCESS_ID")]
assert len(cj(compatibility).encode())==452
assert digest(cj(compatibility).encode())=="9b827fddf98213e1717328634f0ce9df2e7fbbf3a6b1c0b19ce9284cf24a0f85"

mutation_source=extract("R3_8_MUTATION_SPEC_SOURCE","python")+"\n"
assert len(mutation_source.encode())==11136
assert digest(mutation_source.encode())=="fb00a7e838b416e8a37167bb96fedee76057b454fcd78f3db6ed94a2b32b6db1"
mutation_namespace={}
exec(compile(mutation_source,"<r3_8_mutations>","exec"),mutation_namespace)
specs=mutation_namespace["build_mutation_specs"](baseline)
roster=extract_json("VECTOR_R3_8_REAL_MUTATION_ROSTER")
assert len(roster)==len(specs)==67
assert len(cj(roster).encode())==72033
assert digest(cj(roster).encode())=="45500582e4127f6622773c6dabb820af6f0d7f1c0ba295e3a930659078ef674a"
stream="".join(cj(row)+"\n" for row in roster).encode()
assert len(stream)==72032 and digest(stream)=="e7c360ed9730d9dde9c38130a1a5fa15da2f1a53d52de10df76b42516ea6b0aa"

def pointer_tokens(pointer):
    assert pointer.startswith("/")
    return [part.replace("~1","/").replace("~0","~")
            for part in pointer[1:].split("/")]

def get_pointer(root,pointer):
    current=root
    for part in pointer_tokens(pointer):
        current=current[int(part)] if isinstance(current,list) else current[part]
    return current

def apply_patch_once(root,patch):
    parts=pointer_tokens(patch["path"]); current=root
    for part in parts[:-1]:
        current=current[int(part)] if isinstance(current,list) else current[part]
    leaf=parts[-1]; operation=patch["op"]
    if operation=="replace":
        if isinstance(current,list):
            assert 0<=int(leaf)<len(current)
            current[int(leaf)]=copy.deepcopy(patch["value"])
        else:
            assert leaf in current
            current[leaf]=copy.deepcopy(patch["value"])
    elif operation=="remove":
        if isinstance(current,list):
            assert 0<=int(leaf)<len(current)
            current.pop(int(leaf))
        else:
            assert leaf in current
            del current[leaf]
    elif operation=="add":
        if isinstance(current,list):
            assert 0<=int(leaf)<=len(current)
            current.insert(int(leaf),copy.deepcopy(patch["value"]))
        else:
            assert leaf not in current
            current[leaf]=copy.deepcopy(patch["value"])
    else:
        raise AssertionError(operation)

legacy_text=predecessor.read_text(encoding="utf-8")
legacy_match=re.search(r"<!-- BEGIN VECTOR_R3_7_STRUCTURAL_NEGATIVE_ROSTER -->\n```json\n(.*?)\n```\n<!-- END VECTOR_R3_7_STRUCTURAL_NEGATIVE_ROSTER -->",legacy_text,re.S)
assert legacy_match
legacy_compact=json.loads(legacy_match.group(1))
assert len(cj(legacy_compact).encode())==10979
assert digest(cj(legacy_compact).encode())=="818c18e1eea64b97b12a76e4a79a2a8b81ac8497eb6b1d9b8e26537c6d36d03a"
legacy_rows=[dict(zip(legacy_compact["columns"],values))
             for values in legacy_compact["rows"]]

rebuilt=[]; observed=[]
for global_ordinal,(spec,legacy,row) in enumerate(zip(specs,legacy_rows,roster)):
    assert (spec["family"],spec["ordinal"])==(legacy["family"],legacy["ordinal"])
    assert (row["family"],row["ordinal"],row["global_ordinal"])==(
        spec["family"],spec["ordinal"],global_ordinal)
    patch=spec["patch"]
    precondition_pointer=(patch["path"] if patch["op"]!="add"
                          else patch["path"].rsplit("/",1)[0])
    precondition=get_pointer(baseline,precondition_pointer)
    mutated=copy.deepcopy(baseline)
    apply_patch_once(mutated,patch)
    mutated_bytes=cj(mutated).encode()
    candidate={"family":spec["family"],"ordinal":spec["ordinal"],
      "global_ordinal":global_ordinal,
      "legacy_subject_pointer":legacy["subject_pointer"],
      "legacy_expected_primary":legacy["expected_primary"],
      "legacy_expected_subcode":legacy["expected_subcode"],
      "patch":patch,"precondition_pointer":precondition_pointer,
      "precondition_value_size_bytes":len(cj(precondition).encode()),
      "precondition_value_sha256":digest(cj(precondition).encode()),
      "baseline_subject_sha256":digest(baseline_bytes),
      "mutated_subject_size_bytes":len(mutated_bytes),
      "mutated_subject_sha256":digest(mutated_bytes),
      "validation_tier":spec["validation_tier"],
      "expected_primary":spec["expected_primary"],
      "expected_subcode":spec["expected_subcode"]}
    atom=digest(cj({"domain":"PROGRAM_FACTS_G3_R3_8_REAL_MUTATION_ATOM_V1",
                    "value":candidate}).encode())
    candidate["mutation_id"]="pfg3m8-"+atom[:32]
    candidate["atom_sha256"]=atom
    assert candidate==row
    result=validate(mutated_bytes)
    assert result==(row["expected_primary"],row["expected_subcode"])
    assert result[0]!="ACCEPTED"
    rebuilt.append(candidate); observed.append(result)
assert rebuilt==roster
families=["SIGNATURE_DEPENDENCY_NEGATIVE","WINDOWS_RENAME_NEGATIVE",
          "CROSS_SCHEMA_NEGATIVE"]
assert [sum(row["family"]==family for row in roster)
        for family in families]==[20,15,32]

# The validator receives the identical bytes after every oracle mutation.
# It has no reference to either roster object.
scrambled=copy.deepcopy(roster)
for index,row in enumerate(scrambled):
    row["expected_primary"]="SCRAMBLED_PRIMARY_"+str(66-index)
    row["expected_subcode"]="SCRAMBLED_SUBCODE_"+str(index)
independent=[]
for spec in specs:
    mutated=copy.deepcopy(baseline)
    apply_patch_once(mutated,spec["patch"])
    independent.append(validate(cj(mutated).encode()))
assert independent==observed
assert all(result!=(row["expected_primary"],row["expected_subcode"])
           for result,row in zip(independent,scrambled))

no_loss=extract_json("VECTOR_R3_8_LEGACY_NO_LOSS_MAP")
expected_no_loss=[]
for index,(legacy,row) in enumerate(zip(legacy_rows,roster)):
    expected_no_loss.append({"family":row["family"],"ordinal":row["ordinal"],
      "global_ordinal":index,"legacy_row_sha256":digest(cj(legacy).encode()),
      "r3_8_mutation_id":row["mutation_id"],
      "r3_8_atom_sha256":row["atom_sha256"]})
assert no_loss==expected_no_loss and len(no_loss)==67
assert len(cj(no_loss).encode())==20385
assert digest(cj(no_loss).encode())=="091eab06f3a30d541feb3fa8e8262dee308a80fa78fa7d425a80820f9e889011"

authority_names={"authoritative","evidence_authoritative",
 "production_execution_allowed","spawn_allowed","publication_allowed",
 "cutover_allowed","accepting_authority","durability_authority"}
def walk(value):
    if isinstance(value,dict):
        for key,member in value.items():
            if key in authority_names:
                assert member is False,(key,member)
            walk(member)
    elif isinstance(value,list):
        for member in value: walk(member)
walk(baseline)
assert baseline["aggregate"]["atomic_contract_result_count"]==2227
assert [baseline["aggregate"][key] for key in (
 "aggregate_outcome_index_count","aggregate_seam_index_count")]==[720,360]
assert [(row["outcome_result_count"],row["seam_result_count"])
        for row in baseline["aggregate"]["reviewed_profile_receipts"]]==[
        (352,176),(352,176),(16,8)]

print(cj({"status":"PASS_R3_8_REAL_MATERIALIZATION_AND_MUTATION_POWER",
 "validator_source_sha256":digest(validator_source.encode()),
 "baseline_sha256":digest(baseline_bytes),"mutation_count":67,
 "family_counts":[20,15,32],"independence_replays":67,
 "all_mutations_rejected":True,"atomic_contract_result_count":2227,
 "all_authority_and_enabling_false":True}))
```
<!-- END R3_8_DETERMINISTIC_SELF_CHECK -->

<!-- BEGIN R3_8_DETERMINISTIC_SELF_CHECK_IDENTITY -->
```json
{"expected_stdout_sha256":"e56d29aade6fba1fd3841e8e152a9f0c1369127e910b4820663df7126cd9703d","expected_stdout_size_bytes":420,"self_check_source_sha256":"a330cb551bdaf786b50e3591b885ce290928d346202fb910951fe29b0e0baf3e","self_check_source_size_bytes":12501}
```
<!-- END R3_8_DETERMINISTIC_SELF_CHECK_IDENTITY -->

## 11. Frozen R3.8 stable-draft boundary

This amendment closes the two R3.7 repair reviews without changing the frozen
R3.7 file or either review. Its operative claims are limited to the following:

- the five effective-root branches carry parsed semantic bodies, and the
  recursive occurrence walker covers those bodies rather than an opaque file;
- operation identity has four non-self-referential branch domains, including a
  typed Windows returned result and a null result in both no-return branches;
- every materialized per-operation receipt is indexed into one per-profile
  bundle, reviewed within the 256-subject limit, and bound exactly to the
  receipt hash embedded by the all-false authority object;
- compatibility rows bind declared symbol hash, compatibility-row hash,
  projection schema, actual field hash, and actual value schema;
- runtime identity is bound to invocation, boot session, PID, process-start
  ticks, target handle, observation epoch, and the executed production binary;
- the Windows minimum is parsed from one registered, externally pinned policy
  slice; Linux durability is derived from typed mount, device, epoch, and event
  evidence; neither platform capability enables authority;
- review chronology is the exact 27-node/42-edge DAG, with distinct registry,
  runtime, Windows-policy, Linux-profile, Linux-observation, bundle, profile,
  and native-authority reviews; and
- the accepted 830,508-byte baseline and all 67 independently rejected real
  mutations preserve the 20/15/32 legacy axes and the exact 2,227 denominator.

No launcher, provider, fixture, native API, publication, installation, cutover,
or deferred 15-edge admission bridge is executed or enabled here. This remains
a non-lineage, nonauthoritative stable-draft contract pending a separately
accepted bridge.
