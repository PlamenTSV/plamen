# Program Facts G3-00 protected-control-root recovery contract v1

Status: `CONTRACT_AND_PURE_FIXTURES_ONLY_PENDING_FRESH_INDEPENDENT_CONTRACT_AND_OPERATIONAL_REVIEWS`

This is a new-only authority-relocation contract. It imports the frozen v3-r2
semantic and transport design by exact identity, replaces only its repository-
authority boundary, and closes the frozen protected-control-root integration
review. It does not modify the v3-r2 contract, Edge 1/2 artifacts, Edge 3/4
candidates, launchers, production scripts, or reviews. It provisions no root,
changes no ACL or mode, launches no provider, executes no fixture, publishes no
native artifact, runs no audit, and grants no successor authority.

`MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` have RFC 2119 meanings.
`CJ(x)` is RFC 8785 canonical JSON over the integer/string/boolean/null subset,
encoded as strict UTF-8. `CF(x)` is `CJ(x) || LF`. `SHA-256` is lowercase hex.
All paths in governed values use `/` independently of host path syntax.

## 0. Frozen inputs and narrow supersession

The two governing inputs are:

| Role | Bytes | SHA-256 | Exact path |
|---|---:|---|---|
| frozen v3-r2 contract | 154,471 | `7deaa39309656775b86dcf7cc7952461deec51d0696961bc4447efab948eeafc` | `architecture/program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md` |
| frozen integration review | 13,319 | `4edbd6b4a6bdec2b0379540ffcb8a405e85a2be5bb37330f7dfd70a324c92589` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_INTEGRATION_REVIEW_V1.20260809.md` |

The already-created repository Edge 1/2 artifacts are frozen observation inputs
only and MUST NOT be edited, copied into authority, or grandfathered:

| Edge | Bytes | SHA-256 | Exact repository path |
|---:|---:|---|---|
| 1 | 10,245 | `7bb4e25560f643bbda4b215bb36489a297f7552b736ea68ed3fad31352c25f93` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V3_RECOVERY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` |
| 2 | 7,137 | `3078623acf57b5eb5844f5b21c6ca7b51f87ec37ffb41e75de7981aa71705f00` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_V2_BINDING_WRAPPER_FAILURE_OBSERVATION.v1.json` |

All v3-r2 semantic schemas, identity/body formulas, exact semantic projections,
principal-separation rules, edge keys, edge dependency vector, candidate bytes,
and completion-last transport rules remain imported unless this document states
an explicit authority-root substitution. In case of conflict, this document
governs only root selection, typed paths, authoritative publication references,
repository exports, path counts, worker exclusion, platform eligibility, and
the Edge 1/2 regeneration boundary.

The authoring support is new-only under
`Temp/g3_control_root_contract_v1/`. It is a pure model and negative fixture
suite, not implementation code or evidence. Its exact identities are recorded
in `FROZEN_AUTHORING_INPUTS.v1.json` after all bytes are fixed. That manifest is
nonauthoritative, contains an all-false authority ceiling, and does not hash or
approve itself.

## 1. Deterministic provider/subject root selection

There is exactly one logical control root for a tuple
`(provider_namespace, provider_version, subject_contract_identity_sha256)` in a
local installation. The subject/contract digest is:

```text
subject_contract_identity_sha256 = SHA-256(CJ({
  domain: "PLAMEN_G3_CONTROL_ROOT_SUBJECT_CONTRACT_IDENTITY_V1",
  subject: <exact three-field subject file identity>,
  contract: <exact three-field frozen v3-r2 contract identity>
}))
```

The trusted provider selector derives:

```text
logical_root_identifier = "g3cr-" || SHA-256(CJ({
  domain: "PLAMEN_G3_CONTROL_ROOT_SELECTOR_V1",
  provider_namespace: <registered stable provider namespace>,
  provider_version: <registered stable provider version>,
  subject_contract_identity_sha256: <digest above>
}))
```

Only installed, reviewed provider code maps this logical identifier beneath its
single fixed local control namespace. A caller path, environment variable,
configuration override, current working directory, repository root, PID,
timestamp, UUID, random suffix, temporary-directory choice, directory scan,
newest-directory selection, fallback root, or path marked `protected=true`
MUST NOT participate in selection. Restart derives the same identifier and
reopens the exact bound physical root. It MUST NOT discover or choose an
alternative. A missing or invalid bound root fails closed; it does not mint a
replacement identity silently.

The `binding_creation_epoch` is a provider-persisted Z20 monotonic fact used to
distinguish a separately reviewed future root-rotation ceremony. It never
selects a path, and this v1 contract authorizes no rotation or migration.

## 2. Control-root binding and threat boundary

The sole root-binding record is at control-relative path
`bindings/control-root-binding.v1.json`. Its schema version is exactly
`plamen.g3_control_root_binding.v1`; it is recursively closed and has exactly:

```text
schema_version,subject_contract_identity_sha256,provider_namespace,
provider_version,logical_root_identifier,selector_policy,platform,
filesystem_capability,root_physical_identity,retained_parent_physical_identity,
owner_principal,trusted_principal_set_sha256,security_policy_sha256,
ancestor_security_proof_sha256,durability_capability,no_replace_capability,
threat_model,binding_creation_epoch,worker_root_exclusion,authority_ceiling,
control_root_binding_sha256
```

`control_root_binding_sha256` is
`SHA-256(CJ(object_without_only_control_root_binding_sha256))`. No path string,
digest, owner claim, or `protected` boolean substitutes for native observations.
The binding MUST include:

- provider namespace and version plus the deterministic logical identifier;
- platform and local-filesystem capability profile;
- root and retained-parent physical identities obtained from open handles or
  descriptors, not lookups after the fact;
- owner and the digest of the exact trusted-principal set;
- security descriptor/DACL, POSIX ACL/mode, and ancestor-security proof digests;
- reviewed durability and no-replace capabilities;
- threat-model constant and binding creation epoch; and
- literal worker exclusion and all-false authority objects.

The trusted driver validates ownership, filesystem, ACL/mode, complete ancestry,
mount/reparse/alias state, physical identity, and capabilities before any lease
or attempt path is created. It retains root and parent handles/descriptors while
an edge transition is active. It revalidates the root binding at arm,
materialization, reconciliation, and completion. A physical identity, owner,
trusted-principal set, DACL/mode/ACL, ancestor, filesystem, mount, durability, or
no-replace drift fails closed. It cannot be repaired with equal bytes or a new
binding at the same pathname.

The exact threat model remains: one trusted driver writes the control namespace;
the host kernel is not compromised; the filesystem honors reviewed identity and
durability operations; untrusted code cannot write/delete/rename the root or a
mutable ancestor; consumers require a valid control completion; and private
stage aliases are nonconsumable. Same-user exclusion is claimed only to the
platform ceiling in section 6.

## 3. Typed path language and exact formula

`control_relative_path` and `repository_export_path` are disjoint nominal types,
not aliases of a shared `safe_path`.

A `control_relative_path` is relative to the reopened bound physical root and is
one of these exact formulas only:

```text
binding = "bindings/control-root-binding.v1.json"
prefix(i) = "edges/" || Z2(i) || "_" || lowercase(EDGE_KEY[i])
lease(i) = prefix(i) || "/publication.lease"
final(i) = prefix(i) || "/artifact.final"
attempt(i,a) = prefix(i) || "/attempts/" || Z20(a) || "/"
attempt leaves = attempt.json, payload.stage, publish-arm.json,
                 completion.json, debt.json
```

Here `1 <= i <= 15` and `0 <= a <= 99999999999999999999`. Formula probing begins
at zero and opens only successive exact leaves. Enumeration, globbing, newest-
file selection, random suffixes, timestamps, and alternate roots are forbidden.

A `repository_export_path` is one of the exact 15 v3-r2 repository final paths.
It is never valid in a control file identity, attempt, arm, completion, debt,
control predecessor, or control `published_ref`. Conversely a control-relative
path is invalid as a repository export path. Absolute paths occur only inside
trusted provider implementation state and are never serialized as authority.

The static materializable path set is exactly:

```text
17 legacy predecessor/debt paths, including the required-absent GREEN-v2 path
 1 frozen v3-r2 governing contract path
15 nonauthoritative repository export final paths
15 control-root lease paths
15 authoritative control-root final paths
 1 control-root binding path
--
64 static paths
```

For contiguous attempt-prefix lengths `A[1]..A[15]`, the exact path count is:

```text
64 + 5 * SUM(A[i])
```

There is no per-attempt repository-export receipt. Adding one changes the
formula and requires a new reviewed contract. Repository export observation is
not an attempt leaf. Missing, corrupt, or extra repository files do not affect
attempt discovery.

## 4. Root-bound record schemas

All governed JSON is strict `CF`, recursively closed, and rejects duplicate
keys, unknown fields, unsafe integers, non-UTF-8, BOM, CR, noncanonical escapes,
non-finite values, and trailing bytes. Every attempt, arm, completion, and debt
binds `control_root_binding_sha256`, control-relative paths, edge/attempt
ordinal, candidate digest, platform physical identities, and the root
revalidation appropriate to its transition. Attempt predecessors are only
`plamen.g3_control_published_ref.v1` objects.

### 4.1 Attempt

Schema version `plamen.g3_control_attempt.v1` has exactly:

```text
schema_version,attempt_id,control_root_binding_sha256,edge_ordinal,edge_key,
attempt_ordinal,record_paths,control_final_plan,candidate_sha256,
predecessor_control_publications,parent_physical_identity,authority_ceiling,
attempt_body_sha256
```

The five `record_paths` and final plan must equal the section-3 formulas. Every
predecessor binding digest must equal the active root binding. A repository
identity is schema-invalid in this array.

### 4.2 Durable arm

Schema version `plamen.g3_control_publish_arm.v1` has exactly:

```text
schema_version,arm_id,control_root_binding_sha256,edge_ordinal,edge_key,
attempt_ordinal,attempt,payload_stage,planned_control_final,
lease_physical_identity,arm_physical_identity,parent_physical_identity,
stage_physical_identity,root_revalidation,platform_protocol,authority_ceiling,
arm_body_sha256
```

The arm is complete, flushed with its parent, and stable-reread before
materialization. It binds three target-absence observations, the candidate,
same-volume join, retained identities, and the unchanged root security binding
through its body and referenced attempt. No arm may be copied or synthesized
after a final appears.

### 4.3 Completion

Schema version `plamen.g3_control_completion.v1` has exactly:

```text
schema_version,completion_id,control_root_binding_sha256,edge_ordinal,edge_key,
attempt_ordinal,attempt,publish_arm,control_final_artifact,
parent_physical_identity,stage_physical_identity,final_physical_identity,
root_revalidation,completion_grade,completion_marker_rule,authority_ceiling,
completion_body_sha256
```

Only the future grade
`PROTECTED_CONTROL_ROOT_IDENTITY_PRESERVING_MATERIALIZATION` can satisfy a
control predecessor after all joins are independently revalidated. This
contract and its fixtures instantiate no such governed record. The grade binds
the durable arm, same physical staged/final object, exact candidate bytes,
singly linked final, absent stage, unchanged root/parent/security binding,
completion-last ordering, and the imported normalized namespace-poststate
rules. A postcondition-only or equality-only final never enables.

### 4.4 Debt

Schema version `plamen.g3_control_debt.v1` has exactly:

```text
schema_version,debt_id,control_root_binding_sha256,edge_ordinal,edge_key,
attempt_ordinal,attempt,reason,observed_control_objects,
control_final_absence_observations,advance_disposition,root_revalidation,
authority_ceiling,debt_body_sha256
```

Debt may advance exactly one ordinal only for a stable current-attempt mismatch,
a formula-valid debt record, three current control-final absence observations,
and an unchanged valid root binding. A present control final never advances.
Repository export failure, absence, mismatch, or corruption is not debt and does
not advance an attempt.

## 5. Authoritative control reference and nonauthoritative export

`plamen.g3_control_published_ref.v1` is recursively closed and has exactly:

```text
schema_version,control_root_binding_sha256,artifact,attempt_ordinal,
completion_grade,publication_arm,publication_completion
```

`artifact`, `publication_arm`, and `publication_completion` are closed control
file identities with exactly
`{control_relative_path,size_bytes,sha256}`. Their formulas, parsed record IDs,
physical identities, root digest, candidate hash, edge and attempt ordinals, and
completion-last ordering MUST join. Only this type may be a fresh predecessor or
enable a downstream edge. The repository has no `published_ref` type.

`plamen.g3_repository_export.v1`, if an export observation is retained, is
recursively closed and has exactly:

```text
schema_version,source_control_published_ref,repository_export_path,
transformation,observed_size_bytes,observed_sha256,completion_authority,
predecessor_authority,resume_authority,attempt_discriminator_authority,
publication_authority,debt_authority,authority_ceiling
```

`transformation` is normally `IDENTICAL_BYTES`. All six named authority fields
are literal `false`; the complete authority ceiling is also all false. The
source control reference remains authoritative independently of export state.
An export can be absent, partial, corrupt, deleted, or recreated on demand. No
export filename, timestamp, order, bytes, checksum, or equality can choose an
attempt, prove completion, serve as a predecessor, resume publication, create
debt, revoke control completion, or authorize a fallback root.

The preferred implementation stores a control-side export plan and verifies
repository equality on demand. It does not create a sixth attempt leaf. Export
occurs only after the complete control chain has been revalidated and is always
last. The driver MUST NOT mutate a completed control artifact in response to an
export outcome.

## 6. Platform capability ceilings

### 6.1 Windows

Windows is conditionally supportable only after a fresh native provider and
validator pass independent operational review. The root must be on fixed local
NTFS or ReFS. Every component rejects reparse points, aliases, alternate data
streams, case/Unicode ambiguity, and mount redirection. The root has a protected
DACL and exact trusted SID set; no foreign principal has write, append, delete,
delete-child, `WRITE_DAC`, or `WRITE_OWNER` on the root or a mutable ancestor.
Owner, link count, volume serial, and 128-bit file identity come from retained
handles. The volume serial is losslessly encoded as 16 lowercase hex digits.

No-replace requires reviewed parent-relative
`SetFileInformationByHandle(FileRenameInfoEx)` with replacement unset.
Durability requires `FlushFileBuffers` for file and directory handles at the
imported checkpoints. Fixture children remain low integrity while the control
root remains medium integrity, and receive neither a writable root grant nor a
retained control handle. Other processes under the same trusted SID remain in
the TCB; this contract does not claim hostile same-SID exclusion.

### 6.2 Linux

Linux is conditionally supportable only after a fresh native provider and
validator pass independent operational review. It requires a reviewed local
filesystem, expected UID, no group/world write, no foreign access/default ACL,
safe complete ancestry, no symlink/bind-mount/mount ambiguity, retained
directory descriptors, `renameat2(RENAME_NOREPLACE)`, and file/directory
`fsync`. Delegated cgroup v2 and Landlock must confine fixture children to a
writable-root set that excludes the control root and its ancestors. Mode `0700`
alone is not same-UID exclusion and cannot satisfy the profile.

### 6.3 macOS

macOS is unsupported for enabling fixture publication in the current stack.
Before any lease or attempt path is touched, validation fails with
`UNSUPPORTED_FOR_ENABLING_FIXTURE_PUBLICATION`. No substitute primitive,
postcondition, or `chmod 0700` weakens this result. Future support requires a new
review of native sandbox authority excluding the root, exhaustive process
authority, `renameatx_np(RENAME_EXCL)`, `F_FULLFSYNC`, and complete owner,
extended-ACL, filesystem, and ancestor verification.

## 7. Worker exclusion and trusted-driver sequence

The bound control root and every ancestor through the provider namespace MUST be
outside every worker writable-root grant. A worker receives no root path, no
binding record, no inherited root/parent/lease handle, and no API that can mint
control authority. A worker can write only its separately leased auxiliary
scratch/capture root. Auxiliary-root ownership, random selection, `0700`, or
resource-grant policy never establishes control-root protection.

The only future integration sequence is:

1. trusted driver derives and reopens the deterministic bound root;
2. native validator validates platform, filesystem, owner, trusted principals,
   security policy, ancestry, physical identity, worker-grant exclusion,
   durability, and no-replace capabilities;
3. fixture child writes only to its auxiliary lease;
4. process population reaches zero and is proven;
5. trusted driver captures the candidate bytes;
6. auxiliary lease is revoked;
7. trusted driver revalidates the control binding, publishes attempt/stage/arm/
   final/completion under the retained control root, and releases the lease; and
8. an optional nonauthoritative repository export occurs last.

Any grant containing the control root, descendant, ancestor escape, or retained
handle fails before child launch. No worker receipt, subprocess return, provider
report, or resource grant can write a control record or construct a control
`published_ref`.

## 8. Crash and reconciliation behavior

Recovery holds the exact inert control lease and probes only formula paths.
There is no scan and no content-equality adoption.

| Observed state | Required disposition |
|---|---|
| before attempt | derive the current formula ordinal; create nothing during inspection |
| exact prefix of `attempt.json` | append only the unique canonical suffix, flush, and revalidate |
| exact prefix of `payload.stage` | append only the unique candidate suffix, flush, and revalidate |
| valid durable arm, stage singly linked, final absent | revalidate binding and permit only reviewed control materialization |
| valid arm, stage and final are the same object with exactly two links | keep both private; remove only the formula stage alias; flush and revalidate final-only state |
| valid arm, stage absent, singly linked final is the armed object with exact bytes | revalidate binding and imported normalized poststate; completion may be written last |
| final exists before valid arm, or equal bytes have another identity | terminal nonenabling; never adopt, replace, synthesize arm, or advance |
| copied arm/completion, changed root identity, policy drift, or fallback root | reject and fail closed |
| valid control completion | acknowledge read-only after complete independent revalidation |
| crash during export | control completion is unchanged; export may retry independently |
| crash after export | control completion is unchanged; export remains nonauthoritative |
| deleted, corrupt, or mismatched export | no control debt, no attempt advance, no revocation |

A partial record resumes only when it is an exact prefix of bytes already fully
determined from trusted inputs. Complete equal bytes are read-only revalidation,
not adoption. Equal repository bytes, copied control bytes, or a reconstructed
record without the bound arm/physical identity chain have no authority.

## 9. Edge 1/2 boundary and control-only DAG

This v1 contract chooses **fresh regeneration**, not migration. Edges 1 and 2
must be independently regenerated and freshly published under the validated
control root before Edge 3. Their existing repository objects remain frozen and
nonauthoritative. Their exact bytes may inform human review, but neither content
equality, a copied record, an old repository completion, nor a repository path
can establish a new control predecessor.

A migration/root-anchor ceremony is explicitly outside this contract. It would
require its own fresh independent contract and operational reviews and would
have to pin semantic bytes without inheriting any old transport authority. No
code path may treat the existence of that future option as present permission.

The exact 15-edge predecessor vector remains:

```text
[[],[1],[2],[3],[3,4],[5],[6],[6,7],[6,7,8],[9],[10],[11],[12],[11,12,13],[11,12,13,14]]
```

Every vertex is an authoritative control final named by a valid
`plamen.g3_control_published_ref.v1`. Every reference has a strictly smaller
edge ordinal. Kahn's order is exactly `[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]`.
Repository exports are presentation edges outside the DAG. They cannot be roots,
vertices, predecessors, completion markers, resume markers, or attempt
discriminators. The DAG contains no worker root, auxiliary lease, execution
trace, repository completion, or migration anchor.

## 10. Fixture-first pure authoring contract

Before production implementation, fixture authors use only the pure model at:

```text
Temp/g3_control_root_contract_v1/control_root_fixture_model_v1.py
Temp/g3_control_root_contract_v1/test_control_root_fixture_model_v1.py
```

The model performs only deterministic in-memory JSON, hashing, path, formula,
DAG, and state classification. It imports only Python stdlib, makes no provider
or subprocess call, and has no filesystem-write function. The test module does
not execute automatically and is not evidence. It defines exactly these 48
fixture IDs:

```text
G3CR-001-DETERMINISTIC-PROVIDER-SUBJECT-ROOT
G3CR-002-CALLER-ENV-UUID-PID-TIME-SELECTOR-REJECTED
G3CR-003-ROOT-BINDING-CLOSED-SCHEMA
G3CR-004-DUPLICATE-JSON-KEY-REJECTED
G3CR-005-UNKNOWN-FIELD-REJECTED
G3CR-006-ROOT-DIGEST-MUTATION-REJECTED
G3CR-007-CONTROL-AND-EXPORT-PATH-TYPES-DISJOINT
G3CR-008-CONTROL-PUBLISHED-REF-AUTHORITATIVE-TYPE
G3CR-009-REPOSITORY-EXPORT-ALL-AUTHORITY-FALSE
G3CR-010-EXACT-64-PLUS-5-SUM-A-FORMULA
G3CR-011-CONTROL-ONLY-DAG
G3CR-012-WORKER-WRITABLE-ROOT-EXCLUSION
G3CR-013-WINDOWS-FOREIGN-WRITER-REJECTED
G3CR-014-WINDOWS-WRONG-OWNER-REJECTED
G3CR-015-WINDOWS-PARENT-DELETE-CHILD-REJECTED
G3CR-016-WINDOWS-UNPROTECTED-DACL-REJECTED
G3CR-017-WINDOWS-REPARSE-OR-ADS-REJECTED
G3CR-018-WINDOWS-PHYSICAL-IDENTITY-DRIFT-REJECTED
G3CR-019-WINDOWS-CONDITIONAL-CAPABILITY-CEILING
G3CR-020-LINUX-WRONG-UID-REJECTED
G3CR-021-LINUX-GROUP-OR-WORLD-WRITE-REJECTED
G3CR-022-LINUX-FOREIGN-ACCESS-ACL-REJECTED
G3CR-023-LINUX-FOREIGN-DEFAULT-ACL-REJECTED
G3CR-024-LINUX-WRITABLE-ANCESTOR-REJECTED
G3CR-025-LINUX-BIND-MOUNT-OR-MOUNT-AMBIGUITY-REJECTED
G3CR-026-LINUX-LANDLOCK-OMISSION-REJECTED
G3CR-027-LINUX-CGROUP-V2-OMISSION-REJECTED
G3CR-028-LINUX-CONDITIONAL-CAPABILITY-CEILING
G3CR-029-MACOS-UNSUPPORTED-BEFORE-ATTEMPT
G3CR-030-EDGE1-EDGE2-FRESH-REGENERATION-ONLY
G3CR-031-CRASH-BEFORE-ATTEMPT
G3CR-032-CRASH-DURING-ATTEMPT-PREFIX
G3CR-033-CRASH-DURING-STAGE-PREFIX
G3CR-034-CRASH-AFTER-DURABLE-ARM
G3CR-035-CRASH-TWO-LINK-PRIVATE-ALIAS
G3CR-036-CRASH-FINAL-ONLY-AFTER-ARM
G3CR-037-CRASH-AFTER-CONTROL-COMPLETION
G3CR-038-CRASH-DURING-REPOSITORY-EXPORT
G3CR-039-CRASH-AFTER-REPOSITORY-EXPORT
G3CR-040-REPOSITORY-ONLY-EXACT-ARTIFACT-NONENABLING
G3CR-041-EQUAL-BYTES-NOT-ADOPTED
G3CR-042-COPIED-ARM-OR-COMPLETION-REJECTED
G3CR-043-TAMPERED-EXPORT-DOES-NOT-REVOKE-CONTROL-COMPLETION
G3CR-044-VALID-CONTROL-COMPLETION-IS-SOLE-DAG-PREDECESSOR
G3CR-045-PHYSICAL-ROOT-IDENTITY-DRIFT-FAILS-CLOSED
G3CR-046-FALLBACK-OR-NEWEST-ROOT-SELECTION-REJECTED
G3CR-047-POST-ARM-SECURITY-POLICY-DRIFT-FAILS-CLOSED
G3CR-048-EXPORT-FAILURE-CREATES-NO-ATTEMPT-DEBT
```

The fixtures cover closed/duplicate/unknown schemas, root-binding digest
mutations, typed path separation, export false authority, the exact count
formula, the control-only DAG, all platform ceilings, all named crash seams,
fresh Edge 1/2 regeneration, repository-only/equality/copied-record rejection,
export tamper independence, root/policy drift, and worker exclusion. They do not
touch a governed final, lease, attempt, root, ACL, mode, native primitive,
provider, launcher, audit, install, commit, or push.

## 11. Read-only self-check and identity freeze

`Temp/g3_control_root_contract_v1/readonly_self_check_v1.py` is the sole authoring
self-check. It MAY be run only with bytecode writing disabled. It reads and
hashes the frozen inputs and authoring files, parses the nonauthoritative freeze
manifest, invokes the pure model checks, and prints a canonical result to
stdout. It MUST NOT create/update a manifest, provision a root, alter security,
run unittest, execute native publication, invoke a provider/launcher/audit, or
grant authority. Its result contains the exact all-false authority ceiling.

The self-check proves only authoring coverage and byte identity. `PASS` means
that the reviewed source set matches the manifest and the pure invariants are
internally consistent. It is not a contract review, operational review,
implementation approval, fixture execution, publication completion,
predecessor, admission, provider permit, or audit result.

## 12. Authority ceiling, review boundary, and terminal state

Every persisted authoring JSON uses the exact 39-member `authority_ceiling`
defined by the pure model, with every value literal `false`. In particular,
`contract_approval`, `operational_approval`, `control_root_provisioning`,
`native_publication`, `fixture_execution`, `edge_regeneration`, and `migration`
are false in addition to the frozen v3-r2 authority fields. Markdown statements,
source constants, fixture success, file hashes, and the self-check cannot raise
that ceiling.

Before any production implementation, two new reviews are mandatory and
independent of this author:

1. a contract review of the exact frozen contract/model/test/self-check bytes,
   all schemas and formulas, the 64-path inventory, root-selection preimage,
   root-binding digest, typed path separation, control-only DAG, Edge 1/2 fresh
   regeneration, authority ceiling, and no-equality-adoption rules; and
2. an operational review for each host profile. Windows and Linux must prove all
   native capability predicates and adversarial negative cases. macOS is
   expected to fail before an attempt path until a new reviewed capability stack
   exists.

Only after both reviews pass may a separate implementation contract authorize
production source work. That later work must still begin RED, must not use this
self-check as evidence, and must not reuse repository Edge 1/2 transport
authority. This document stops at contract and fixture authorship. Its terminal
state is:

```text
CONTRACT_AND_PURE_FIXTURES_ONLY_PENDING_FRESH_INDEPENDENT_CONTRACT_AND_OPERATIONAL_REVIEWS
```

No successor operation is authorized by this document or its authoring support.
