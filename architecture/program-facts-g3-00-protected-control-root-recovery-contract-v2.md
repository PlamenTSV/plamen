# Program Facts G3-00 protected-control-root recovery contract v2

Status: **NEW-ONLY DESIGN SUCCESSOR; PURE MODEL GREEN; INDEPENDENT REVIEW REQUIRED**

This document repairs the frozen v1 semantic and platform/operational REPAIR
verdicts. It specifies a protected out-of-tree control namespace, but it does
not provision one and cannot authorize one. Repository artifacts remain
nonauthoritative exports. No statement in this document is native evidence.

## 0. Frozen inputs, supersession, and authority ceiling

This v2 generation preserves every v1 byte and review. It narrowly supersedes
the v1 design for future implementation planning only.

| Role | Bytes | SHA-256 | Path |
|---|---:|---|---|
| frozen G3-00 v3-r2 contract | 154,471 | `7deaa39309656775b86dcf7cc7952461deec51d0696961bc4447efab948eeafc` | `architecture/program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md` |
| protected-root v1 contract | 27,709 | `ec060632ef0b461ca0d69d66effc941f5ed08367bf36aecb9f3859529104c095` | `architecture/program-facts-g3-00-protected-control-root-recovery-contract-v1.md` |
| v1 semantic REPAIR review | 17,402 | `e09a9a7dc01b8d8c8d4dd29eb59461e64015db6e6cef1954a8490dea4b91dde3` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V1_SEMANTIC_REVIEW_ec060632ef0b.md` |
| v1 final platform REPAIR review | 34,807 | `961d25719c3b8f35d3d540c529e41a8285ae165859692fb72e56e4e5ce7cd435` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V1_PLATFORM_OPERATIONAL_REVIEW_ec060632ef0b.md` |
| Edge 3/4 v4 code-only review | 10,500 | `0a4e3074979ad6c32c6fbd9d7c26b21245ed6c48805233fd8fd974b8f3fca90e` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V3_EDGES_3_4_PREPUBLICATION_REVIEW_V4.20260809.md` |
| proposed installed-provider registry profile (not installed) | 1,232 | `598adf59f67ede05d841dbde075e1b237687baa6b07562b10262d5e439990043` | `Temp/g3_control_root_contract_v2/installed_provider_registry_profile_v2.json` |

The Edge 3/4 disposition is
`PASS_PREPUBLICATION_CODE_ONLY_ENVIRONMENT_UNAVAILABLE`. It is useful
code-review evidence, but it is not fixture execution, root availability,
publication, or predecessor authority. All fourteen governed paths were absent
at that review boundary.

The 39-member authority object from v1 remains exact and literal-false. This
authoring generation grants no contract approval, fixture execution, native
prototype, provider, operational approval, control-root provisioning,
publication, Edge 1/2 regeneration, Edge 3 execution, migration, installation,
commit, push, cutover, audit, finding, severity, or report authority.

## 1. Closed obligation matrix and fixture-first evidence

The successor obligation catalog is executable data in
`Temp/g3_control_root_contract_v2/obligation_matrix_v2.py`. It contains exactly
seven semantic rows (`G3CR2-S01` through `G3CR2-S07`) and 28 platform/operational
rows (`G3CR2-O01` through `G3CR2-O28`). Every row binds one independently named
test method. Catalog membership is not coverage.

Before the v2 model existed, the frozen v1 subject was run against the 35 RED
fixtures in `test_v1_accepted_invalid_red_v2.py`: 35 tests ran and all 35 were
RED. Seven reproduce accepted-invalid semantic behavior; 28 establish missing
typed operational contracts. `RED_RECEIPT.v2.json` pins that result and its
pre-implementation fixture identities.

The green suite must retain all of these properties:

1. one named executable predicate per obligation;
2. an independent mutation, not a constant-table membership assertion;
3. an exact public entrypoint and diagnostic;
4. a poststate assertion;
5. subject and prerequisite identities; and
6. an evidence class that cannot turn pure-model execution into native proof.

## 2. Governance stages remove the v1 review deadlock

The lifecycle has four distinct stages. No stage self-authorizes the next.

1. **Design authoring.** Pure model and prose are all-authority-false.
2. **Disposable native prototype authorization.** Two independent design
   reviews of exact frozen v2 bytes may authorize writing and executing a
   prototype only in reviewer-owned disposable fixtures. The authorization
   remains all-authority-false for production, governed roots, and edges.
3. **Native acceptance.** Independent Windows and Linux reviewers bind exact
   source, binary, toolchain, OS build, kernel, filesystem, mount/volume, and
   fixture receipts. This still does not create a governed root.
4. **Production integration.** A separate explicit integration contract may
   consume the native acceptances. Provisioning and Edge 1/2 regeneration each
   require later, separately reviewed ceremonies.

Design review never masquerades as native acceptance. A prototype receipt can
never become a predecessor, publication, operational approval, or production
permit. `validate_governance_stage` models the minimum review inputs and keeps
the three operative authorization flags `NO` in this generation.

## 3. Trusted external registry, selector, anchor, and bootstrap

### 3.1 Exact registered tuple

The logical root selector accepts only this installed-provider tuple:

```text
provider_namespace = "plamen.local.g3-control-root"
provider_version   = "2.0.0"
subject_identity   = exact three-field identity of the frozen v1 contract
governing_contract = exact three-field identity of frozen G3-00 v3-r2
registry_record    = exact bytes of the proposed registry profile above
```

Every file identity is exactly `{path,size_bytes,sha256}` with a strict integer
size and lowercase SHA-256. Let `CJ(x)` be the strict canonical JSON encoding
defined in section 4. Then:

```text
S = SHA256(CJ({
  "domain":"PLAMEN_G3_CONTROL_ROOT_SUBJECT_CONTRACT_IDENTITY_V2",
  "subject":subject_identity,
  "governing_contract":governing_contract_identity
}))

logical_root_identifier = "g3cr2-" || SHA256(CJ({
  "domain":"PLAMEN_G3_CONTROL_ROOT_SELECTOR_V2",
  "provider_namespace":provider_namespace,
  "provider_version":provider_version,
  "subject_contract_identity_sha256":S,
  "registry_record_sha256":registry_record_sha256
}))
```

The profile is presently marked `PROPOSED_BYTES_NOT_INSTALLED`; its digest is a
design input, not evidence that a registry exists. A later reviewed installation
must reproduce these exact bytes at an accepted external anchor or explicitly
revise and re-review the selector tuple. Caller paths, environment paths, PIDs,
timestamps, UUIDs, random values,
directory scans, newest-directory selection, fallback roots, and provider-
version substitution are forbidden selector inputs.

### 3.2 External anchor

The installed namespace mapping is exact and is not read from environment
variables. Windows resolves `FOLDERID_ProgramData` through the native Known
Folder API and then uses constant suffix `Plamen/g3-control/v2`; Linux uses
`/var/lib/plamen/g3-control/v2`. Beneath that base, `registry.json`,
`anchors/<logical>.anchor.json`, and `roots/<logical>` are the only registry,
anchor, and child formulas. The later installer/provider acceptance must prove
the complete base ancestry and dedicated driver/service ownership. A system
without that installed protected base is unsupported; it does not fall back to
a user-writable or environment-selected directory.

The installed-provider registry and root-anchor record live outside the child
they authenticate. The anchor binds the exact provider tuple, `S`, logical
identifier, binding epoch, retained parent identity, child identity, and
platform. It is create-only/no-replace and requires successful file and parent
namespace durability observations. The anchor body digest excludes only its
own digest field.

Root-binding validation consumes the complete external anchor and complete
typed platform observation, recomputes both digests, and joins their parent and
root physical identities. A digest-shaped caller value is insufficient. The
child binding cannot authenticate its own replacement. Reopen begins from
the externally pinned registry and anchor, opens each ancestor and the child
without following aliases, captures physical identities, and compares the
complete binding. Missing, partial, corrupt, replaced, retired, or old-provider
state returns `FAIL_CLOSED_NO_REMINT`. It never creates a replacement, scans,
or adopts equal bytes.

### 3.3 Bootstrap crash transaction

Provisioning, when separately authorized, is a nine-state transaction:

```text
ABSENT
 -> ANCHOR_CREATED_UNFLUSHED
 -> ANCHOR_FILE_FLUSHED
 -> ANCHOR_PARENT_FLUSHED
 -> CHILD_CREATED_UNBOUND
 -> BINDING_WRITTEN_UNFLUSHED
 -> BINDING_FILE_FLUSHED
 -> BINDING_PARENT_FLUSHED
 -> COMPLETE
```

Every state has one deterministic resume or fail-closed disposition in
`BOOTSTRAP_TRANSITIONS`. Any ambiguous flush, unexpected native error,
self-consistent replacement, or state outside the table requires manual
recovery and forbids reminting. The root and parent must be distinct directory
objects, on the same admitted volume/mount, with the root identity observed by
opening the named child relative to the retained parent handle/descriptor.

## 4. Strict CF and satisfiable Draft-2020-12 schemas

`CJ` admits only objects with string keys, arrays, strings, literal booleans,
null, and integers in `[-9007199254740991, 9007199254740991]`. It rejects
floats, NaN/infinity, unsafe integers, duplicate keys, non-UTF-8, BOM, CR,
multiple/trailing line breaks, noncanonical whitespace/order/escaping, and a
Python boolean at any integer locus. A canonical file is `CJ(value)` followed
by exactly one LF.

The v2 model exposes seven complete Draft-2020-12 schemas:

```text
root_binding, attempt, arm, completion, debt, published_ref, repository_export
```

Every required property appears in `properties`; every object, including every
nested object, is closed with `additionalProperties:false` or an exact `const`.
Integers carry safe bounds; enums and ID patterns are explicit. A real
`Draft202012Validator` must accept one complete example and reject missing,
unknown, nested-unknown, wrong-enum, unsafe numeric, and bool-as-int mutations
for every schema.

## 5. Exact path language, denominator, and control-only DAG

For edge `i in 1..15`, let `K[i]` be the exact frozen key and `Z20(a)` the
20-digit zero-padded attempt ordinal:

```text
E(i) = edges/{i:02d}_{lower(K[i])}
lease(i) = E(i)/publication.lease
final(i) = E(i)/artifact.final
attempt(i,a) = E(i)/attempts/Z20(a)/attempt.json
stage(i,a) = E(i)/attempts/Z20(a)/payload.stage
arm(i,a) = E(i)/attempts/Z20(a)/publish-arm.json
completion(i,a) = E(i)/attempts/Z20(a)/completion.json
debt(i,a) = E(i)/attempts/Z20(a)/debt.json
```

No regex alone grants a typed role. Constructors validate ordinal, exact key,
leaf role, and attempt ordinal. The static inventory is exactly 64 distinct
typed paths: 17 legacy inputs, the frozen governing contract, 15 repository
exports, 15 control leases, 15 control finals, and
`bindings/control-root-binding.v2.json`. For attempt prefix lengths `A[1..15]`:

```text
N(A) = 64 + 5 * SUM(A[i])
```

`A` is exactly 15 strict nonnegative integers. Boolean coercion is forbidden.

The exact predecessor vector is:

```text
(), (1), (2), (3), (3,4), (5), (6), (6,7), (6,7,8),
(9), (10), (11), (12), (11,12,13), (11,12,13,14)
```

It has exactly 15 vertices and 23 arcs, all backward, with Kahn order 1..15.
Self-checks compare the exact key and predecessor vectors, not merely the
resulting topological order.

## 6. Bound record calculus

All IDs use explicit v2 domains. For a record `R`, `BODY(R,d)` removes only
digest field `d`; `RID(R,id,d)` removes both the ID field and digest field.

```text
attempt_id    = "g3a-" || SHA256(CJ({domain:"PLAMEN_G3_ATTEMPT_ID_V2",body:RID(...)}))
arm_id        = "g3r-" || SHA256(CJ({domain:"PLAMEN_G3_ARM_ID_V2",body:RID(...)}))
completion_id = "g3c-" || SHA256(CJ({domain:"PLAMEN_G3_COMPLETION_ID_V2",body:RID(...)}))
debt_id       = "g3d-" || SHA256(CJ({domain:"PLAMEN_G3_DEBT_ID_V2",body:RID(...)}))
*_body_sha256 = SHA256(CJ(BODY(...)))
```

Every record joins the root-binding digest, exact edge ordinal/key, strict
attempt ordinal, exact formula paths, candidate digest, exact predecessor
vector, and exact all-false authority ceiling.

`root_revalidation` is mandatory at attempt, arm, materialization/completion,
and debt transitions. It is a typed native-observation reference containing
the exact binding digest, external anchor digest, native-observation digest,
transition name, root physical identity, and parent physical identity. Missing
or caller-selected booleans never pass.

The attempt binds all five record paths, final plan, candidate, and complete
same-root predecessor references. The arm binds the attempt and stage file
identities, planned final, candidate, lease/arm/stage physical identities,
retained parent, platform protocol, and arm-time revalidation. Completion is
written last and joins the exact attempt, arm, final, candidate, preserved
stage-to-final physical identity, parent, and completion-time revalidation.
Debt is always nonadvancing/nonenabling, joins the formula attempt, records
only formula-valid observed objects, requires independent final-absence
observations, and is root-revalidated.

## 7. Enabling references and nonauthoritative exports

Only `plamen.g3_control_published_ref.v2` can represent an enabling predecessor.
Validation consumes the underlying attempt, arm, completion, and context. It
proves all of the following, not just syntactic paths:

- edge 1..15 and exact frozen key;
- one exact root binding and attempt ordinal across all records;
- exact candidate digest across attempt, stage/final, completion, and ref;
- artifact is precisely `final(i)`;
- arm is precisely `arm(i,a)` with exact canonical bytes identity;
- completion is precisely `completion(i,a)` with exact canonical bytes identity;
- the published-reference body digest is recomputed over every member other
  than its own digest field;
- completion grade is the v2 identity-preserving grade;
- attempt predecessors and reference predecessor ordinals equal the frozen DAG
  vector; and
- every underlying record formula and mandatory root revalidation passes.

Cross-role, off-formula, other-edge, other-attempt, other-root, copied, and
repository references fail.

Repository exports are restricted to the exact 15 frozen destination enums.
Rooted nofollow I/O is required even though exports are nonauthoritative.
`IDENTICAL_BYTES` requires observed size and SHA-256 to equal the source final;
otherwise the record must say `OBSERVED_MISMATCH_NONAUTHORITY`. Absence,
partial write, corruption, deletion, or retry never changes control completion,
attempt count, debt count, or DAG authority.
The export transition table is total over absent, formula-partial, exact,
mismatch, unsafe path, ambiguous flush, and replaced repository-root states;
every disposition preserves the before/after control digest and counters.

## 8. Native observation preimages: common rule

Security decisions consume typed observation preimages captured by the trusted
launcher from retained handles/descriptors and process/token/kernel APIs. They
do not consume `safe:true`, caller-selected classifications, path strings, or
agent prose. Each preimage binds platform/build, capture sequence, physical
identities, policy inputs, native results/errors, and a receipt digest.
Every digest-bearing security field also carries its recursively closed
canonical preimage. Validation recomputes the digest and joins semantic members
back to the enclosing observation. Windows covers the security descriptor,
trusted/token SID sets, worker token, feature profile, and fault receipt;
Linux covers the Landlock ruleset, cgroup delegation identity and receipt,
mount namespace, mount options, and fault receipt. An opaque 64-hex assertion
without its matching preimage fails.

The current pure examples deliberately say
`PURE_MODEL_FIXTURE_NOT_NATIVE`. They exercise schema and transition logic but
cannot satisfy native acceptance. A later prototype must replace them with
actual observations, freeze source/binary/toolchain/profile identities, and be
independently rerun.

Worker topology is handle-derived. Every writable grant must be physically
disjoint from the root and all protected ancestors; equal, ancestor,
descendant, alias, bind/reparse, replaceable, inherited-handle, and
passed-handle relationships fail before child launch.

## 9. Windows prototype contract

Windows is only conditionally supportable on an exact independently accepted
NTFS profile. ReFS is disabled until the identical matrix passes separately.

### 9.1 Effective access and ancestry

For the root, every mutable object, and every ancestor through the installed
anchor, map generic rights and evaluate canonical allow/deny order,
inherit-only/effective ACEs, owner and `OWNER_RIGHTS`, nested groups, services,
packages, and the complete token SID set. The mutation mask is exactly:

```text
FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_WRITE_DATA, FILE_APPEND_DATA,
FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, DELETE, FILE_DELETE_CHILD,
WRITE_DAC, WRITE_OWNER
```

No foreign effective mutation right is allowed. Each component is opened
without following a reparse point and binds descriptor, owner, physical
identity, object type, and child identity. A mutable grandparent is as fatal as
a mutable immediate parent.

### 9.2 Path, physical identity, MIC, and handles

Reject every reparse tag, junction, mount point, ADS, UNC/device ambiguity,
case/Unicode mismatch, non-directory component, unexpected link count, and
handle-resolved-name mismatch. Join volume serial, 128-bit file ID, link count,
type, parent, child, and resolved path.

The worker preimage must show a low-integrity primary token, mandatory
`NO_WRITE_UP`, a medium-integrity root label with no-write-up, no breakaway or
elevation capability, and zero inherited or brokered control handles.

Root and ancestor handles use the exact reviewed access/share modes. Delete
sharing is absent on retained ancestors. Stage/rename handles use the frozen
protocol-compatible modes; incompatible or substitution-permitting variants
fail the native matrix.

### 9.3 No-replace and durability

Materialization uses `FILE_RENAME_INFO_EX` / `FileRenameInfoEx`, an opened
parent directory, a simple parent-relative target, same volume, and replacement
flags unset. An absent target succeeds while preserving identity; a present
target returns an exact admitted no-replace error and remains unchanged.

The admitted profile binds exact Windows build, NTFS features, fixed-local
volume, no CSV/remote/overlay semantics, file flush, the provider's tested
directory barrier, and every fault point. Any ambiguous durability result fails
closed. API documentation is design input, never native acceptance.

## 10. Linux prototype contract

Linux is only conditionally supportable on exact independently accepted
kernel/filesystem/mount profiles.

### 10.1 Credentials, Landlock, seccomp, and descriptor closure

The preferred worker boundary uses a distinct unprivileged UID, empty effective,
permitted, and ambient capability sets, and reviewed seccomp denial for
`chmod/fchmod/fchmodat`, `chown/fchown/fchownat`,
`setxattr/fsetxattr`, and `utime/utimes/utimensat`. User/mount namespace escape,
ptrace sources, and descriptor-transfer sources are denied or absent.

Landlock ABI must be at least 3. The exact handled-rights set includes
`REFER`, `TRUNCATE`, write/read/execute, remove, and every make right. Unknown
future rights fail closed. ABI 0/1/2 never reaches lease or attempt creation.

Before the first untrusted program byte, the launcher must, in exact order,
close unreviewed descriptors, set distinct credentials, drop capabilities,
set `no_new_privs`, install seccomp, create and populate the Landlock ruleset,
restrict self, attach the nonescapable cgroup, verify the domain, and only then
exec. Pre-opened, inherited, or passed control descriptors are forbidden;
native fixtures include `O_RDONLY|O_TRUNC`, rename, link, create, and remove.

### 10.2 Cgroup, rooted resolution, ACL, and durability

The delegated cgroup v2 contract prevents migration, ancestor control, and
peer escape. Revocation orders kill, reap/wait, hierarchical `populated=0`, and
removal, with a bound receipt.

Rooted traversal uses retained descriptors plus exact `openat2`/`statx`
resolution including `RESOLVE_BENEATH`, `NO_MAGICLINKS`, `NO_SYMLINKS`, and
`NO_XDEV`. Symlink, magic link, bind mount including same-device bind, mount
point, mount-namespace drift, and descriptor/path replacement fail.

Effective access evaluates UID/GID, supplementary groups, mode, access/default
ACLs and masks, setgid/sticky, owner, object type, and every ancestor. No
foreign effective mutation right is allowed.

The initial profile candidate is exact reviewed ext4 only. Overlay, network,
FUSE, unknown filesystems, or unbound mount options fail before lease. Native
fixtures must establish `renameat2(RENAME_NOREPLACE)`, file `fsync`, directory
`fsync`, and all crash orderings. No profile is admitted by this document.

## 11. Lease, crash, and recovery totality

The root-bound lease observation includes the exact binding digest, edge
ordinal/key-derived lease path, lease physical identity, owner-process identity,
and durability observations. It has deterministic states for absent, created but
unflushed, durable self-held, other-live, other-dead, ambiguous owner,
release-unflushed, and durably released states. A second driver fails closed;
stale ownership is never automatically stolen; ambiguous ownership requires
manual recovery.

Recovery consumes a closed observed-state object containing binding parse,
attempt-prefix length, stage, arm, private alias, final, completion, debt,
root-policy, durability, and export states. It does not accept a state label.
The total pure transition table covers empty, attempt prefix/complete, stage
partial/complete, arm, two-link alias, final-only, complete, debt
prefix/complete, corruption, flush failure, and export partial/complete.

Policy drift dominates every otherwise complete state and fails closed.
Durability failure or ambiguity also dominates. Any tuple outside the closed
table is nonenabling and requires explicit repair; it is never guessed from
content equality. Fault injection in the later native prototype must kill at
every create/write/flush/rename/unlink boundary and re-enter through the same
public recovery entrypoint.

## 12. macOS earliest-entrypoint nonmutation

macOS remains unsupported. The first public dispatcher checks the host before
selector mapping, registry/anchor lookup, opening anything for write, directory
creation, lease acquisition, attempt probing, or export inspection. It returns
`UNSUPPORTED_BEFORE_ANY_NAMESPACE_TOUCH` with zero mutations and identical
before/after namespace digests. There is no generic POSIX fallback.

Future support requires a separate exact sandbox/credential, ACL/ancestry,
`RENAME_EXCL`, and durability contract plus native acceptance.

## 13. Fresh Edge 1/2 regeneration ceremony

Old repository objects, v1 control records, copied records, migration, content
equality, other roots, and other provider versions cannot enable anything.
After native provider acceptance and separately authorized provisioning:

1. Edge 1 has distinct producer and independent reviewer roles, no predecessor,
   a fresh v2 attempt/arm/completion history, and the exact accepted root tuple.
2. Edge 2 has distinct producer and independent reviewer roles, a fresh v2
   history under the same root, and consumes exactly Edge 1's new control
   published reference.
3. Edge 3 consumes exactly Edge 2's new same-root reference and rejects every
   repository, copied, migrated, equality-only, old-root, or old-provider ref.

Frozen repository bytes may be semantic source inputs only. Transport/history
inputs are empty. Byte-identical semantic output is permitted only when all
transport and publication history is demonstrably fresh. The current Edge 3/4
code-only PASS remains nonauthority until this ceremony is independently
executed.

## 14. Required successor reviews and implementation boundary

The exact final v2 bytes require two independent pre-implementation reviews:

- semantic/schema/calculus review, including real Draft-2020-12 execution and
  adversarial mutations of every ID, digest, path role, join, DAG edge,
  denominator, trusted tuple, numeric domain, export state, and fixture receipt;
- platform/design-operational review, including the governance split,
  bootstrap/anchor/reopen transaction, Windows and Linux observation contracts,
  worker topology, lease/recovery/export totality, macOS early rejection, and
  Edge 1/2 ceremony.

Only if both pass may a separate artifact authorize an all-authority-false
native prototype in disposable reviewer-owned fixtures. That prototype must
produce exact-source/binary/toolchain/profile receipts and then receive fresh
independent Windows and Linux native reviews. Production integration,
provisioning, and governed edge execution remain later decisions.

## 15. Terminal state

```text
PURE_V2_SUCCESSOR_CANDIDATE_READY_FOR_INDEPENDENT_SEMANTIC_AND_DESIGN_OPERATIONAL_REVIEW
```

No protected root was selected, created, opened for write, mutated, or
provisioned while authoring this contract. No ACL, mode, cgroup, Landlock,
seccomp, token, job, handle, rename, flush, process, export, publication, or
governed edge operation was performed.
