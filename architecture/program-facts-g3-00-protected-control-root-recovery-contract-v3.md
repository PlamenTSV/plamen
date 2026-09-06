# Program Facts G3-00 protected-control-root recovery contract v3

Status: **NEW-ONLY PURE DESIGN REPAIR; INDEPENDENT SEMANTIC AND PLATFORM REVIEW REQUIRED**

This successor preserves every v1/v2 byte. It repairs the exact frozen v2
subjects reviewed at semantic-review SHA-256
`670dd1f27caaec28cc518e6235b105a8cd88b879bed5214671984b4c2d8a2ac9`
and platform/operational-review SHA-256
`b61d273b7a9327b3a58bfe4356882ab8b5ea3b7305d47dcc588f321e476eb1f4`.
It is an executable pure/offline calculus, not native evidence. It grants no
installation, prototype, fixture-execution, provisioning, publication,
governed-edge, migration, cutover, commit, or push authority.

## 1. Fixture-first repair boundary

`Temp/g3_control_root_contract_v3/test_v2_accepted_invalid_red_v3.py` is the
frozen RED family. Each method presents one of the v2 reviews' accepted-invalid
preimages to the v2 public validator and expects rejection; against v2, every
method therefore fails. `RED_RECEIPT.v3.json` records that executed denominator.
The same classes are independently mutated against v3 in
`test_control_root_mutation_sweep_v3.py`, where every invalid preimage must be
rejected. The principal suite binds the repaired affirmative contracts.

The evidence class is `PURE_DESIGN_MODEL_ONLY_NATIVE_PENDING`. Counts are
design-model predicate counts and must never be described as Windows or Linux
native coverage.

## 2. Non-self-authenticating root transaction

The installed-provider profile, installed-registry receipt, design-review
receipts, platform-native-acceptance receipt, root anchor, child binding, and
activation marker are different typed records. Each receipt carries its full
subject, source, binary, toolchain, profile, issuer, role, and disposition
preimage. Validators recompute every receipt identity, require exact pinned
issuer roles, require independent issuers, and join the accepted receipt bytes
to the record that consumes them. A digest-shaped string is never sufficient.

The protected namespace is a graph, not a linear path. It has distinct physical
identities for the protected base, registry parent, anchors parent, roots
parent, anchor file, child directory, binding file, and activation file. The
exact parent/name edges are validated from retained-handle observations.

The create-only transaction is physically constructible:

```text
INSTALLED_REGISTRY_DURABLE
 -> BRANCH_PARENTS_RETAINED
 -> CHILD_CREATED_IDENTITY_CAPTURED
 -> CHILD_AND_ROOTS_PARENT_DURABLE
 -> ANCHOR_CREATED_WITH_OBSERVED_CHILD_IDENTITY
 -> ANCHOR_FILE_DURABLE
 -> ANCHORS_PARENT_DURABLE
 -> BINDING_CREATED_WITH_ANCHOR_FILE_IDENTITY
 -> BINDING_FILE_DURABLE
 -> CHILD_PARENT_DURABLE
 -> ACTIVATION_CREATED_WITH_BINDING_FILE_IDENTITY
 -> ACTIVATION_AND_REGISTRY_PARENT_DURABLE
 -> COMPLETE
```

The child identity exists before the immutable anchor bytes are constructed.
The anchor epoch equals the binding epoch. Reopen starts from independently
accepted installed-registry and activation bytes, derives the anchor/binding/
native identities from canonical bytes and physical observations, and never
remints, scans, adopts equality, or rewrites create-only history.

The lifecycle is installation-global and same-host-only. Provider upgrade,
retirement, uninstall, or cross-host migration requires a separately reviewed
successor transaction. No ordinary version update silently rotates or strands
the root.

## 3. Immutable validation context and publication calculus

The public publication validator accepts a complete root bundle and canonical
attempt, arm, completion, stage, final-artifact, and published-reference bytes.
It first validates the installed profile, receipts, namespace graph, native
observation, anchor, binding, and activation marker. Only then does it construct
a frozen `RootContext`; callers cannot populate its root, anchor, native,
attempt, arm, or activation identities.

Attempt and arm file identities are derived inside the same call from their
canonical bytes. One candidate digest joins attempt, staged bytes, arm,
completion, final bytes, and published reference. One stage physical identity
joins arm to final/completion. Publication-arm and completion identities are
derived from actual canonical records. The reference artifact identity is
derived from actual final bytes. Caller-supplied identity shortcuts are not
inputs.

Each predecessor is supplied as complete publication evidence. The validator
recursively validates its root-bound attempt/arm/completion/final chain and then
derives the predecessor registry snapshot digest consumed by the new attempt.
A candidate cannot copy its own synthetic reference into an `accepted` map.
Cycles, duplicate predecessor entries, wrong DAG order, foreign roots, and
unvalidated record digests fail closed.

## 4. Strict representation and frozen topology

Every public record is recursively closed. JSON integers are literal integers
in the I-JSON safe range; a Boolean is never accepted at an integer locus. Every
Boolean field is checked with identity (`is True`/`is False`), so integer `0`
never substitutes for authority `false`. The mutation suite performs both
Boolean-to-integer and integer-to-Boolean substitutions across root, receipt,
native, topology, broker, lease, recovery, export, and publication families.

The complete 64-member v2 static path vector is copied as an exact frozen typed
vector. Self-check compares every role/path pair, order included. Cardinality
alone is not evidence. The 15-edge/23-arc DAG is likewise exact.

## 5. Independently bound reviews, fixtures, and Edge 1/2

Governance stages consume complete registered receipts, not counts of hashes.
Design and native receipts must have the exact subject/source/binary/toolchain/
profile tuple, accepted disposition, distinct receipt identity, distinct issuer
identity, and the expected role. Fixture receipts bind the exact case ID,
mutation ID, entrypoint, expected diagnostic, poststate digest, test-subject
set, executed-result digest, and prerequisite profile. Duplicate or unrelated
receipts fail.

Fresh Edge 1/2 regeneration crosses a narrow trusted publication broker:

```text
untrusted producer staged grant ----\
                                      broker -> create-only control records
independent reviewer staged grant ---/
```

Producer and reviewer grants are typed, physically disjoint from the control
root and protected ancestors, and bound to different process/role identities.
The pinned broker independently digests their exact staged bytes, revalidates
the root, validates the receipt registries, and alone holds control-write
authority. Edge 2 contains the complete broker-validated Edge-1 publication;
Edge 3 names the exact broker-validated Edge-2 publication. Prose role labels,
freshness labels, and arbitrary acceptance digests grant nothing.

## 6. Derived Windows evidence

The Windows pure record is a recursively closed native-observation *shape* for
an exact NTFS/build profile. It includes the complete DACL and SACL mandatory
label ACE, trusted/enabled/deny-only/restricted/token SID sets, integrity SID
and mandatory policy, privileges, elevation/token/AppContainer/capability/
session/UIAccess/default-DACL state, ancestor descriptor preimages, retained
handle access/share/options and identities, rename request/result/poststate,
durability barriers, and a complete job object receipt.

The validator derives effective mutation rights from ACE and token preimages,
derives MIC write denial from integrity ranks and mandatory mask, requires link
count one, derives no-breakaway and kill-on-close from job limit/membership/
notification preimages, and accepts only `ERROR_ALREADY_EXISTS` as the reviewed
present-target collision. `ACCESS_DENIED`, missing SACL/MIC/job evidence,
unexpected links, ReFS, unknown builds, and contradictory resealed preimages
fail. These checks are model evidence only until separately authorized native
fixtures bind actual API observations.

## 7. Derived Linux evidence and executable handoff shape

The Linux pure record pins one exact Landlock ABI/kernel/ext4/mount profile and
the complete handled-right set. Every path-beneath rule binds a retained parent
FD identity, purpose, and minimal allowed-right set for immutable source,
toolchain/runtime libraries/CA bundle, staged outputs, cache, and brokered
backend access. Credentials include real/effective/saved/fs UID/GID,
supplementary groups, all capability sets, securebits, and executable file
capabilities. Seccomp binds source, binary, architecture, default action, and
the complete denied metadata/namespace/ptrace/descriptor-transfer surface.

The trusted parent creates and attaches the worker with
`clone3(CLONE_INTO_CGROUP)` before credential drop. It then clears groups,
sets IDs, drops all capability sets, sets `no_new_privs`, installs seccomp and
Landlock, closes every non-grant FD, and only then execs. The worker cannot
write `cgroup.procs`. UNIX-domain `SCM_RIGHTS` and other descriptor-transfer
sources are denied; backend credentials remain in a trusted mediation channel.
The cgroup decision is derived from the exact kill/reap/population/removal
receipt. Unknown ABI/rights, stale rule sets, missing runtime grants, failed or
nonempty cgroups, and contradictory projections fail.

## 8. Worker topology

Topology is derived from typed physical identities and parent edges. Every
grant is joined to the exact Windows token/job or Linux domain/native receipt
consumed by publication. Equality is tested before any relation label:
`grant_identity == control_root_identity` always rejects, including when a
caller writes `DISJOINT`. Ancestor/descendant/equal/disjoint relations are
computed, and alias, reparse, bind-mount, inherited-handle, passed-FD, and
brokerable-descriptor observations are closed.

## 9. Parameterized lease, recovery, and export

Lease, recovery, and export constructors require a validated root bundle,
arbitrary edge `1..15`, and arbitrary safe attempt ordinal. Lease identity binds
canonical lease bytes to a boot ID, process birth identity, PID, nonce,
executable digest, root activation, edge, and attempt; liveness evidence must
match that full owner identity and is resistant to PID reuse.

Recovery consumes observed canonical record bytes, file identities, native
physical observations, and durability results. `COMPLETE` is returned only
after the same full publication validator succeeds; a matching tuple of labels
cannot acknowledge completion. Ambiguous durability has an explicit
human-review disposition. All other unrecognized states fail closed.

Export has separate Windows handle-relative/no-reparse and Linux retained-FD
`openat2` algorithms. The first component is joined to the retained repository
root, every component is a unique typed object whose parent identity equals the
previous component, and the final component is the exact frozen destination.
Before/after control snapshots are independently derived from the validated
source chain; exports remain nonauthoritative.

## 10. Earliest platform gate and residual boundary

The real future launcher must dispatch the host before selector construction,
registry access, namespace inspection, worker creation, or export. macOS and
unknown hosts return unsupported with identical before/after namespace digest
and zero operations. This pure dispatcher is not that native launcher proof.

V3 intentionally performs no filesystem, ACL, process, job, Landlock, seccomp,
cgroup, rename, flush, provider, publication, or governed-edge operation.
Independent semantic and platform/design reviews of the exact frozen v3 bytes
are required. Only dual PASS reviews may authorize a separate all-authority-
false disposable native prototype, whose exact source/binary/toolchain/profile
and destructive reviewer-owned fixture receipts must then be reviewed again.

Terminal state:

```text
FROZEN_PURE_V3_REPAIR_FOR_INDEPENDENT_REVIEW_ONLY
```
