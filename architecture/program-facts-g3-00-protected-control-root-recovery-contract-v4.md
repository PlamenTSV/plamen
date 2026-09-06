# Program Facts G3-00 protected-control-root recovery contract v4

Status: **NEW-ONLY, NONINSTALLED PURE-DESIGN SUCCESSOR; TWO FRESH INDEPENDENT REVIEWS REQUIRED**

V4 is a new successor to the frozen v3 generation. It does not edit, replace,
or reinterpret any v1-v3 artifact. It consumes the final v3 semantic review at
SHA-256 `3c342a97df111c650c04fc5e397566d76bbc52848fc23fe6e327ed9d47f1a33f`
and the final v3 platform/operational review at SHA-256
`fb9f22d345afa1d6a9011d00c3b612d881b13cee1870b1c252619e01b2fdf194`.

The claim is intentionally narrower than v3: v4 is a pure, offline,
**noninstalled design calculus**. It cannot construct an active `RootContext`,
does not install or provision a root, and does not authorize a disposable
native prototype. Its affirmative fixtures demonstrate validation semantics,
not Windows, Linux, filesystem, ACL, token, job, Landlock, seccomp, cgroup,
lease, publication, durability, recovery, or export execution.

The authority ceiling remains false for contract approval, native prototype,
fixture execution, operational approval, provider, control-root provisioning,
native publication, edge regeneration, governed-edge execution, migration,
cutover, install, commit, and push. Only two fresh independent reviews of the
exact frozen v4 bytes may decide whether a later, separate all-authority-false
native prototype is worth authoring.

## 1. Fixture-first boundary

`Temp/g3_control_root_contract_v4/test_v3_accepted_invalid_red_v4.py` was
written and executed before the v4 implementation. It targets only the frozen
v3 model. Its 20 named tests encode every independently reported accepted-
invalid class, including the overlapping platform counterexamples, as fully
resealed v3 inputs where a seal exists. The observed boundary was exactly 20
failures, zero errors, and zero passes. `RED_RECEIPT.v4.json` pins the two
reviews, v3 subject, RED fixture, command, and result.

`obligation_matrix_v4.py` is a closed 20-row mapping from each RED entrypoint
to a v4 public-validator test. Missing, duplicate, reordered, or additional
obligation rows are not coverage. The author evidence separates:

- 20 historical accepted-invalid RED executions;
- ordinary v4 public-validator tests;
- full end-to-end Boolean-to-integer and integer-to-Boolean mutations; and
- structural missing/duplicate/additional/reorder mutations.

No leaf-guard count is represented as a public-validator count. No test result
is represented as native evidence.

## 2. B1: authenticated evidence is external to candidate records

V3 accepted receipts constructed from public constants and an unkeyed digest.
V4 has no receipt minting function. The only trust root embedded in the model
is an RSA-2048 public verification key. The corresponding private key was
created ephemerally outside the model and is not present in any v4 or
predecessor artifact.

`EXTERNAL_AUTHORITY_REGISTRY.v4.json` is a separately frozen registry snapshot.
Its root signature covers the exact registry epoch, complete issuer roster,
complete accepted-statement roster, purposes, roles, and all-false authority
ceiling. A receipt is only a reference into that authenticated snapshot. The
consumer recomputes the canonical statement digest, requires the exact role
and purpose, and joins the exact registry identity and epoch. Copying a receipt
to a modified statement, relabelling an issuer, adding or deleting a row, or
recomputing an unkeyed digest does not validate.

The frozen snapshot contains fixture observation statements for the two pure
platform examples, publications, leases, recovery, and export. It deliberately
contains no v4 semantic-review PASS, platform-review PASS, installation PASS,
or native-acceptance PASS. The semantic and platform issuer roles exist in the
authenticated roster, but the author has not fabricated their decisions.
Likewise, the fixture-runner role is enrolled but no claim that these author
tests were independently executed is admitted by the model. Fresh independent
review results must be separate frozen artifacts, never candidate-minted rows.

This registry demonstrates the non-self-minting verification boundary. It is
not an organizational PKI, key-rotation protocol, or production registry.

## 3. B2: stable physical keys precede mutable observation metadata

Physical identities have two distinct layers:

- Windows stable key: `(platform, volume_serial, file_id)`;
- Linux stable key: `(platform, st_dev, st_ino, mount_id, inode_generation)`;
- observation metadata: object type, link count where meaningful, and the
  handle/FD observation digest.

Equality, alias detection, uniqueness, topology, protected-object exclusion,
publication, recovery, and export compare the stable key first. Changing
`DIRECTORY` to `FILE`, link count, or observation labels cannot create a new
object. Object type is then checked separately against the expected operation.

The namespace requires eight distinct stable keys. Publication objects cannot
equal any protected key and cannot reuse one physical key across records.
Worker grants cannot equal a protected key even if every supplied label says
`DISJOINT`. Export components cannot equal a protected key or any preceding
component.

## 4. B3: one global content-addressed publication registry

V4 never recursively validates with path-local copied state. It materializes a
single registry and validates it in three passes:

1. Each record is canonicalized and keyed by
   `(root_design_sha256, edge_ordinal, attempt_ordinal)`. Duplicate keys,
   duplicate statement content, and reused physical objects reject globally.
2. An exact 15-row selection vector chooses one content identity per edge.
   Missing, duplicate, foreign, or additional selections reject.
3. Every selected record's predecessor vector is derived from the selected
   registry rows and the exact 15-edge/23-arc DAG. A direct row and a nested
   branch cannot select different versions of the same logical publication.

Each publication statement joins payload bytes, candidate digest, attempt,
arm, no-replace native result code, stable stage/final identity, completion,
file barrier, parent barrier, and exact predecessors. The statement has an
authenticated publication-broker observation receipt. The complete selection
snapshot has a separate authenticated registry observation receipt.

The fixture uses attempt zero because the registry is a finite frozen
observation snapshot. The validator is parameterized by attempt and never
falls back to a sample candidate; a future native registry must authenticate
its own exact statements under a separately reviewed live issuer mechanism.

## 5. B4: one constructible canonical namespace transaction

The selector is not supplied by a caller. It is the closed grammar
`g3cr4-<64 lowercase hex>` derived from the exact noninstalled profile and
namespace version. Separator, dot-component, drive, UNC, alternate-stream, and
device-name injection cannot enter the selector grammar.

One namespace object contains the profile, selector, eight physical nodes,
anchor bytes, binding bytes, design-activation bytes, and exact transaction
events. The canonical path edges are:

```text
roots_parent  -- <selector>.root                --> child
anchors_parent -- <selector>.anchor.json        --> anchor_file
child         -- control-root-binding.v4.json   --> binding_file
registry_parent -- <selector>.activation.json   --> activation_file
```

The child observation precedes anchor creation. The anchor consumes the exact
roots-parent and child stable keys. Binding consumes the anchor digest, anchor
file stable key, child stable key, equal epoch, and native statement digest.
Design activation consumes the binding digest and binding-file stable key.
There is no parallel symbolic path.

Every event consumes the exact previous event digest, retained parent stable
key, canonical name, output stable key and type, payload digest, platform
native result code, and barrier result. Changing a name and resealing all
public digests still conflicts with the derived graph and the authenticated
namespace statement.

The final record is explicitly `installed:false`, `active:false`,
`lifecycle_state:REVIEW_PENDING`. The filename `activation` describes the
future transaction record type; it does not activate a root.

## 6. B5: decisions are reduced from preimages

Caller-supplied `success`, `safe`, and `disjoint` labels are not decision
inputs. The platform statements are authenticated exact preimages, and public
validators compute decisions.

### Windows pure reducer

The Windows fixture pins one design build and includes the ordered DACL,
requested mutation rights, enabled/deny-only/restricted token sets, integrity
levels, mandatory policy, privileges, job limits, process census, completion
messages, and a closed retained-handle roster. The reducer:

- walks ACEs in order over the token SID set and remaining requested access;
- rejects any granted or undecided mutation right;
- derives `NO_WRITE_UP` from the token and object integrity ranks;
- equates active process count to the supplied process-members denominator;
- accepts empty-job state only when both are zero and the zero-process event is
  present; and
- requires `GENERIC_WRITE` plus `SYNCHRONIZE` on every modeled flush handle.

An enabled-group allow followed by Everyone deny therefore does not disappear
through set subtraction. A nonempty process list cannot coexist with an empty
job. This is still a pure reducer, not Authz/AccessCheck or Job Object evidence.

### Linux pure reducer

The Linux fixture pins Linux 6.8 with Landlock ABI 4 rather than the impossible
v3 6.8/ABI-6 pair. The exact launch sequence sets and locks securebits before
dropping all capability sets. Source rights are read-only. Output rights are
write/make/truncate only and contain no read permission. The seccomp preimage
denies `sendmsg`, `recvmsg`, `socketpair`, and `pidfd_getfd`; the worker backend
channel is a trusted-parent pipe with no FD passing. Credentials, capabilities,
descriptor table, cgroup kill/reap/population/remove return codes, and the
handled-right set are closed and reduced from exact fields.

No directory link count is used as an alias proof. Stable keys and complete
topology provide that model relation.

## 7. B6: generic lease, recovery, and export consistency

Lease validation consumes an authenticated native observation for the exact
root, edge, and attempt. It validates every field before branching. The absent
branch requires the platform's no-entry result, no record bytes, no owner
observation, a retained parent observation, exclusive-create success, and a
parent barrier. A contradictory live owner cannot ride the absent fast path.
Present leases parse bounded canonical bytes and compare the full boot ID, PID,
process-birth ID, nonce, executable digest, root, edge, and attempt. PID/birth
mismatch fails closed.

Recovery takes the supplied already-validated global registry. It derives the
selected publication and the exact attempt, arm, final, completion, and
published-reference bytes. Every observed row joins its logical digest and
stable physical key. The authenticated observation must match that derivation;
a status string alone cannot acknowledge completion. This works over the
selected record, not one hard-coded candidate.

Export also derives its source from the supplied registry. Its authenticated
observation contains the retained repository root, every component parent and
stable identity, create-exclusive result, readback digest, and the final stable
key inside the exported-artifact identity. The final logical bytes and final
physical object are therefore one observation. Export remains explicitly
nonauthoritative.

## 8. B7: bounded failure and honest denominators

Every public aggregate validator begins with an iterative budget walk:

- input bytes: at most 1,048,576;
- nesting depth: at most 48;
- total nodes: at most 20,000; and
- total scalar UTF-8 bytes: at most 1,048,576.

Cycle detection tracks the active ancestry rather than rejecting harmless
shared object references. Strict JSON rejects duplicate keys, invalid UTF-8,
invalid JSON, oversized bytes, excessive depth, excessive nodes, and recursive
parser failure as one bounded `ValidationError`; raw `RecursionError` does not
escape.

Boolean fields use identity/type checks and integer fields require
`type(value) is int`. The mutation suite sends every literal Boolean locus
through its actual aggregate public validator after substituting integer zero,
and every literal integer locus after substituting Boolean false. Repeated
authority records remain separate executed public-validator candidates and are
reported as such. No leaf-only check is included in that total.

## 9. B8: closed, explicitly noninstalled lifecycle

V4 chooses the review-authorized narrower option instead of pretending to have
an installed lifecycle. Its entire state machine is:

```text
NEW --REGISTER_DESIGN--> REVIEW_PENDING
REVIEW_PENDING --FREEZE_FOR_REVIEW--> FROZEN_REVIEW_PENDING
REVIEW_PENDING --RETIRE_DESIGN--> RETIRED
FROZEN_REVIEW_PENDING --REPAIR_SUCCESSOR--> REVIEW_PENDING
FROZEN_REVIEW_PENDING --RETIRE_DESIGN--> RETIRED
RETIRED --REOPEN--> RETIRED
```

`INSTALL`, `UPGRADE_INSTALLED`, `ACTIVATE_ROOT`, `UNINSTALL`, `MIGRATE_HOST`,
`MIGRATE_OS`, and `ADOPT_EXISTING_ROOT` are explicit fail-closed operations.
Unknown state/operation pairs also fail closed. No profile or context can emit
`installed:true` or `active_root:true`.

An installed implementation, if later authorized, requires its own closed
install/reopen/upgrade/retire/uninstall/migration contract and fresh review.
That work cannot be inferred from v4.

## 10. Platform-review repairs and worker topology

The worker grant roster is exact and nonempty: source, toolchain/runtime/CA,
staged output, cache, and backend broker. Each grant joins the native statement
digest used by the design bundle, has a complete nonempty parent chain ending
at a retained trusted topology root, uses distinct stable keys, and is compared
against every protected key before any type or relation reasoning. Empty
rosters and absence-of-evidence `DISJOINT` claims do not exist in the schema.

Publication broker authority is not a Boolean claim. Each exact statement must
be present under the `PUBLICATION_BROKER` role and exact purpose in the signed
external registry. Edge 1/2 and every later fixture record use the same
authenticated boundary; the complete global registry carries exact prior
content identities.

Unsupported hosts dispatch before profile/selector construction. macOS and
unknown values return `PREIMPORT_HOST_DISPATCH`, zero operations, and identical
before/after namespace digests. Supported hosts still return
`native_execution_authorized:false` and zero operations in this pure model.

## 11. Evidence and nonclaims

The author is allowed to claim only:

- the historical v3 accepted-invalid suite was RED as recorded;
- the exact v4 Python validators accepted their affirmative pure fixtures and
  rejected the executed mutations;
- the external fixture registry's RSA signature verifies under the frozen
  public key and candidate mutation does not; and
- all modeled authority ceilings are literal false.

The author may not claim external review acceptance, independently executed
fixture receipts, cryptographic key custody, production PKI, native platform
semantics, filesystem durability, launcher compatibility, installation,
provisioning, publication, governed-edge execution, migration, cutover,
commit, or push.

The registry signing event authenticated a frozen fixture snapshot, not a
production trust decision. The private key is intentionally absent, so the
snapshot cannot be extended. Key storage, rotation, revocation, threshold
governance, and rollback protection belong to a future independently reviewed
registry implementation.

## 12. Required independent successor reviews

Two fresh reviewers must independently rehash the freeze manifest and inspect:

1. semantic/authority closure across B1-B8 and the global publication map;
2. Windows/Linux reducer correctness and the truthfulness of the noninstalled
   claim;
3. every RED-to-GREEN obligation row and its actual public-validator reach;
4. budget behavior, strict representation, Boolean/integer substitutions, and
   error normalization;
5. absence of receipt-minting/private-key material and of fabricated review or
   native acceptance; and
6. the all-false authority ceiling and zero native/governed-edge operations.

Only dual fresh PASS reviews may authorize a different artifact: a disposable,
all-authority-false native prototype. V4 itself never receives that authority.

Terminal state:

```text
FROZEN_NONINSTALLED_PURE_V4_FOR_TWO_FRESH_INDEPENDENT_REVIEWS_ONLY
```
