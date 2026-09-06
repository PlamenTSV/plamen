# Program Facts G3-00 parity launcher R3.10 dependency-closed semantic amendment

Status: `NEW_ONLY_FROZEN_PENDING_TWO_FRESH_INDEPENDENT_REVIEWS`

Disposition: `FIXTURE_AND_HOST_CONTRACT_MATERIALIZATION_PASS_IS_NOT_NATIVE_OR_ADMISSION_AUTHORITY`

Admission: `BLOCKED_PENDING_TWO_FRESH_REVIEWS_HOST_NATIVE_EVIDENCE_AND_CROSSCHECK_V3_LINEAGE_BRIDGE`

R3.10 is a new-only successor to frozen R3.9. It modifies no R3.9 or earlier
subject, review, fixture, or implementation asset. This amendment is the
normative contract for the R3.10 family in
`Temp/program_facts_g3_launcher_r3_10_20260809/`. It performed pure Python/JSON
fixture construction and validation only. It performed no native API call,
launcher or provider operation, provisioning, installation, publication,
commit, push, cutover, or admission transition.

## 1. Frozen repair inputs

Both independent R3.9 `REPAIR` reviews were read in full and are normative
repair inputs, never PASS lineage.

| Input | Bytes | SHA-256 | Verdict |
|---|---:|---|---|
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_9_STATE_OPERATIONAL_REVIEW_9046b24b9d42a130.md` | 24,033 | `49525cd03978377476a47019c4053e5a0f2d2dbb3fc6039b1edd2fc71bff3973` | `REPAIR` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_9_NATIVE_CONTRACT_REVIEW_9046b24b9d42a130.md` | 23,120 | `7f6ca6a9cd5ce59ab9b7e7d0df780bf3a5642a94490772b2b31a3b44cb041806` | `REPAIR` |

The frozen R3.9 executable inputs retain their reviewed identities:

- model: `aab610a871715532c7768cd9ee44d87cfb88172137b7c23d9945ad5e453b09b3`;
- validator: `692d955c9097de096ef6874f0bc129e294a4d9cc5e997aaca353a3fe753afb6e`;
- R3.8 canonical baseline: `830,508` bytes /
  `e953c148ecc43aefc402c9196336a1c5e7fc9abca6105b233693ed1e52968467`.

## 2. Executable acceptance boundary

`r3_10_validator.py` has one bytes argument and no case ID or expected
diagnostic argument. It implements canonical JSON and SHA-256 locally. Before
using candidate semantics, it hashes and checks the exact sibling model,
contract, R3.8 predecessor roster, and R3.8 lineage asset against constants
compiled into the validator. Its executable pins are:

| Dependency | Required SHA-256 |
|---|---|
| `r3_10_model.py` | `a7bc8e35bd577a869c5f140b7f4390e162263f546e4b75cf330a0b89b7e7dc6c` |
| `r3_10_contract.v1.json` | `6912628277883133320b19142f77abce45b4a9d49b6295911828facd47450b9b` |
| `r3_8_predecessor_results.v1.json` | `a7ed6304dc1863719f62021152acf3e76e5961bebbc29f3385f05c46dc06f0cf` |
| `r3_8_legacy_lineage.v1.json` | `b1aed55351a64a050275c259346623fac9a759a81aeac561b789b0b8877ea35d` |

The validator source itself is externally frozen below. A fresh-interpreter
test changes only the sibling model bytes and proves deterministic rejection
as `DEPENDENCY_CLOSURE / MODEL_SOURCE_MISMATCH`. The corresponding frozen R3.9
fresh-interpreter hash-implementation splice still accepts, preserving the
fixture-first RED distinction.

Every typed object is recursively domain-hashed. Semantic negative candidates
are resealed through all permitted dependent object, operation, root, symbol,
roster, capture-receipt, and subject hashes before validation. A stale hash is
not accepted as proof of a semantic gate.

## 3. Closed fixture/host evidence union

The exact contract admits two versioned branches without changing the schema:

| Branch | Source version | Path namespace | Evidence disposition |
|---|---|---|---|
| `FIXTURE_TEST_V1` | `R3_10_FIXTURE_V1` | `fixture://r3.10/<capture>/...` | non-authoritative fixture |
| `HOST_EVIDENCE_V1` | `R3_10_HOST_CAPTURE_V1` | `host://capture/<capture>/...` | constructible platform-evidence candidate pending fresh host review |

Every source binds an exact profile, role, capture ID, capture epoch, path,
version, offset, byte length, canonical content bytes, content SHA-256, and
typed object SHA-256. One capture receipt binds the complete source roster,
the three process-invocation identities, capture methods, capture epoch,
producer-contract identity, and review disposition. Its admission authority is
literal false.

The validator parses the canonical source bytes rather than trusting parallel
claims. It enforces the exact profile-specific role roster for:

- API declarations, build manifests, runtime observations, freshness
  universes, and content-bearing executable/module artifacts;
- Linux platform profile, mount observation, and durability events;
- Windows policy, SDK declaration, and observed build tuple.

Same-roster wrong-role/profile substitutions and contradictory but correctly
hashed content therefore reject after full resealing.

## 4. Build, runtime, and module identity

Each build manifest contains the executable bytes and module membership. Each
module has content bytes, content SHA-256, exact size, path, native file ID,
role, and source identity. The runtime observation adds load ranges and binds
the same rows to a capture method, process ID/start tuple, platform handle
where applicable, lifetime token, capture ID, and epoch. The validator derives
manifest membership and loaded-module identity from those content-bearing
objects.

Zero/unrelated manifests, nonexistent forged modules, wrong content size/hash,
role substitutions, invalid load ranges, stale process lifetime pairs, and
capture-epoch splices reject deterministically.

## 5. Native API, frame, ordinal, effect, and root semantics

The exact API registry has four operation classes:

| Profile | API | Completion | API ordinal | Matrix ordinal | Seam ordinal |
|---|---|---|---:|---:|---:|
| Linux x86-64 | `renameat2` syscall 316 | returned | 18 | 316 | null |
| Linux AArch64 | `renameat2` syscall 276 | process-crash no-return | 18 | 276 | 10 |
| Windows x64 | `SetFileInformationByHandle.FileRenameInfoEx` class 22 | returned | 0 | 22 | null |
| Windows x64 | `SetFileInformationByHandle.FileRenameInfoEx` class 22 | process-crash no-return | 0 | 22 | 7 |

Request and returned-result frames are even-length hexadecimal encodings of
canonical typed JSON. The validator decodes them, checks the registered API,
derives all three ordinals from the frozen registry, validates status/error
and replay semantics, and binds expected effect to observed poststate.

Windows requests restore the typed predecessor semantics: null root directory,
absolute protected-root destination path, exact UTF-16LE bytes, filename byte
length excluding a terminator, zero padding, information class 22, and the
registered flag value. Windows execution is ordinary-user protected-root
`PROCESS_CRASH_ONLY`; it is never power-loss authoritative.

The exact five-root transition relation is:

| Root | Completion relation | Terminal state |
|---|---|---|
| `CONFIRMED` | returned operations only | `RETURNED_CONFIRMED` |
| `NO_SPAWN` | no operation | `NO_SPAWN_CONFIRMED` |
| `SPAWN_UNCERTAIN` | one crash/no-return clone operation | `PROCESS_CRASH_CLONE_STATE_UNCERTAIN` |
| `QUARANTINE_PROCESS_BASIS` | one crash/no-return operation | `PROCESS_CRASH_QUARANTINED` |
| `SPAWN_UNCERTAINTY_OBSERVATION` | the same clone operation | `PROCESS_CRASH_CLONE_RECONCILED_NO_REPLAY` |

The two uncertainty roots must carry the same operation SHA-256 and non-empty
clone-attempt identity. Arbitrary terminal strings, expected-effect
contradictions, and divergent clone histories reject after resealing.

## 6. Platform authority boundary

macOS is exactly `UNAVAILABLE` and has no admitted platform instance.

Fixture Linux is `UNAVAILABLE` for power-loss authority. The host branch may
set Linux `power_loss_authoritative=true` only when all of the following parse
and join exactly:

1. source and destination retained parent handles carry the observed mount ID;
2. both parent handles carry the observed exact `st_dev`;
3. the handles are on the same mount;
4. the registered call is `renameat2` with flags zero and the architecture's
   exact syscall number;
5. the renamed file is fsynced;
6. the source parent is fsynced against its exact file identity;
7. the destination parent is separately fsynced against its exact file
   identity;
8. the parsed filesystem/profile/cache evidence is the exact profile source.

Windows is always `PROCESS_CRASH_ONLY`, requires an ordinary-user principal
and protected root, and must keep `power_loss_authoritative=false` in both
branches. Global native execution, production execution, spawn, publication,
installation, cutover, and admission authority remain literal false. Thus the
host witness demonstrates schema constructibility; it is not host-native
execution evidence and cannot perform an admission transition.

## 7. Fresh projections and predecessor conservation

The six fresh-symbol bindings are derived from decoded returned-result
projection slots. Each slot binds its ordinal, symbol kind, schema, parsed
value, result operation, and the exact profile freshness-universe source.
Synthetic label hashes are not an acceptance input.

`r3_8_predecessor_results.v1.json` is the exact 2,227-row roster emitted by the
frozen R3.8 executable baseline generator; an independent replay compared all
rows byte for byte. R3.10 carries, for every predecessor row:

- the R3.8 ordinal, kind, result, and exact R3.8 result SHA-256;
- one successor ordinal, kind, result, predecessor join, semantic payload, and
  successor SHA-256;
- one mapping row whose only admitted transformation is
  `SEMANTIC_IDENTITY_R3_8_TO_R3_10`.

The validator independently regenerates the R3.8 roster and enforces exact
2,227-row totality, order, injectivity, semantic equality, successor hashes,
and mapping hashes. Fully resealed predecessor omission, duplication, and
payload substitution fixtures reject at distinct exact diagnostics.

The 67-row lineage asset is extracted from the frozen R3.8 mutation roster.
Every row binds the predecessor atom, mutation ID, mutated subject identity,
property, patch, precondition pointer/hash, restored successor semantic
surface, full-reseal policy, and exact predecessor primary/subcode. No row is
represented by an R3.9 label alone.

## 8. Fixture-first mutation evidence

The frozen RED evidence reconstructs nine representative accepted-invalid
R3.9 classes before R3.10 validation:

1. contradictory registered source content;
2. wrong profile-specific source role;
3. zero build-manifest identity;
4. forged loaded-module identity;
5. unregistered API and non-hex frame;
6. arbitrary API/matrix ordinals;
7. arbitrary seam ordinal;
8. contradictory terminal state;
9. divergent uncertainty-root clone operation.

All nine candidates are fully reconstructed upstream of R3.9 downstream
hashes and receive `ACCEPTED / R3_9_MATERIALIZATION_VALID`. The evidence also
replays R3.9's final-LF baseline rejection and escaping `RecursionError`.

The frozen GREEN evidence contains 26 distinct R3.10 canonical candidates.
Every candidate is fully resealed, none stops at `HASH_CLOSURE`, all reject,
and all 26 observed primary/subcode pairs exactly equal their independently
fixed expectations. Coverage includes source content and role binding,
manifest/module identity, API and hex frames, three ordinal classes, Windows
request semantics, expected effects, terminal/clone semantics, fresh
projection values, all three predecessor attacks, exact Linux mount/st_dev,
both parent fsyncs, rename flags, forbidden Windows power-loss escalation, and
forbidden macOS admission.

## 9. Transport and bounded failure semantics

The exact frozen accepted baseline includes one terminal LF and is accepted as
stored. The canonical no-LF payload is also accepted. A second LF, CR, NUL,
noncanonical JSON, malformed JSON, oversized subject, excessive collection
work, or depth above 64 rejects deterministically. The 1,100-level input that
raises uncaught `RecursionError` in R3.9 returns
`INPUT_LIMIT / JSON_DEPTH_EXCEEDED` in R3.10. Dependency file-read and resource
failures degrade to deterministic non-authoritative rejection.

## 10. Frozen R3.10 asset identities

All rows below have final LF and no CR. The identity manifest lists the other
13 assets and intentionally does not self-pin; this amendment externally pins
the manifest.

| Asset | Bytes | LF | CR | SHA-256 |
|---|---:|---:|---:|---|
| `Temp/program_facts_g3_launcher_r3_10_20260809/materialize_r3_10.py` | 8,786 | 174 | 0 | `188797a9f2c499a55270910fe977f0579f8249eada185d0661d5444835f46441` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_accepted_baseline.v1.json` | 2,175,076 | 1 | 0 | `38ea9a971906e2ebe96f8eba3bad6d20801c956b3a7eb17226e76c570f11676d` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_contract.v1.json` | 4,375 | 152 | 0 | `6912628277883133320b19142f77abce45b4a9d49b6295911828facd47450b9b` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/R3_10_FIXTURE_FIRST_RECEIPT.md` | 1,871 | 16 | 0 | `d584d5c04ef7fc98b3132a3d6972a14b7a962bd7907d31ce59a8bc70a0370534` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_host_linux_witness.v1.json` | 2,175,559 | 1 | 0 | `108b1d43047f63ddaed9ec145b4e4b5826f3d2ee026a76a270e6090be354dc3f` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_identity_manifest.v1.json` | 3,384 | 1 | 0 | `6cffa880db08a37b0087105d796c5907281c7114a4a46b8e3fefa7ce7b31ebcd` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_model.py` | 32,227 | 729 | 0 | `a7bc8e35bd577a869c5f140b7f4390e162263f546e4b75cf330a0b89b7e7dc6c` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_mutation_results.v1.json` | 9,987 | 1 | 0 | `eb76b9ffdd6ec9c749ffd8fcbce394e7ee05d7b6ecd579ab931be8ba2379d845` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_mutations.py` | 20,314 | 423 | 0 | `2bba87bebdfc46523ae553b8b83286bc06e1e37e8dab70d61c76d8d0132eb04d` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_red_against_r3_9.v1.json` | 2,780 | 1 | 0 | `8ea0973225bc5d5fc0623210562c8a39010b4c886704a3e4796ab357c272b98d` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_validator.py` | 43,741 | 723 | 0 | `e6285a56efb92714bad21d0c87e2836fc8f856e5c53ccf2093cc975405e0a32a` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_8_legacy_lineage.v1.json` | 69,482 | 1 | 0 | `b1aed55351a64a050275c259346623fac9a759a81aeac561b789b0b8877ea35d` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/r3_8_predecessor_results.v1.json` | 343,290 | 1 | 0 | `a7ed6304dc1863719f62021152acf3e76e5961bebbc29f3385f05c46dc06f0cf` |
| `Temp/program_facts_g3_launcher_r3_10_20260809/test_r3_10_contract.py` | 6,441 | 135 | 0 | `11df546d2b7fb9b3b6237c4d6410ff68e5d767b285bf9fe370e5c1effd441099` |

The final focused suite result is `7 passed`. It includes fresh-interpreter
R3.9 acceptance and R3.10 fail-closed dependency-splice cases. No cache or
execution byproduct is part of the frozen family.

## 11. Required fresh independent review boundary

Stop here for two fresh independent reviews of the exact R3.10 amendment and
asset set:

1. state/schema/operational review, including exact-byte replay, full-reseal
   mutation independence, 2,227-row predecessor conservation, 67-row lineage,
   final-LF handling, and bounded parser/resource behavior;
2. native/platform/authority review, including host-branch constructibility,
   source parsers and roles, module/build provenance, request/result ABI
   semantics, Linux mount/st_dev/rename/fsync authority, Windows protected-root
   process-crash ceiling, macOS unavailability, root transitions, clone
   identity, and dependency-splice behavior.

The host witness is synthetic contract evidence, not an observation of this
machine. Fresh host-native execution evidence and the crosscheck-v3 15-edge
admission bridge remain explicitly deferred. No launcher, provider,
production-execution, publication, installation, cutover, or admission
authority is granted by this amendment.
