# Plamen RunBundle V2 Codex Repair Handoff R10

Date: 2026-07-29
Author lane: Codex RunBundle R10 repair author
Review state: AUTHOR COMPLETE; INDEPENDENT BLOCKING REVIEW REQUIRED
Commit/push state: no commit, merge, push, provider run, benchmark, or audit performed
Claim scope: local implementation and fixture validation only

This artifact is ASCII only. It does not authorize cutover. It is not B1
effectiveness, recall, precision, comparison, publication, or audit evidence.
The author does not self-certify this repair.

## 0. Disposition and exact boundary

R10 supersedes the R9 author conclusion after an independent R9 review found
three fresh blockers:

1. a forged but internally self-consistent READY v1 receipt could be treated
   as source-observation authority while an interrupted source had drifted;
2. cleanup of the external promotion journal after READY could fail silently;
   and
3. a retry after partial RETIRED quarantine could collide with a fresh
   retirement write rather than resume idempotently.

The blocking R9 review is:

`plamen-codex-implementation/review_fixtures/runbundle_v2_independent_review_r9.md`

- bytes: `21582`
- raw SHA-256:
  `9f0b6080b51dc220913b4ee4943751a08b8738651cae35b2fa991129fe875f44`

The fixture-first R10 design is:

`plamen-codex-implementation/review_fixtures/runbundle_v2_r10_blocker_fix_design_20260729.md`

- bytes: `20735`
- raw SHA-256:
  `76c87aa0b6f464714e3c95f46cca093221db86b33819cbf86a8e1a688f017771`
- embedded-payload SHA-256:
  `f7f89382c9db6ac522a98920e1e433328209647525ccbe3074914dbc3694814ca`

Two authority implementation shapes were presented without choosing an
unauthorized trust root:

`Downloads/Plamen_RunBundle_V2_R10_Authority_Scope_Implementation_Shapes_2026-07-29.md`

- bytes: `17262`
- raw SHA-256:
  `7bf61826fedc9fbb23ac830c3458a025e78cd9a34720ebc0d0f9d1da28350d58`

The governing independent adjudication is:

`plamen-codex-implementation/review_fixtures/runbundle_v2_r10_scope_adjudication_20260729.md`

- disposition: `AMEND`
- bytes: `17510`
- raw SHA-256:
  `d0177ba0f081bc9791497bd80f3971dc0445df268167faea4955ab64a94e3035`
- validated zero-stamp content SHA-256:
  `ec45f7eb5d5508ba5c2cc45b39400b26bb6e5049f769ecb6abe928bcc57c645d`

R10 implements only the adjudicated USER_RUN/B0 local-integrity shape:

- READY v1 remains an unsigned local-integrity receipt;
- self-consistency is never described as authenticated provenance;
- the API distinguishes local integrity from authenticated export
  attestation;
- cleanup debt is durable and loud;
- retirement and quarantine recovery are idempotent; and
- no signer, key, public-lock change, or READY v2 authority is fabricated.

Repository HEADs identify the dirty shared local baselines. They do not commit
or identify the R10 source:

- production HEAD: `67a0f85adc7a8169d79a286908b00bef7adb764a`
- evaluator HEAD: `345d016d0c86b6201e90cec908c37c6a66f739c3`

## 1. Assurance model

### 1.1 Explicit assurance levels

The production verifier exposes two requested assurance levels:

- `INTEGRITY_ONLY`
- `AUTHENTICATED_EXPORT_ATTESTATION`

`verify_export(..., required_assurance="INTEGRITY_ONLY")` is the compatibility
default. A canonical and self-consistent READY v1 can satisfy this local
integrity check only.

READY v1 is reported with:

- `bundle_integrity=VERIFIED`
- `ready_schema=plamen.runbundle-publication-ready.v1`
- `ready_assurance=UNAUTHENTICATED_LOCAL`
- `source_observation_claim=SELF_ASSERTED_NOT_AUTHENTICATED`
- `cleanup_state=COMPLETE` or `DEBT`

Requesting `AUTHENTICATED_EXPORT_ATTESTATION` against READY v1 raises the
typed `RunBundleAuthorityError` and the CLI exits nonzero. No READY v1 field,
bounded observation, code digest, or self-generated receipt is upgraded into
external provenance.

### 1.2 Deliberately absent READY v2

R10 does not implement a signed READY v2 because this lane has no governed
external signer, key lifecycle, issuer authority, revocation mechanism,
secure launcher, or public verification policy. A v2-shaped marker is
rejected; it does not fall back to READY v1 semantics.

The public case lock v2 contract is unchanged. A future B1 authority design
must bind a real out-of-process authority and receive its own schema,
fixtures, adversarial review, freeze, and cutover decision.

### 1.3 Publication ceiling

Assurance reporting does not raise the publication ceiling. The existing
payload and synthetic-v1 compatibility behavior remain intact. Local
integrity is not a benchmark-effectiveness or external-attestation claim.

## 2. Local publication state machine

RETIRED denial has precedence over READY acceptance.

| Observed state | Result |
|---|---|
| valid RETIRED receipt | deny harvest; recovery may finish exact quarantine |
| valid READY v1, no promotion journal | local integrity, cleanup COMPLETE |
| valid READY v1 plus journal, no exact cleanup debt | `RECOVERY_REQUIRED` |
| valid READY v1 plus journal plus exact cleanup debt | local integrity, cleanup DEBT |
| seal without READY | deny |
| unsupported READY schema | deny |
| missing, non-canonical, or mismatched control receipt | deny |

The distinction between cleanup-only recovery and source replay is explicit:

- `verify_export` never invents cleanup authority from a leftover journal;
- an exact cleanup-debt receipt permits only the bounded cleanup operation;
- READY plus journal without that exact debt must enter `recover_export`;
- `recover_export` owns source replay and drift handling; and
- a forged READY plus journal and no debt cannot bypass a fresh source check.

## 3. Loud cleanup debt

The cleanup receipt schema is:

`plamen.runbundle-publication-cleanup-debt.v1`

The sibling receipt is:

`.<output-name>.CLEANUP_DEBT.json`

It canonically binds:

- schema and operation;
- run ID and authorized target;
- bundle seal;
- exact READY digest;
- exact promotion-journal name and digest;
- exporter code and policy identities; and
- bounded failure class.

Direct export and recovery use the same cleanup implementation. After READY
has been reloaded and accepted, a promotion-journal cleanup failure:

1. preserves the valid READY generation;
2. writes or reloads the exact debt receipt durably;
3. raises typed `RunBundleCleanupDebtError`;
4. produces a nonzero CLI outcome; and
5. requires exact cleanup-only recovery.

No successful return silently hides cleanup debt. Recovery handles both
observable crash windows:

- journal still present after the failure; and
- journal unlink completed but parent durability failed.

In the second window, the debt receipt retains the exact authorized journal
identity even though the journal itself is already absent. Later source drift
does not convert exact cleanup-only recovery into unauthorized source replay.

Debt receipts are transaction-bound. Replay or tamper across run ID, target,
READY, seal, journal, exporter identity, or failure class is rejected.

## 4. Idempotent retirement and quarantine

The retirement schema is:

`plamen.runbundle-publication-retirement.v2`

The exact retirement receipt binds:

- the mutation or failure control receipt;
- run and output identity;
- the promoted bundle seal;
- exporter code and policy identities;
- the deterministic quarantine target; and
- the retirement timestamp fixed by the first exact receipt.

If an exact retirement receipt already exists, recovery reloads it rather
than constructing a new receipt. The quarantine path is derived from the
receipt digest, so retries converge on one destination.

The valid topology is exclusive:

- target present and quarantine absent; or
- target absent and exact quarantine present.

Both-present and neither-present states fail closed. A mismatched retirement
receipt, wrong seal, wrong control receipt, wrong run, or substituted
quarantine is rejected.

Recovery can finish journal cleanup after quarantine already completed. A
second recovery attempt does not collide on a new retirement write and does
not rewrite the original failure outcome. The original typed mutation or
failure remains the terminal semantic result.

## 5. Atomic external control publication

READY, retirement, failure, debt, and mutation controls use the shared
`_write_or_load_exact_control` primitive.

The primitive:

1. writes a fresh sibling temporary file;
2. publishes the final control path using a no-replace hard-link operation;
3. fsyncs the parent boundary where supported;
4. removes the temporary name; and
5. reloads and compares the exact final bytes.

A conflicting existing final path is accepted only when its stable bytes are
exactly equal. Partial writes do not create a partial final control path.
Stable reads also reject unsafe file types and multi-link final controls.

The promotion journal loader now proves that the stable raw bytes equal the
canonical bytes of the validated row. Fresh-export preflight includes cleanup
debt among forbidden stale controls.

## 6. Fixture-first evidence

Before production repair, the four new production blocker fixtures were run
and all four failed as intended:

- forged READY v1 during interrupted source drift;
- direct READY cleanup failure;
- recovery READY cleanup failure; and
- RETIRED quarantine retry collision.

Before production repair, the independent evaluator subprocess fixture for
the forged READY counterexample also failed as intended.

After the repair:

| Gate | Exact result |
|---|---|
| original R10 production blockers | 4 passed, 58 deselected in 5.22s |
| neutral forged-READY conformance | 1 passed, 4 deselected in 1.51s |
| expanded debt/authority/retirement matrix | 9 passed, 62 deselected in 8.00s |
| final crash/CLI assurance matrix | 4 passed, 71 deselected in 4.68s |
| focused production harvest/export file | 75 passed in 37.89s |
| exact production six-file RunBundle denominator | 567 passed in 133.12s |
| neutral production conformance suite | 5 passed in 10.12s |
| evaluator full suite, final source boundary | 232 passed, 6 subtests passed in 45.08s |
| evaluator freeze replay tests | 3 passed in 6.62s |
| production packaging denominator, final rerun | 9 passed in 66.33s |
| cross-OS pre-handoff gate | 22 passed in 1.74s |
| native Windows physical filesystem focus | 4 passed, 120 deselected in 0.52s |
| native Windows no-replace and long-path focus | 2 passed, 73 deselected in 0.82s |
| in-memory compilation of frozen Python roster | 71 files, PASS |

The expanded matrix includes:

- forged self-consistent READY with journal and source drift;
- forged READY after deleting the journal, accepted only as local integrity;
- stronger authenticated assurance rejection;
- READY plus journal without debt requiring recovery;
- debt replay and tamper across run, output, and transaction;
- genuine cleanup-only recovery after later source drift;
- journal unlink followed by parent-durability failure;
- unsupported READY v2 with no v1 fallback;
- READY and RETIRED precedence;
- mismatched retirement receipt;
- both-present retirement topology;
- quarantine completed before retirement-journal cleanup failure;
- repeated recovery after partial retirement;
- exact CLI assurance, ceiling, cleanup-state, and nonzero behavior; and
- preservation of R9 late-drift, native no-replace, privacy, contract,
  phase-map, and synthetic-compatibility coverage.

The exact production six-file denominator was:

- `scripts/test_runbundle_export_ready_marker.py`
- `scripts/test_runbundle_phase_map.py`
- `scripts/test_runbundle_real_harvest_export.py`
- `scripts/test_runbundle_v2_contracts.py`
- `scripts/test_runbundle_v2_privacy.py`
- `scripts/test_runbundle_v2_r5_regressions.py`

## 7. Runtime and package identities

Final exporter identity:

- version: `2.3.0`
- exporter code SHA-256:
  `8556dcddc9e956a5c4fdb4344a90695241c6b27d7b0e99c1445f9882a27285dd`
- exporter policy SHA-256:
  `4a5acff1e435a2a07002db91de41eddb07131b9d331b9439fc69f39cc04aa4d4`

Two clean external wheel builds were byte-identical:

- filename: `plamen_eval_control-0.2.0-py3-none-any.whl`
- byte length: `162258`
- SHA-256:
  `8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f`
- wheel-member roster SHA-256:
  `0828df80c035f5a428f0c43b17c7841b652a153287ef04bc30843f778c04b256`

The preserved wheel is:

`<PRIVATE_EVALUATOR_REPO>/dist/frozen-v10/plamen_eval_control-0.2.0-py3-none-any.whl`

It was installed offline into a fresh virtual environment with:

`python -I -m pip install --no-index --no-deps`

With no `PYTHONPATH`, `PYTHONNOUSERSITE=1`, isolated Python, and temporary
HOME and USERPROFILE, the installed artifact:

- reported package and CLI version `0.2.0`;
- imported only from the fresh environment; and
- installed exactly 47 schemas under
  `sys.prefix/share/<PRIVATE_EVALUATOR_REPO>/schemas`.

## 8. R10 local freeze

Freeze artifact:

`Downloads/Plamen_RunBundle_V2_Local_Freeze_R10_2026-07-29.json`

- embedded freeze-manifest SHA-256:
  `7b5e2086b63b5d342990eecdfe8a1eef3c14ad68bf21af46d404a42ec95c6f5d`
- raw manifest-file SHA-256:
  `689d570c0456f79c28e5c4f2aef915ff8b262a4266562a32699a58785af3a8df`
- raw manifest length: `70085`
- immediate replay: `REPLAYED`

Frozen aggregate identities:

| Source set | Count | SHA-256 |
|---|---:|---|
| production runtime | 7 | `051bee9d3766a3c936b986c1852efdd6ce5de68f7e465a8ed62922ecc0e451b5` |
| production RunBundle tests | 6 | `b08eb976a908d83ec416cc3f125a3f394be7389078d6be26c1747f00152557d6` |
| evaluator source | 28 | `d8eaa59a5aeac8d34b6cc5e59ecf5271d25bb2297ad3f0003f5bb0f801bd9131` |
| evaluator tests | 29 | `87dcb74a826d87a07d7358d4a0d4ee74d0e0a154ee33c48ff14d0becff702496` |
| evaluator schemas | 47 | `2423f116380205e01c6d7114112c2b95d24081a0fb7f09aa8a113ccc6484cad8` |
| evaluator packaging | 2 | `8bf0b3d4d6e918529379b2e53114db7966d207fec08b52d4b056a3608db8986b` |
| freeze tooling | 2 | `c4077d655c582f70a2b331a10ddf288f2b59c06d9948067c85c925aec3d9e5ce` |
| production public API | 125 | `cc5febf4100ff5099f85de9daa88b7f2de8c7a288e809832774e0bec0ee15d81` |
| evaluator public API | 103 | `f9284041b26a4ff2108b729ba21e24ef6e03a1bd2755d3e180b744c71ab2f801` |

Frozen protocol phase-map identities remain:

- smart-contract map SHA-256:
  `28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae`
- L1 map SHA-256:
  `1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6`

## 9. Exact key-file hashes

| File | Bytes | SHA-256 |
|---|---:|---|
| `plamen-codex-implementation/scripts/runbundle_export.py` | 118773 | `b10be552d23010c15e21f895c859623fdc962aeb943031222717643ffdc6fd57` |
| `plamen-codex-implementation/scripts/test_runbundle_real_harvest_export.py` | 87805 | `6e84c137432ef5d7ce25383bd0c7fdd1b8b5716dce257163c1d2537436843223` |
| `<PRIVATE_EVALUATOR_REPO>/tests/test_real_v2_production_conformance.py` | 19445 | `fd09fc332686bdc89d035d78f8568348df84912c78d123160dc84075469df40a` |
| `<PRIVATE_EVALUATOR_REPO>/tools/runbundle_v2_freeze.py` | 25801 | `697bcc62afbffb38aab70401e3809752dd70af6f01bfdcb046ee2b5652772302` |
| `<PRIVATE_EVALUATOR_REPO>/docs/runbundle-v2-freeze.md` | 4368 | `c90e388bb3a7380a03438441072bc82ae2ad5b9b6387277228eca320372c7aa7` |
| `<PRIVATE_EVALUATOR_REPO>/dist/frozen-v10/plamen_eval_control-0.2.0-py3-none-any.whl` | 162258 | `8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f` |
| `Downloads/Plamen_RunBundle_V2_Local_Freeze_R10_2026-07-29.json` | 70085 | `689d570c0456f79c28e5c4f2aef915ff8b262a4266562a32699a58785af3a8df` |

## 10. Limits and non-claims

This author evidence is narrower than whole-program release readiness:

- READY v1 local integrity does not resist a malicious same-OS writer that
  can forge all sibling controls and bundle content;
- no externally authenticated READY v2 exists;
- no governed key, signer, secure launcher, issuer, revocation, or external
  authority was added;
- no B1 campaign or effectiveness benchmark was run;
- the repositories are dirty and shared with concurrent author lanes;
- the R10 freeze binds exact owned source sets, tooling, schemas, and wheel,
  not unrelated moving files in either worktree;
- whole-tree and cross-lane integration must be rerun by the root
  orchestrator after all author lanes quiesce;
- native physical filesystem execution in this lane was Windows;
- Linux and Darwin no-replace paths are covered by conditioned semantic
  tests but require native CI before a native release claim;
- exact local assurance does not prove perpetual source immutability;
- no real provider or model backend was invoked;
- no audit, benchmark comparison, recall estimate, or precision estimate was
  produced; and
- no commit, merge, push, or cutover is authorized.

## 11. Required independent blocking review

The independent reviewer should, at minimum:

1. verify every hash in Sections 0 and 7 through 9;
2. replay the R10 freeze from the exact repository roots;
3. rebuild two clean wheels and compare them byte-for-byte to frozen-v10;
4. install the preserved wheel offline into a fresh isolated environment;
5. reproduce all three R9 blocker PoCs without trusting author fixtures;
6. attempt forged self-consistent READY v1 with and without a journal, debt,
   source drift, a seal, and a retirement receipt;
7. prove READY v1 never satisfies authenticated export attestation;
8. prove unsupported or attacker-shaped READY v2 cannot fall back to v1;
9. attack required-assurance CLI and API defaults for silent elevation;
10. interrupt cleanup before unlink, after unlink, before parent durability,
    after debt publication, and after debt cleanup;
11. replay and substitute cleanup debt across run, output, READY, journal,
    seal, exporter identity, and failure class;
12. verify debt authorizes cleanup only and never skips required source replay;
13. interrupt retirement before receipt, after receipt, before quarantine,
    after quarantine, and during journal cleanup;
14. retry every retirement interruption and prove deterministic idempotence;
15. attack target/quarantine both-present, neither-present, substituted,
    linked, reparse, and mismatched-seal states;
16. attack partial and competing control publication on Windows, Linux, and
    Darwin native filesystems;
17. verify no existing sealed generation or unrelated sibling is replaced;
18. verify payload bytes, synthetic v1 compatibility, phase mapping, and
    publication ceilings remain unchanged;
19. rerun production, evaluator, packaging, cross-OS, native, isolated-install,
    and freeze gates; and
20. issue PASS, AMEND, or BLOCK without treating this handoff as
    effectiveness evidence.

## 12. Author disposition

The R10 author slice is complete and frozen for independent blocking review.
The implementation closes the three reproduced R9 blockers within the
adjudicated local-integrity scope. It deliberately does not claim an external
trust root or B1 effectiveness.

No cutover, commit, merge, push, provider run, benchmark claim, recall claim,
precision claim, or audit authorization is made by this handoff.
