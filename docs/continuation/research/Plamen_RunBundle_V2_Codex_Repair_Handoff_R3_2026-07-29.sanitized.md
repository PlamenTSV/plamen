# RunBundle V2 blocker-repair handoff R3

Date: 2026-07-29  
Author role: repair implementer; **not** acceptance authority  
Disposition: **IMPLEMENTATION COMPLETE — INDEPENDENT BLOCKING RE-REVIEW REQUIRED**  
Claim scope: local implementation, deterministic replay, packaging, and fixture validation only  
B1 effectiveness claim: **NONE**

## 0. Review request and authority boundary

This handoff requests an independent adversarial re-review of the five blockers
in:

`<LOCAL_USER_ROOT>\plamen-codex-implementation\review_fixtures\runbundle_v2_independent_review_r2.md`

SHA-256:

`a10ef73e13d67f0dab726a4106b4630b0adff2e2c873993d36cff172933d524d`

The implementer does not clear, accept, merge, commit, push, or deploy this
boundary. The reviewer should independently recompute the R3 manifest, attack
the five repairs, and issue a new blocking disposition.

Both repositories remain shared dirty worktrees. Their HEADs are context only:

| Repository | HEAD |
|---|---|
| production (`<LOCAL_USER_ROOT>\plamen-codex-implementation`) | `67a0f85adc7a8169d79a286908b00bef7adb764a` |
| evaluator (`<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>`) | `345d016d0c86b6201e90cec908c37c6a66f739c3` |

The exact source authority is the complete per-file preimage in the R3 freeze,
not either dirty-tree HEAD.

## 1. Exact R3 freeze

Manifest:

`<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Local_Freeze_R3_2026-07-29.json`

| Binding | Value |
|---|---|
| Raw manifest file SHA-256 | `5d85385db35ddf6072c97103151d9493a6e58df34a9f617d1dd92d8f03eb7793` |
| Embedded canonical self-digest | `c4dfa8c0256840e8d68f27c460d4ac3a9bba55b8fab122e76598ca8423c65822` |
| Schema | `plamen.runbundle-v2-local-freeze.v2` |
| Claim scope | `LOCAL_IMPLEMENTATION_AND_FIXTURE_VALIDATION_ONLY` |
| `not_B1_effectiveness_evidence` | `true` |

Final replay command:

```powershell
python tools/runbundle_v2_freeze.py replay `
  "<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Local_Freeze_R3_2026-07-29.json" `
  --production-root "<LOCAL_USER_ROOT>\plamen-codex-implementation" `
  --evaluator-root "<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>"
```

Final result:

```json
{"freeze_manifest_sha256":"c4dfa8c0256840e8d68f27c460d4ac3a9bba55b8fab122e76598ca8423c65822","status":"REPLAYED"}
```

R2 is superseded by R3 solely because the final native Windows `SUBST`
regression fixture was added before handoff. Runtime, schema, API, wheel, and
protocol hashes are unchanged; only the evaluator-test aggregate changed.

### Source-set and API authority

| Source set | Files | Tree SHA-256 |
|---|---:|---|
| production runtime | 7 | `89f8b180f421c5079bb35b5fe21227778a8a9a57c4d4cd80da5697f0a93c53e2` |
| production tests | 6 | `31be45ad9521c54feefb80ff2da289be0d1453780450867fd4c75069f7266e67` |
| evaluator source | 28 | `b9c4d539640493b2e465cb690cc1e543402e27eb4d03e0b58c9321811057c95a` |
| evaluator schemas | 47 | `e43817a85233b0daa9de3f975a9dfe77f8dd00e377b1ddaf1a2011f8a24180bd` |
| evaluator tests | 29 | `660f9cd8852ec074d9a7bc2491d3c10a221b8f46b84e94d18c4eb443f205c63b` |
| evaluator packaging | 2 | `a3621c2063bed999b412613eb6157c7faaab9b64bf11fdc2b665c059cce1b765` |
| freeze tooling | 2 | `7983db7ff516108b3243636f15b42b2f6987c0da3a013377226da219bd3b559d` |

| Public API | Symbols | SHA-256 |
|---|---:|---|
| production runtime | 107 | `dd507961432faa427d6a20f917ea78dabb6aa08e42e246357fbb673a48e664a3` |
| evaluator source | 102 | `4de16b8418ffec9ab014bb893cdbdbf6d324f14a6f2d103913d1e81a73d8de26` |

Protocol phase-map hashes:

- smart-contract: `28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae`
- L1: `1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6`

## 2. Exact wheel and replay authority

Preserved evaluator wheel:

`<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>\dist\frozen-v2\plamen_eval_control-0.2.0-py3-none-any.whl`

| Binding | Value |
|---|---|
| Wheel SHA-256 | `b51883f100137115523794561711132a7040526d4e27df58d9fd2460fc09fb67` |
| Size | 157,867 bytes |
| Members | 80 |
| Member-roster SHA-256 | `56f059619abb62812e6296c9b492ea01d71cce13c3fd2ab65652009cbf59b101` |
| Installed/source version | `0.2.0` |

Freeze/replay implementation:

`<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>\tools\runbundle_v2_freeze.py`

SHA-256:

`37b2ffde8e6539d0d26b8803363e1279ee37618b60074ca2794362dd4dce4da7`

The manifest embeds the complete tree, API, protocol, key-file, and wheel-member
preimages. The documented algorithms use canonical, NFC, float-free JSON and
portable relative paths; physical repository roots are excluded from semantic
hashes.

The exact recorded build recipe is:

```text
{PYTHON} -m build --wheel --no-isolation --outdir {OUTDIR} {CLEAN_SOURCE}
SOURCE_DATE_EPOCH=315532800
PYTHONHASHSEED=0
PYTHONDONTWRITEBYTECODE=1
```

Recorded build environment:

- CPython `3.12.10`
- `build` `1.4.0`
- `setuptools` `82.0.0`
- `packaging` `26.1`
- separately installed `wheel` distribution: `UNAVAILABLE`

`UNAVAILABLE` is the exact observed distribution-metadata state, not a guessed
version. The backend nevertheless produced two byte-identical wheels from
separate external clean copies; both matched the preserved wheel above.

An offline clean-install exercise installed that exact wheel with
`--no-index --no-deps` into a fresh venv under empty `HOME`/`USERPROFILE`,
`PYTHONNOUSERSITE=1`, no `PYTHONPATH`, and `python -I`. It imported
`objects`, `safeio`, and `semantic_replay` from `site-packages`, resolved all
47 schemas from the installed share directory, performed content-addressed
import, and verified the structural exact-B1 fixture with seal:

`884c9d727576c95ede36eb93782933bd5dec4dbfab25664ed8b1fa09bcc6c473`

That is local structural/installability evidence only, not benchmark
effectiveness evidence.

## 3. Blocker dispositions submitted for review

### RB2-R2-B01 — unreplayable aggregate/API/wheel freeze

Repair:

- added a deterministic freeze/replay utility and versioned preimage formats;
- embedded every raw-file and public-API preimage in the manifest;
- bound phase maps, key files, tool digest, toolchain state, build recipe, and
  exact command;
- preserved the exact wheel at a manifest-bound path;
- embedded and validated all 80 wheel members;
- added path-root independence, byte-identical double-build, exact replay, and
  tampered-preimage fixtures.

Evidence:

- `tests/test_runbundle_v2_freeze_replay.py`: 3 focused tests, included in the
  172-test evaluator denominator;
- final independent invocation of `replay`: `REPLAYED`;
- exact wheel and roster hashes above.

### RB2-R2-B02 — physical import-root alias bypass

Repair:

- compares physical directory identity, not only lexical `Path` values;
- rejects source/import equality, import beneath source, and import as physical
  ancestor of source;
- rejects linked/reparse/non-directory roots and existing ancestors;
- rechecks source/import identities after destination creation, after temporary
  creation, and immediately before promotion;
- verifies the temporary directory's physical parent identity.

Fixtures:

- `\\?\` extended-path spelling of the source;
- physical ancestor of the source;
- native Windows `SUBST` alias of the source.

Final focused result: `3 passed, 10 deselected`.

The physical-identity predicate also covers case aliases, DOS short-name
aliases, junctions, and other alternate spellings that resolve to the same
directory identity. The reviewer should still attack those variants
independently.

### RB2-R2-B03 — 23 open nested schema objects

Repair:

- closed every reported nested object in:
  - `run_manifest.v2.schema.json`;
  - `harvest_receipt.v2.schema.json`;
  - `public_case_lock.v2.schema.json`;
  - `public_launch_receipt.v1.schema.json`;
- retained semantic validators as defense in depth;
- added recursive closure inspection over all 18 `V2_CONTRACT_FILES`.

`denial_counts` is deliberately an exact empty v1 object: no normative
producer/consumer field roster exists. Adding fields requires a schema-version
migration rather than accepting arbitrary extension keys.

### RB2-R2-B04 — Pashov double capture / intervening mutation

Repair:

- introduced immutable `CapturedInventory` and `CapturedArtifact` values;
- CLI captures inventory exactly once;
- preflight, parsing, events, report projection, diagnostics, and receipts
  consume that same captured object;
- diagnostics and receipts bind `inventory_roster_sha256`;
- semantic validation recomputes the binding.

Fixtures assert one call, intervening mutation resistance, and captured-object
immutability/tamper rejection.

### RB2-R2-B05 — confidential identity values in allowed blind prose

Repair:

- compiles a confidential token set from hidden candidate, producer, adapter,
  receipt, system, run, cell, case, and optional private-lock/private-context
  identities;
- scans normalized visible leaves, concatenated leaves, and the complete
  serialized packet;
- uses Unicode NFKC, case folding, formatting/space normalization, and
  fragmentation detection;
- fails closed rather than silently redacting;
- replaces a deterministic case digest with a per-render random HMAC-SHA256
  commitment whose key remains only in the private map;
- validates the HMAC binding during unblinding;
- adds optional CLI `--private-case-lock` authority.

Fixtures cover direct identity tokens, normalized equivalents, fragmentation
across list strings, and non-repeating commitments for the same case.

## 4. Repair-file hashes

All paths below are relative to
`<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>`.

| File | SHA-256 |
|---|---|
| `src/plamen_eval/objects.py` | `af97b782f0b7998531bd89af8c8dfd433b9d4783058ce9e0e6d2c333a9281daa` |
| `tests/test_real_v2_objects_profiles.py` | `9936a483bd4bdf33a8a237ae12243a85cebd8b4c61261308e5a3fc2f4a7a386a` |
| `schemas/run_manifest.v2.schema.json` | `112008d035616e494938cc7b476076bdda42a9932eda764874bf04c703451c20` |
| `schemas/harvest_receipt.v2.schema.json` | `fe7b20f36d3a0c941f016f5d79f53e5934b987a35267640449d1d87ef63b484d` |
| `schemas/public_case_lock.v2.schema.json` | `083eca0aa4ddf5909b2965c6aa9415c9c3558b473f8b607a524d06f5a8766e15` |
| `schemas/public_launch_receipt.v1.schema.json` | `10b09b37b44449eba8acbc6a75bf2ae9dacdb90c2e629d69cf630aca6510c895` |
| `tests/test_real_v2_contracts.py` | `20fe23e407e8f5cb0a8242bd90aee2feda55925d6703002ebe19a38d897a63d3` |
| `schemas/external_adapter_receipt.v1.schema.json` | `7365802bd4c8434b53d762c4d9a16027fda247e10588dde717ce07e079bf4f23` |
| `schemas/pashov_v3_parse_receipt.v1.schema.json` | `3030822e86402f298fe55c9c546691f3ba7ef09698ee8cfdd33ddc48eb87f032` |
| `src/plamen_eval/adapters/base.py` | `156bf859450820ba647e131c04ec161af6a6e54509bf539de43b1d01b07acd56` |
| `src/plamen_eval/adapters/pashov_v3.py` | `bab6dff6214be086f568723fea427abe31ae5111f51e06056a8f3a10a82ba810` |
| `src/plamen_eval/cli.py` | `5774d51b2e0062dc020e4ee74d5584e8d07180e32b080b11cf87605724cc9d4c` |
| `src/plamen_eval/contracts.py` | `4452f03539dfc5f7b256e05a1ecf47d3e9a500de6f3dad6fe13fb44092c69fb3` |
| `tests/test_pashov_v3_adapter.py` | `4a4366231034ab8b6c5525a88daa38b96e4d7465b4000f535dc55eb49bd15677` |
| `src/plamen_eval/blinding.py` | `4511eb2ef3283975e13f6a585113b2ef2815a6e05fd68600694add9db6597594` |
| `tests/test_real_v2_blinding_comparison.py` | `2b4df1838302df2ddda62806e9c23ffdfbe260771f21ce5c7b9a3c3f865ae656` |
| `tools/runbundle_v2_freeze.py` | `37b2ffde8e6539d0d26b8803363e1279ee37618b60074ca2794362dd4dce4da7` |
| `docs/runbundle-v2-freeze.md` | `2693f4c273a0582df5b48d66bf0a3d966374c4ae9571f1ac1c25bc3e0790c96a` |
| `tests/test_runbundle_v2_freeze_replay.py` | `bbe629252b4b8b7f1f9baadb4942323da443cf6b893890cadddd064350be4d79` |

The R3 manifest contains the full 121-file source preimage, including all
unchanged files that participate in the boundary; this table is only the
blocker-repair subset.

## 5. Final validation denominators

| Validation | Final result |
|---|---:|
| B02 native physical-alias focus | **3 passed** |
| Neutral evaluator full suite | **172 passed, 6 subtests passed** |
| Production RunBundle exact six-file suite | **509 passed** |
| Production Python packaging contract | **2 passed** |
| Public packaging freeze, including fresh-public-archive visibility | **5 passed** |
| Cross-OS/toolchain pre-handoff gate | **22 passed** |
| Freeze/replay focused suite | **3 passed** (included in evaluator full) |
| Exact manifest replay | **REPLAYED** |
| Offline isolated-wheel exercise | **PASS** |

The Python packaging denominator was rerun after the separate Claude-provider
package-visibility owner exposed `scripts/claude_provider_policy.py`; it is now
green. That unrelated provider change is not part of the RunBundle runtime
source set or a claimed RunBundle repair.

## 6. Mandatory independent re-review

The reviewer is asked to:

1. verify the raw manifest hash and embedded self-digest;
2. replay every source/API/protocol/key/tool/wheel binding from the R3
   manifest;
3. rerun the original attack matrix, especially physical path aliases,
   recursive schema closure, Pashov single-capture TOCTOU, and blind value
   leakage;
4. build twice from separate external clean copies and compare both wheels to
   the manifest-bound wheel;
5. repeat the clean installed-wheel exercise outside both repositories;
6. verify that no B1 effectiveness or cutover authority has been inferred from
   this local evidence; and
7. issue a new hash-stamped blocking disposition.

No merge, commit, push, deployment, provider run, benchmark campaign, or live
audit was performed or authorized by this handoff.
