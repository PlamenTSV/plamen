# Plamen RunBundle V2 Codex Repair Handoff R8

Date: 2026-07-29
Author lane: Codex RunBundle R8 repair author
Review state: AUTHOR COMPLETE; INDEPENDENT REVIEW REQUIRED
Commit/push state: no commit, merge, or push performed
Claim scope: local implementation and fixture validation only; not B1
effectiveness, recall, precision, comparison, or publication evidence

## 0. Review boundary

This handoff answers the R7 S-13 / R7-B07 blocker in:

`Downloads/Plamen_RunBundle_V2_Fresh_Independent_Blocking_Review_R7_2026-07-29.md`

The R7 counterexample proved that the exporter could capture a source,
complete harvest and materialization, then accept a sealed bundle after the
live source changed. R8 adds an exact live-source closure at the acceptance
boundary and binds interrupted recovery to that authority.

The author does not certify this repair. The independent RunBundle reviewer
must reproduce the counterexample, inspect the full source, attack recovery
and filesystem boundaries, and issue the blocking verdict.

Repository HEADs are identifiers for the dirty local baselines, not claims
that R8 is committed:

- production HEAD: `67a0f85adc7a8169d79a286908b00bef7adb764a`
- evaluator HEAD: `345d016d0c86b6201e90cec908c37c6a66f739c3`

## 1. Normative repair

### 1.1 Exact source capture and authority

`runbundle_privacy.py` now exposes immutable file and tree snapshots that bind:

- exact recursive roster and directory membership;
- portable relative path;
- raw bytes, byte length, and SHA-256;
- device, file identity, size, mtime-ns, ctime-ns, link count, and file type;
- directory physical state;
- single-link regular-file status;
- no symlink, reparse point, junction, hardlink alias, sparse alias, ADS, or
  case-fold collision.

`runbundle_sources.py` now captures the complete scratchpad tree and final
report twice. It rejects any membership, physical-state, or byte drift. A
`SourceInventory.live_source_authority_sha256` binds the complete content and
physical authority without storing an absolute project path.

The final closure re-enumerates and re-reads the live scratchpad and report
with the same hardened physical rules and requires exact equality with the
initial source generation.

### 1.2 Acceptance ordering

For a live-source export, the final sequence is:

1. inventory twice and freeze the exact source authority;
2. harvest and materialize only the captured bytes;
3. write payload and content-addressed objects into fresh staging;
4. build the bundle index;
5. re-enumerate and rehash the live sources at `PRE_SEAL`;
6. write the staging seal and verify the complete staged bundle;
7. re-enumerate and rehash the live sources at `PRE_PUBLICATION`;
8. atomically rename the staging generation to the fresh output;
9. verify the promoted bundle and require the same verification digest.

The second live check closes mutation during seal creation or staged
verification. A source change never creates an accepted output. Any staging
seal produced before a later failure is removed with the unaccepted staging
tree.

### 1.3 Typed mutation receipt

Late drift creates one canonical, digest-bound, GT-blind sibling receipt:

`.<output-name>.mutation-<receipt-digest-prefix>.json`

The closed receipt schema is
`plamen.runbundle-export-mutation.v1`. It contains only:

- `MUTATED_DURING_EXPORT`;
- the exact check stage;
- run ID and output basename;
- the initially frozen live-source authority digest;
- exporter code and policy digests; and
- the embedded receipt digest.

It contains no absolute project path, raw source byte, ground truth, private
case lock, score, expected finding, or grader value. Re-emission is
idempotent; a same-name/different-byte collision fails closed.

### 1.4 Recovery

The journal is now `plamen.real-audit-export-journal.v2` and carries
`live_source_authority_sha256`, either one lowercase SHA-256 or exact null.

Recovery rules are:

- a live-source journal cannot recover without all three explicit source
  paths: project root, scratchpad, and report;
- a materialized-only journal with null authority cannot be relabeled by
  supplying source paths;
- recovery derives the pipeline kind from the staged canonical manifest;
- it reconstructs the current inventory and requires exact equality with the
  journaled physical/content authority;
- it rechecks the live closure immediately before recovered sealing and again
  before recovered publication;
- absence or mismatch emits `MUTATED_DURING_EXPORT`, removes the unaccepted
  staging generation, and creates no accepted output;
- payload, object, public-lock, code, policy, run identity, topology, and
  fresh-output checks remain mandatory.

The CLI `recover` command accepts optional `--project-root`, `--scratchpad`,
and `--report`; live journals require the complete set.

### 1.5 Code and policy binding

The exporter version is `2.1.0`.

The exporter code digest now covers every directly security-relevant runtime
module used by export and source closure:

- `runbundle_contracts.py`
- `runbundle_export.py`
- `runbundle_harvest.py`
- `runbundle_phase_map.py`
- `runbundle_privacy.py`
- `runbundle_sources.py`

The policy preimage explicitly binds exact roster/bytes/physical identity,
`PRE_SEAL` plus `PRE_PUBLICATION`, typed mutation outcome, no accepted bundle
on mutation, and recovery replay.

Final runtime identities:

- exporter code SHA-256:
  `896240cb900e92224ebbec54091aa796d989cc6ef971a1389b622f52cfccf17e`
- exporter policy SHA-256:
  `fddf0dea1e28b4968bfce6187ed8163186d5c3ba9f0ce2c22b92157a70895de0`
- schema-set SHA-256:
  `9c7343703954942e06a6e0176e48c14df439f8f3ffa28fbc1bd9cdf4975e69e1`
- source-registry SHA-256:
  `ac994b33932572eacf3d6911115613a5547274ed34ca45a42529c16414ccfb24`

## 2. Fixture-first evidence

The first synchronized publication-boundary fixture was run before the late
receipt implementation. It failed because the old exporter published no
mutation receipt. The pre-seal fixture likewise failed on the missing
receipt. The recovery fixture initially failed because no live-source
authority property or recovery binding existed.

The final production fixture matrix includes:

- mutation after the first complete inventory capture;
- mutation after the second capture and during harvest;
- add, remove, and rename during harvest;
- report mutation during document materialization;
- mutation after index and before seal;
- mutation after staged verification and before publication;
- scratchpad add, remove, rename, same-byte file replacement, hardlink,
  symlink, and simulated reparse transition;
- report same-byte replacement and content change with restored mtime;
- matching live-source interrupted recovery;
- absent recovery authority denial;
- drifted recovery authority denial and staging removal;
- mutation-receipt canonicality, embedded digest, path privacy, and stage;
- no accepted output and no surviving staging generation; and
- byte/identity preservation of an independent prior sealed generation.

The late closure calls the same hardened production reader covered by the
native Windows ADS, NTFS identity, and junction fixtures and by the wider
privacy suite. The independent reviewer should still attempt direct
synchronized Windows ADS, junction, and sparse substitutions at the final
closure boundary.

An out-of-tree neutral evaluator conformance test synchronizes drift after
harvest, invokes the real production exporter in a subprocess, and requires a
canonical `PRE_SEAL` mutation receipt with no bundle or staging output.

## 3. Exact validation

All pytest runs used:

- `PYTHONDONTWRITEBYTECODE=1`
- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`
- `python -B`
- `-p no:cacheprovider`

Final results:

| Gate | Exact result |
|---|---|
| production harvest/export focused file | 35 passed in 72.72s |
| production exact six-file RunBundle denominator | 527 passed in 131.94s |
| neutral evaluator focused Pashov/blinding/CLI | 79 passed in 7.67s |
| neutral evaluator full suite | 230 passed, 6 subtests passed in 83.49s |
| neutral production S-13 conformance | 1 passed in 4.31s |
| production packaging denominator | 9 passed in 93.99s |
| cross-OS pre-handoff gate | 22 passed in 6.93s |
| native Windows physical focus | 4 passed, 120 deselected in 0.66s |
| evaluator compileall | PASS |
| production RunBundle py_compile | PASS |
| git diff check | exit 0; line-ending warnings only |

The production 527-test denominator was run twice. The earlier run also
passed, in 212.88s, but a policy-preimage field was written during that run.
Only the final 131.94s frozen-source run is the acceptance result.

## 4. Wheel, isolated install, and freeze

Two independent clean external wheel builds were byte-identical:

- SHA-256:
  `8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f`
- byte length: `162258`

The exact wheel is preserved at the new boundary:

`<PRIVATE_EVALUATOR_REPO>/dist/frozen-v8/plamen_eval_control-0.2.0-py3-none-any.whl`

It was installed offline into a fresh venv with `python -I -m pip install
--no-index --no-deps`. With no `PYTHONPATH`, `PYTHONNOUSERSITE=1`, isolated
Python, and temporary HOME/USERPROFILE, it:

- imported `plamen_eval` from that venv's `site-packages`;
- reported package and CLI version `0.2.0`; and
- installed exactly 47 schema files.

The R8 local freeze is:

`Downloads/Plamen_RunBundle_V2_Local_Freeze_R8_2026-07-29.json`

- embedded freeze-manifest SHA-256:
  `19a6c2c40f8ae3265579fc6820339e30141103a4f9362c9872f75e4b1de256ff`
- raw manifest-file SHA-256:
  `9e081e269736564d8c7696aa8cbe7ff107e215b168429576c6a2756e3989e446`
- raw manifest length: `68968`
- immediate replay: `REPLAYED`

Frozen aggregate identities:

| Set | Count | SHA-256 |
|---|---:|---|
| production runtime | 7 | `052472ff2942fb54a0d61398d32b31ace35000aa351132d96a7bf11ba2ac3923` |
| production RunBundle tests | 6 | `68c9d5e9c8dc5bf3bf9d71e2e9c029dd17158ab0a8009797208553f306bac329` |
| evaluator source | 28 | `d8eaa59a5aeac8d34b6cc5e59ecf5271d25bb2297ad3f0003f5bb0f801bd9131` |
| evaluator tests | 29 | `d3ba585b2bd2bba029320c4e444e793e681ab918fb11e59e825503ce620eec54` |
| production public API | 114 | `da4a68f28ac58735b1c906d80ba87a007f102338f245257c39ef4e2ac3e3e179` |
| evaluator public API | 103 | `f9284041b26a4ff2108b729ba21e24ef6e03a1bd2755d3e180b744c71ab2f801` |

## 5. Exact changed-file hashes

| File | Bytes | SHA-256 |
|---|---:|---|
| `plamen-codex-implementation/scripts/runbundle_export.py` | 52644 | `85c30dd6249b968ca3a367c1619eb4aae77aab1627bc4ad010f343fe647e5387` |
| `plamen-codex-implementation/scripts/runbundle_privacy.py` | 68508 | `8962f43fb361029be4cd7332cbcc37b302a766d43e82fd25bd603b5a91e9b2e2` |
| `plamen-codex-implementation/scripts/runbundle_sources.py` | 26315 | `08053a2bd185b982edc8192326f3d27c961480cf20ddce6ecb19a1d878f48c0d` |
| `plamen-codex-implementation/scripts/test_runbundle_real_harvest_export.py` | 35900 | `6ea59635239762b10cd7c1def0029c1eb83eeba6d1972a2ca26cfb1e3d1dd745` |
| `<PRIVATE_EVALUATOR_REPO>/tests/test_real_v2_production_conformance.py` | 13896 | `d72c4b0ab78793d6c68700611502720c41e247aa3ac2489fa1dc933507029a51` |
| `<PRIVATE_EVALUATOR_REPO>/tools/runbundle_v2_freeze.py` | 25800 | `e25515a151d1c6bc4b688dac1c3176f90bb1f5d5f42c18d033c5495c0fc8e371` |
| `<PRIVATE_EVALUATOR_REPO>/docs/runbundle-v2-freeze.md` | 4367 | `7f50a9423ca831d2d2c7feb1d25f85a0e8b2b4da110a1a9fac2f1160dcac8b4f` |
| `<PRIVATE_EVALUATOR_REPO>/README.md` | 8065 | `9096a87f633cac32b60131d6e601f18b29c29433522905c407924853195fa0ff` |
| `<PRIVATE_EVALUATOR_REPO>/dist/frozen-v8/plamen_eval_control-0.2.0-py3-none-any.whl` | 162258 | `8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f` |
| `Downloads/Plamen_RunBundle_V2_Local_Freeze_R8_2026-07-29.json` | 68968 | `9e081e269736564d8c7696aa8cbe7ff107e215b168429576c6a2756e3989e446` |

## 6. Required independent review

The independent reviewer should, at minimum:

1. verify every hash in Sections 4 and 5 before reading conclusions;
2. replay the R8 freeze from both local repository roots;
3. rerun the original R7 synchronized counterexample unchanged;
4. inspect whether both live checks are after the required work and before
   accepted publication;
5. attack add/remove/rename/replacement/case-collision/symlink/reparse/
   junction/hardlink/ADS/sparse and restored-metadata transitions;
6. attack mutation during each capture, harvest, materialization, index,
   staged verification, and promotion boundary;
7. attack journal schema closure, digest substitution, null/non-null
   relabeling, source-path omission, source-path aliasing, recovery drift,
   stale code/policy, and staging cleanup;
8. verify the mutation receipt is canonical, idempotent, path-private,
   GT-blind, and cannot be mistaken for an accepted bundle;
9. verify prior sealed generations remain byte- and identity-stable;
10. rerun exact production, evaluator, packaging, cross-OS, Windows,
    double-wheel, isolated-install, and freeze-replay gates; and
11. issue PASS or BLOCK without treating this author handoff as evidence of
    comparative audit effectiveness.

## 7. Author disposition

R8 is ready for independent blocking review. No cutover, commit, merge, push,
provider run, benchmark claim, or audit authorization is made by this handoff.
