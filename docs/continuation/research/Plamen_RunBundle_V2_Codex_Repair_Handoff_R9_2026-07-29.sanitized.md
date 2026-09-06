# Plamen RunBundle V2 Codex Repair Handoff R9

Date: 2026-07-29
Author lane: Codex RunBundle R9 repair author
Review state: AUTHOR COMPLETE; INDEPENDENT REVIEW REQUIRED
Commit/push state: no commit, merge, push, provider run, or audit performed
Claim scope: local implementation and fixture validation only

This artifact is ASCII only. It does not authorize cutover and is not B1
effectiveness, recall, precision, comparison, or publication evidence.

## 0. Exact review boundary

R9 closes the residual publication race left after R8:

- a live source could change immediately before staging promotion;
- a live source could change immediately after promotion but before promoted
  verification and successful return; and
- the promoted directory could therefore exist without a final live-source
  authority check at the exact publication boundary.

R9 adds two bounded observations after promotion and makes a separately
verified READY receipt the only production harvest authority. Drift retires
and quarantines only the just-published target. Existing sealed generations
are never replaced or modified.

Repository HEADs identify the dirty local baselines. They do not identify or
commit the R9 source:

- production HEAD: `67a0f85adc7a8169d79a286908b00bef7adb764a`
- evaluator HEAD: `345d016d0c86b6201e90cec908c37c6a66f739c3`

The author does not certify this repair. An independent reviewer must replay
the freeze, inspect the source, reproduce the counterexamples, attack the
publication and recovery boundaries, and issue the blocking verdict.

## 1. Normative publication protocol

### 1.1 Durable no-replace promotion

Publication now uses `_durable_directory_rename_new`, not an overwrite-capable
generic rename:

- Windows uses `MoveFileExW` with write-through behavior and an absolute
  extended-length path;
- Linux uses `renameat2` with `RENAME_NOREPLACE`;
- Darwin uses `renamex_np` with `RENAME_EXCL`;
- the parent directory is fsynced where the platform exposes the required
  primitive; and
- unsupported native semantics fail closed.

The source and target must be plain directories in the same parent. Symlink
or reparse targets are rejected. A pre-existing target is never replaced.
Postconditions require the source to be absent and the new target to be the
published directory.

The external promotion journal is created durably before rename:

`.<output-name>.<nonce>.promotion.json`

It is a sibling control artifact, not content inside the RunBundle.

### 1.2 Final bounded authority sequence

For a live-source export, the acceptance-critical tail is:

1. verify the complete staged bundle and its captured source authority;
2. write the durable external promotion journal;
3. promote staging to the fresh target with no-replace native semantics;
4. re-enumerate and re-read the full live source closure at
   `POST_PROMOTION`;
5. verify the promoted bundle from the target path;
6. re-enumerate and re-read the full live source closure at
   `POST_VERIFY_PRE_READY`;
7. create a canonical sibling READY receipt bound to the promoted bundle,
   both exact observations, the exporter code and policy, and the run;
8. reload and verify the exact on-disk READY bytes; and
9. return success only after the reloaded READY binds the verified target.

The two observations bind:

- the exact live-source authority SHA-256;
- the exact observation state;
- observation start and completion UTC timestamps;
- a canonical observation digest; and
- the explicit claim limitation
  `BOUNDED_OBSERVATIONS_NOT_CONTINUOUS_OR_PERPETUAL_IMMUTABILITY`.

R9 does not claim that source files remain immutable after READY. It proves
only that the exact source closure matched at the two recorded bounded
observations. READY is the acceptance boundary for that published generation.

### 1.3 READY is the only production harvest authority

The sibling authority receipt is:

`.<output-name>.READY.json`

Production `verify_export` rejects:

- a bundle with no READY receipt;
- a bundle with an invalid or non-canonical READY receipt;
- a READY receipt that does not bind the verified target;
- a target with a RETIRED receipt; and
- a seal without READY.

The exporter returns only after reloading and validating the exact READY
bytes from disk. A seal, directory name, promotion journal, or verifier prose
cannot independently authorize harvest.

The neutral evaluator can inspect foreign RunBundle content without adopting
production publication authority. The production import boundary remains
responsible for the local READY rule.

### 1.4 Drift, retirement, and quarantine

Any post-promotion source drift creates a typed canonical mutation or failure
receipt, then durably retires the just-published target:

`.<output-name>.RETIRED.json`

The retirement receipt binds the control receipt, exporter identity, output
name, run ID, UTC timestamp, and `NO_READY_NO_HARVEST`.

The just-published target is moved with the same durable no-replace primitive
to a unique sibling:

`.<output-name>.retired-<nonce>`

No prior target is replaced. No prior sealed generation is altered.

If quarantine itself fails, the exporter fails loudly. It attempts to leave
durable retirement state and never writes READY. Therefore the generation is
not harvestable even when cleanup is incomplete.

A valid, already verified READY target is not silently retired by later
journal cleanup debt. READY is the authority cutoff. Cleanup failure after
that cutoff remains loud operational debt but does not retroactively rewrite
the accepted generation.

### 1.5 Interruption and recovery

The journal schema is `plamen.real-audit-export-journal.v3`.

Recovery accepts exactly one authorized topology:

- an unpromoted staging directory plus its staging journal; or
- an already promoted, unready target plus its sibling promotion journal.

Recovery requires the caller-authorized output path, exact source authority,
code and policy identity, payload, objects, index, run identity, and fresh
target topology. It performs the same promoted verification, two bounded
source observations, READY creation, on-disk READY reload, retirement, and
quarantine protocol as a direct export.

An interruption immediately after promotion leaves an unready target. It
cannot be harvested. An unchanged source can resume to READY. A changed source
is retired and quarantined. Recovery never upgrades an absent or mismatched
source authority and never changes an earlier sealed generation.

## 2. Fixture-first repair evidence

The initial R9 fixtures were executed before the complete repair. Four
promotion/recovery fixtures failed because the durable publication helper and
new authority behavior did not yet exist or the inherited verification call
shape was obsolete. The complete inherited focused file also exposed four
partial-R9 failures before the final integration.

The final production matrix covers:

- source mutation immediately before promotion rename;
- source mutation immediately after promotion rename;
- the same two windows during interrupted recovery;
- add, remove, rename, same-byte replacement, and restored-mtime content
  changes after promotion;
- scratchpad and final-report replacement;
- symlink, hardlink, and simulated reparse transitions;
- mutation during promoted verification;
- mutation by the final READY publisher before its last observation;
- tampering with READY before successful return;
- interruption after promotion and unchanged-source resume;
- interruption after promotion followed by source drift and retirement;
- direct and recovered stage labels;
- seal-only, unready, and retired targets denied production harvest;
- quarantine failure remaining loud and unharvestable;
- no-replace preservation of independent source and target directories;
- native Windows extended-length paths beyond 260 characters;
- cleanup failure before and after the READY authority boundary;
- observation schema, digests, timestamps, state, and bounded-claim wording;
  and
- preservation of an independent prior sealed generation.

The out-of-tree evaluator conformance suite now contains a separate R9
subprocess counterexample. It patches only the production promotion primitive,
changes the live report immediately after rename, and requires:

- `MUTATED_DURING_EXPORT`;
- stage `POST_PROMOTION`;
- no output target;
- no READY receipt;
- a canonical mutation receipt;
- a canonical RETIRED receipt; and
- one quarantined just-published generation.

This neutral test is in addition to the R8 pre-seal late-drift conformance
test.

## 3. Exact validation results

Final relevant results:

| Gate | Exact result |
|---|---|
| production R9 targeted recovery/rename matrix | 10 passed, 31 deselected in 25.45s |
| production post-promotion physical matrix | 13 passed, 41 deselected in 15.19s |
| production READY/interruption/cleanup matrix | 10 passed, 46 deselected in 26.13s |
| production durable no-replace and Windows long path | 2 passed, 56 deselected in 3.39s |
| production focused harvest/export file | 58 passed in 102.53s |
| production exact six-file RunBundle denominator | 550 passed in 387.01s |
| neutral production conformance after R9 addition | 4 passed in 9.06s |
| evaluator focused Pashov/blinding/CLI | 79 passed in 12.66s |
| evaluator full suite after R9 addition | 231 passed, 6 subtests passed in 46.20s |
| evaluator freeze replay tests | 3 passed in 7.22s |
| evaluator packaging denominator | 9 passed in 329.63s |
| cross-OS pre-handoff gate | 22 passed in 16.68s |
| native Windows physical focus | 4 passed, 120 deselected in 3.29s |
| production scoped py_compile | PASS |
| evaluator compileall | PASS |

The first packaging attempt ran concurrently with another long gate and
timed out after 244 seconds without a pytest verdict. The isolated rerun is
the recorded acceptance result: 9 passed in 329.63 seconds.

An initial isolated-install probe looked for schemas under the import package
directory and failed because the wheel correctly installs data under
`sys.prefix/share/<PRIVATE_EVALUATOR_REPO>/schemas`. The corrected probe found
exactly 47 schemas. This was a probe-path correction, not a package change.

The exact production six-file denominator was:

- `scripts/test_runbundle_export_ready_marker.py`
- `scripts/test_runbundle_phase_map.py`
- `scripts/test_runbundle_real_harvest_export.py`
- `scripts/test_runbundle_v2_contracts.py`
- `scripts/test_runbundle_v2_privacy.py`
- `scripts/test_runbundle_v2_r5_regressions.py`

## 4. Runtime and artifact identities

Final exporter identity:

- version: `2.2.0`
- exporter code SHA-256:
  `7796df218dbaffa43ffa0b8354a1c55537d02ebd26035ba3d0f8e70bd2bcd0ca`
- exporter policy SHA-256:
  `663b4f8b0ee94456854a82f2a2daadd4afffcfb126d9d55b5c3ba562fa5782ef`

Two independent external wheel builds were byte-identical:

- filename: `plamen_eval_control-0.2.0-py3-none-any.whl`
- byte length: `162258`
- SHA-256:
  `8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f`

The preserved wheel is:

`<PRIVATE_EVALUATOR_REPO>/dist/frozen-v9/plamen_eval_control-0.2.0-py3-none-any.whl`

It was installed offline into a fresh virtual environment with:

`python -I -m pip install --no-index --no-deps`

With no `PYTHONPATH`, `PYTHONNOUSERSITE=1`, isolated Python, and temporary
HOME and USERPROFILE, the installed artifact:

- reported version `0.2.0`;
- imported from the fresh venv site-packages;
- exposed CLI version `0.2.0`; and
- installed exactly 47 schemas under
  `sys.prefix/share/<PRIVATE_EVALUATOR_REPO>/schemas`.

## 5. R9 local freeze

Freeze artifact:

`Downloads/Plamen_RunBundle_V2_Local_Freeze_R9_2026-07-29.json`

- embedded freeze-manifest SHA-256:
  `fd4d25712c7806545ded1476fb797433e06e73a05446c1e401675d6c2545757f`
- raw manifest-file SHA-256:
  `dcddd516cc94375422080be3beb40bc00dadec26155d03c9735d6e8be0e7000f`
- raw manifest length: `69366`
- immediate replay: `REPLAYED`

Frozen aggregate identities:

| Source set | Count | SHA-256 |
|---|---:|---|
| production runtime | 7 | `7d60319651f52774b480f25de64b6defa140c32d0d331081cf5054c55e4294be` |
| production RunBundle tests | 6 | `815ae177d86b68f28498164060b72f80cef336b42dd2c4e6f93ad82037d98416` |
| evaluator source | 28 | `d8eaa59a5aeac8d34b6cc5e59ecf5271d25bb2297ad3f0003f5bb0f801bd9131` |
| evaluator tests | 29 | `f3cfe9e8c256f3a45ee2caa4738455cf8de075fdbbbdbafca3ec72e551313a5b` |
| evaluator schemas | 47 | `2423f116380205e01c6d7114112c2b95d24081a0fb7f09aa8a113ccc6484cad8` |
| evaluator packaging | 2 | `8bf0b3d4d6e918529379b2e53114db7966d207fec08b52d4b056a3608db8986b` |
| freeze tooling | 2 | `84c3be630ea8278537885c88c5316a01d712c241a3d7024a1600cb63c0c344bb` |
| production public API | 118 | `6715f1a72de5af8b70240a8401fab4c5e9a1427be659960907306e3c4afd8531` |
| evaluator public API | 103 | `f9284041b26a4ff2108b729ba21e24ef6e03a1bd2755d3e180b744c71ab2f801` |

## 6. Exact key-file hashes

| File | Bytes | SHA-256 |
|---|---:|---|
| `plamen-codex-implementation/scripts/runbundle_export.py` | 87970 | `f5d4adef9b02d62431f029ea1d8baa099440b9553acf41c3b7e81ca2dbe3c993` |
| `plamen-codex-implementation/scripts/test_runbundle_real_harvest_export.py` | 58621 | `754e897b0846c2d40dc2f16be91242da8d367c113e11aa1b3c4c9117ba8137f7` |
| `<PRIVATE_EVALUATOR_REPO>/tests/test_real_v2_production_conformance.py` | 16854 | `99b47ecd87aa1b6faa7dd77597e0f70fd9c3d4bb8f303d185c9757cd9653d879` |
| `<PRIVATE_EVALUATOR_REPO>/tools/runbundle_v2_freeze.py` | 25800 | `1958c1e89526f98b7b80752382216d0eb623816fae4f1d3a73e4f23a5b84c292` |
| `<PRIVATE_EVALUATOR_REPO>/docs/runbundle-v2-freeze.md` | 4367 | `ef1b8a4f75a943f4f2cba11b7cc70405aad4c20b886db7fe7d7fe77a2e029433` |
| `<PRIVATE_EVALUATOR_REPO>/dist/frozen-v9/plamen_eval_control-0.2.0-py3-none-any.whl` | 162258 | `8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f` |
| `Downloads/Plamen_RunBundle_V2_Local_Freeze_R9_2026-07-29.json` | 69366 | `dcddd516cc94375422080be3beb40bc00dadec26155d03c9735d6e8be0e7000f` |

## 7. Limits and non-claims

This author evidence is deliberately narrower than whole-program release
readiness:

- the two repositories are dirty and shared with concurrent work;
- the R9 freeze binds the exact owned source sets and wheel, not unrelated
  moving files in either worktree;
- whole-tree tests must be rerun by the root orchestrator after all author
  lanes quiesce;
- native filesystem execution in this lane was Windows;
- Linux and Darwin no-replace paths are implemented with native exclusive
  primitives and covered by platform-conditioned semantic tests, but require
  native CI execution before a cross-platform release claim;
- the evaluator can analyze foreign bundles independently; this does not
  weaken production's local READY import rule;
- READY proves bounded observations, not perpetual source immutability;
- no real provider, live B1 campaign, benchmark, comparative recall, or
  precision claim was run; and
- no audit was launched.

## 8. Required independent blocking review

The independent reviewer should, at minimum:

1. verify the Section 4 through 6 hashes before relying on conclusions;
2. replay the R9 freeze from both exact repository roots;
3. rebuild two wheels externally and compare every byte to the frozen wheel;
4. install the wheel offline into a fresh isolated environment;
5. reproduce mutation immediately before and after promotion rename;
6. reproduce mutation during promoted verification and before READY;
7. attack add, remove, rename, case collision, same-byte replacement,
   restored mtime, symlink, reparse, junction, hardlink, ADS, sparse, and
   alternate-stream transitions at every final window;
8. attack Windows extended-length paths and native no-replace behavior;
9. run the Linux `renameat2(RENAME_NOREPLACE)` and Darwin
   `renamex_np(RENAME_EXCL)` paths on native hosts;
10. attack target pre-existence, target substitution, parent substitution,
    journal substitution, stale journal, and wrong authorized output;
11. interrupt before rename, immediately after rename, during promoted
    verification, before READY, after READY, and during cleanup;
12. verify an unready or retired target cannot pass production `verify_export`;
13. force retirement and quarantine failures and prove no READY is created;
14. verify valid READY cannot be replaced, forged, or silently retired;
15. verify exact READY bytes are reloaded before successful return;
16. verify both observation digests and timestamps bind the recorded bounded
    source states without making a perpetual claim;
17. verify prior sealed generations remain byte- and identity-stable;
18. rerun exact production, evaluator, packaging, cross-OS, native Windows,
    isolated-install, and freeze gates; and
19. issue PASS or BLOCK without treating this author handoff as comparative
    audit-effectiveness evidence.

## 9. Author disposition

The R9 author slice is complete and frozen for independent blocking review.
No cutover, commit, merge, push, provider run, benchmark claim, or audit
authorization is made by this handoff.
