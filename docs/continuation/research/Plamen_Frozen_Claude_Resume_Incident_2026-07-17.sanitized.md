# Plamen frozen-Claude resume incident

Date: 2026-07-17  
Run: `evm-siloconfig-thorough-007-claude-frozen`  
Purpose: regression-only legacy-Claude architecture canary; never benchmark-scored

## Disposition

The frozen baseline is a **terminal failed baseline**, not a completed audit. It stopped after report-stage worker execution because backend-created runtime state was classified as audited source drift. A subsequent invocation with the identical configuration, intended only to test resume behavior, did not preserve and resume the stopped transaction. It automatically archived the old scratchpad, reset the checkpoint, removed or moved project-root run outputs, and launched recon workers. The observer was manually stopped to avoid an unintended second multi-hour audit.

This incident disproves clean identical-resume behavior. It does not invalidate the preserved pre-resume evidence: the automatic scratchpad archive contains byte-identical copies of every scratchpad file in the authoritative pre-resume manifest.

## Authoritative pre-resume state

- Receipt: `<PRIVATE_RUN_EVIDENCE_ROOT>\2026-07-17\launcher-logs\evm-siloconfig-thorough-007.run-state.authoritative-before-resume.json`
- Receipt SHA-256: `372DEE9E480290C8E1C99504FD02A3F18A38E378EC3A75C385B7A4F3711982B6`
- Manifest SHA-256: `01742C27541BB157A2CB61E745875DFBB4BE3EB4F33FE5C3D74E22F65B80FBFF`
- Files: 834; unreadable: 0; dispatch prompts: 84; model stdio logs: 129.
- Checkpoint: 70 completed phases; degraded: `report_assemble`.
- Last committed report phase: `report_low_info_merge`.
- `report_dedup_agent_decisions.md` existed, but the phase was not committed because post-execution snapshot validation failed.
- `report_dedup`, `report_disposition`, and `report_floor` never ran.
- The assembled report existed before resume, but its quality phase had degraded on a false private-ID substring match; it was not a completed final report.

The archived checkpoint is SHA-256 `426C31D725209997C352E8E9A54E8176086A9512FB6BDAA8FE2781E03726A5DC` and records stored snapshot digest `979948076AAEBFE0CDD4D86437E8AE08F15195D57BB29E691DAB440F5A200A68`.

## Original stop trigger

The Claude backend created project-local `.claude/scheduled_tasks.lock` during report-dedup background-task activity. Because project-context snapshot construction treated this ephemeral runtime file as stable audited input, post-execution validation emitted `audit_input_drift.json` with:

- phase: `report_dedup_agent:post-execution`
- changed component: `source_scope`
- stored snapshot: `979948076AAEBFE0CDD4D86437E8AE08F15195D57BB29E691DAB440F5A200A68`
- current snapshot: `BDF51DF8946C516504B9B48A4B8C6B6C31C9378886C496A8081073E366BB248C`

This is the P0-AN runtime/input-classification defect. The drift stop itself was fail-closed; the supported backend caused the false input drift.

## What the identical resume did

Startup classification treated the stopped run as a mismatch and invoked the automatic rewind path. Current code explicitly:

1. renames the complete scratchpad into `.plamen-stale-snapshots/stale-<uuid>`;
2. creates a new scratchpad and fresh empty checkpoint;
3. archives project-root reports and selected fuzz artifacts;
4. re-prepares inputs and rebinds a new snapshot; and
5. continues into recon without an explicit restart authorization.

The resulting receipt is:

- New scratchpad `snapshot_rewind_receipt.json` SHA-256: `2DC3772740F1F6794C2E2E04F8F6E8644D5EE8C971C8A68378444DEACE7BCF81`
- verdict: `MISMATCH`
- changed components: `source_scope`, `toolchain`
- new snapshot: `8BDEF8DA17A2D0955C762598423021A45E24792358A6571977274AF5070B0BC9`
- archive: `<PRIVATE_RUN_EVIDENCE_ROOT>\2026-07-17\evm-siloconfig-thorough-007-claude-frozen\.plamen-stale-snapshots\stale-b36cd68055304217a48aaec6ddf94696`

During observation, the new run launched a Python driver and multiple Claude recon workers. The outer observer was terminated with that process tree before it could write its normal process receipt. That operator observation is therefore supporting, not sole, evidence. The new scratchpad independently contains five new dispatch prompts, four Claude stdio logs, recon worker-pool state, and partial recon outputs.

## Archive preservation proof

The pre-resume receipt contains 701 scratchpad files. Mapping each `.scratchpad/<relative path>` entry to the automatic archive and hashing the archive produced:

- expected scratchpad files: 701
- present: 701
- byte/hash matches: 701
- missing: 0
- changed: 0

The archive has three additional archive-time files: a regenerated scratchpad-owner sentinel, `snapshot_mismatch_receipt.json`, and an archive-time `_plamen.log`. The mismatch receipt is SHA-256 `890B258013B10BAD4B20C60FDE765708D08C3D11FA2C902EF33C245013C595F7`.

This proves preservation of the original scratchpad evidence, but it does **not** make the resume correct: identity, active checkpoint, root outputs, and process lifecycle were changed.

## Independent before/after comparison

After manually stopping the unintended fresh run, the run root was captured again:

- After receipt: `<PRIVATE_RUN_EVIDENCE_ROOT>\2026-07-17\launcher-logs\evm-siloconfig-thorough-007.run-state.after-aborted-auto-restart.json`
- After receipt SHA-256: `6FAF6FCB21374EC24DA3EC8C4688C33E0E85CFA41D026881D6B55AF21C65A47D`
- After manifest SHA-256: `A98C3CE4A807AC7D492C035E7476685C2E3D1564DE0B3FB0D7491B63A62756CE`
- Comparator receipt: `<PRIVATE_RUN_EVIDENCE_ROOT>\2026-07-17\launcher-logs\evm-siloconfig-thorough-007.resume-comparison.failed-auto-restart.json`
- Comparator SHA-256: `B9351C1476F503BA604477E5466BD724D1E4F30DAD63801576FAD3ECEFFA5E5D`

Comparator result:

- status: `FAIL`
- admissible: `true`
- exact equal: `false`
- no model relaunch: `false`
- no semantic mutation: `false`
- added paths: 706
- removed paths: 747
- changed paths: 28
- `AUDIT_REPORT.md`: removed from the active run root
- generated-test paths removed from their original locations: 37
- active checkpoint changed from 70 completed phases to an empty fresh checkpoint

Many “added” paths are the preserved files under their new archive prefix, and many “removed” paths are their former active scratchpad identities. That distinction reinforces the architectural defect: bytes survived, but the run transaction and authoritative identities did not.

## Implementation repository isolation

The canary/resume incident did not mutate the implementation worktree:

- implementation HEAD: `67A0F85ADC7A8169D79A286908B00BEF7ADB764A`
- dirty diff fingerprint: `B7FC9260AC6628B7DE798692DE78956206F117FB`
- status entries: 57

Those values match the frozen pre-resume implementation state. Nothing was committed, pushed, merged, or installed.

## Required correction

This incident establishes P0-AO:

- A normal resume request must never reinterpret input mismatch, unbound legacy state, graph mismatch, or failed post-execution validation as authorization to archive/reset/relaunch.
- Mismatch must stop before model launch and emit a typed decision request identifying the changed components and available actions.
- Explicit restart is a separate command with a new run identity and destination. It must preserve the prior run root as immutable evidence and must not remove its delivered report, tests, checkpoint, or artifacts.
- Continuing an existing run is permitted only when its exact snapshot and phase transaction validate, or after a separately recorded human-approved migration that preserves before/after lineage.
- The resume observer must support abort-on-first-model-child and still write its receipt after terminating only the observed child tree.

The corrected behavior requires red-to-green fixtures for mismatch-without-authorization, explicit new-run restart, unchanged resume, post-execution drift, legacy unbound state, mode/graph mismatch, root-report preservation, generated-test preservation, process-crash recovery, concurrent startup, Windows/POSIX paths, and observer abort receipt durability.
