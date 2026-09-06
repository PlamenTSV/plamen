# Plamen RunBundle V2 — Codex review handoff

Date: 2026-07-29  
Disposition requested: independent blocking review  
Implementation status: source frozen for review; not committed or pushed  
Claim boundary: local implementation and fixture validation only

## Frozen review boundary

The normative machine-readable boundary is:

`<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Local_Freeze_2026-07-29.json`

SHA-256:

`0cea65cd23ee9a32c1e07b9fb69027a25b040d3a0e7001266f22bbf9630ebba9`

The manifest binds the exact RunBundle runtime, tests, evaluator source, schemas,
packaging inputs, public API surfaces, phase maps, clean wheel, and authenticated
B1 fixture seal. Both repositories remain shared dirty worktrees, so repository
HEAD alone is not the implementation identity.

## Review blockers addressed

1. The evaluator now performs an independent cross-artifact semantic replay and
   consumes every typed B1 authority against reconstructed bundle facts. Valid
   signatures over a foreign run-context commitment or a foreign severity decision
   are rejected. The signed physical partition and report-quality preimages are
   reconstructed independently.
2. Evaluator and Pashov input reads use one bounded, stable filesystem capture with
   root-alias, TOCTOU, hardlink, reparse, sparse-file, ADS, case-fold, and NFC
   collision rejection.
3. Blind review packets use a closed visible projection; nested system, cell,
   run, producer, receipt, and candidate identities are not copied.
4. Comparison cells require a closed field roster and exact seed, backend,
   repetition, budget-group, total-budget, and per-channel parity. The required
   2x2 matrix cannot be omitted through optional fields.
5. Lifecycle adjudication rejects downstream `YES` after any upstream
   non-`YES` state.
6. Windows stream enumeration now installs its ctypes structure and Win32 ABI once
   at module scope. A 256-iteration regression proves stable type identities and
   call signatures.
7. Export recovery now requires an explicit caller-authorized `out` path. The
   journal location, nonce-bearing staging directory, output parent/name, and
   canonical journal fields must match that authority. Self-consistent forged
   output/staging paths and wrong output capabilities are rejected.
8. Nested v2 schemas are closed, source/package versions agree at `0.2.0`,
   canonical JSON is bounded and NFC/case-fold checked, and SC/L1 phase-map hashes
   are recomputed from their ordered preimages.
9. Pashov V3 inventory is captured once, its adapter pin must be committed by the
   public case lock, and the retained bytes and complete parse preimage are bound.
   It remains explicitly local adapter evidence, not independent comparator
   execution attestation.

## Validation evidence

- Production RunBundle matrix: `509 passed in 104.53s`.
- Neutral evaluator full suite: `156 passed, 6 subtests passed in 51.35s`.
- Production packaging contract: `2 passed in 21.09s`.
- Public packaging freeze: `4 passed in 84.73s`.
- Cross-OS/toolchain pre-handoff gate: `22 passed in 2.99s`.
- Clean wheel:
  `plamen_eval_control-0.2.0-py3-none-any.whl`,
  SHA-256
  `1874f8c4a4d3d4eb72e154108e0f3ef83558d0be4b3e92300387bef41a694362`.
- The wheel was installed offline into a fresh environment with an empty profile
  and no repository on `PYTHONPATH`.
- That installed wheel independently verified and content-address imported the
  exact B1 fixture seal
  `884c9d727576c95ede36eb93782933bd5dec4dbfab25664ed8b1fa09bcc6c473`.
- Freeze-manifest replay succeeded with no hash drift.

## Requested adversarial checks

The reviewer should treat the following as blocking:

1. Recompute every source-set, schema, API, phase-map, wheel, and key-file hash in
   the freeze manifest.
2. Attack typed authority replay with valid signatures over:
   a foreign run context, correct subject IDs but wrong semantic payload, extra
   signed rows, unused authority records, and a forged physical partition.
3. Attack capture/import with root aliases, junctions/reparse points, hardlinks,
   ADS, mutation between capture and use, case-fold collisions, and Unicode
   normalization collisions.
4. Attack recovery with a self-hashed forged journal, sibling staging directory,
   wrong output capability, aliased parent, existing target, and payload drift.
5. Inspect all nested object schemas for any remaining open object and confirm the
   installed wheel resolves packaged schemas rather than the source checkout.
6. Confirm Pashov output cannot be represented as B1 effectiveness evidence and
   that no nested identity leaks into blinded review material.
7. Verify no synthetic-v1 behavior or golden fixture changed.

## Non-claims and external boundary

This handoff is explicitly `not_B1_effectiveness_evidence`.

It does not claim recall improvement, precision improvement, comparative
superiority, secure execution isolation, provider-authenticated metering, or
publication-grade B1 completion. Those require a governed hidden corpus, a secure
independently operated launcher, external authority keys, independent blinded
reviewers/adjudicator, provider evidence, and independently pinned comparator
execution.

No live audit, network operation, commit, push, merge, or publication was performed.
Source generation should remain frozen until the independent reviewer issues a
disposition against the exact manifest hash above.
