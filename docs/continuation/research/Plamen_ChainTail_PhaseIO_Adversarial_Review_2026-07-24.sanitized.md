# Plamen Chain-Tail PhaseIO Adversarial Checkpoint Review

**Date:** 2026-07-24  
**Disposition:** **BLOCKED — repair authorized only against the consolidated roster below**  
**Review mode:** independent, read-only, adversarial checkpoint review  
**Scope:** isolated chain-tail scheduling, shard MODEL and DRIVER commits, semantic disposition authority, final aggregation/publication, legacy compatibility, retry behavior, Claude output isolation, and downstream candidate delivery

## 0. Executive disposition

The checkpoint is not safe to accept yet.

The implementation has made real progress: isolated MODEL transcripts are unique per shard, MODEL precedes DRIVER in the intended path, the obsolete post-hoc authority recorder has no production callers, clean pre-arm behavior exists, and the focused suites exercise substantially more than the earlier implementation. Those properties do not compensate for unresolved authority gaps in the commit protocol.

Sixteen blockers were found. The most important are not isolated parser defects. They share one architectural cause: the implementation still splits semantic truth among a mutable control ledger, a non-authoritative scheduler journal, unbound archive copies, root compatibility artifacts, and partially independent PhaseIO receipts. Because those stores do not yet participate in one recoverable transaction, a crash, retry, deleted marker, mutated copy, or direct helper invocation can cause semantic state to advance without its required evidence—or can publish evidence that was never committed.

The coherent repair is:

1. Make the manifest plus committed producer receipts the canonical denominator.
2. Give every semantic transition a pre-armed, idempotently recoverable DRIVER transaction.
3. Build one immutable terminal semantic snapshot from exact committed predecessors.
4. Make the final publication consume only that snapshot and exact committed transcript bytes.
5. Treat scheduler files and mutable control projections as operational hints and consistency checks, never authority.
6. Make root compatibility publication a generation-scoped transaction, not a permanent capability.

The implementer was frozen until this complete sweep closed. Editing was released only against the complete roster in this document. A second independent review is required after a new `TREE_QUIESCENT` declaration.

## 1. Frozen review boundary

### 1.1 Repository state

| Field | Reviewed value |
|---|---|
| Repository | `<LOCAL_USER_ROOT>\plamen-codex-implementation` |
| Git `HEAD` | `67a0f85adc7a8169d79a286908b00bef7adb764a` |
| Review fingerprint time | `2026-07-24T16:14:49Z` |
| Local time | `2026-07-24T19:14:49+03:00` |
| Working-tree note | The program is intentionally uncommitted/dirty; unrelated user and program changes were not modified. |

### 1.2 Reviewed file fingerprints

| File | Bytes | Last write UTC | SHA-256 |
|---|---:|---|---|
| `scripts/chain_tail_authority.py` | 98,204 | `2026-07-24T15:43:48.3082238Z` | `F3AB925D0203F16485A15CDAD2DCE7A0210838D149E325BF5AA0A72DCC058F7C` |
| `scripts/phase_io_contracts.py` | 141,737 | `2026-07-24T15:36:49.5499430Z` | `6CAF8B104D96DD5AC09C002CF0AF521B74B9D4C30D9E8CCBF56BB171119E1DC7` |
| `scripts/plamen_driver.py` | 2,123,241 | `2026-07-24T15:42:00.9694393Z` | `B03062C924AEC366C0AF39D637DCDCD83F52BEC2C59E2D4DC783C61AAD9370FB` |
| `scripts/test_chain_tail_isolated_phase_io_p0_t.py` | 16,440 | `2026-07-24T15:44:42.1959047Z` | `F2CDA61EE6401486AF240DF1B94E578C25E4EBE50D0B13BE6ED4EFF5A2ADA2CB` |

Any change to one of these files, or to an upstream/downstream authority component involved in the fixes, creates a new review boundary.

## 2. Required invariants

The second review will test the following invariants, not merely whether named tests pass.

### 2.1 Authority

- A mutable scheduler journal cannot add, remove, or redefine semantic work.
- A root Markdown or JSON compatibility artifact cannot become authority before a committed final publication.
- Every accepted terminal semantic disposition has one exact committed DRIVER producer.
- Every successful shard disposition has one exact committed MODEL predecessor.
- Every primary ChainAgent2 semantic input used at finalization has an exact committed producer.
- No consumer may accept a copied artifact without binding its original, copy, packet, source, and current byte digest.
- A legacy adapter is usable only when explicit legacy eligibility is proven and every isolation-era marker is absent.

### 2.2 Transactionality and recovery

- A crash at every write boundary is recoverable by deterministic roll-forward or explicit debt.
- Semantic state cannot advance while the corresponding receipt is absent.
- A committed MODEL transcript is never deleted, quarantined, rewritten, or rerun because a later DRIVER step failed.
- Failure paths are first-class terminal transactions, not log messages or soft return codes.
- Lock rejection cannot release another process's lock.

### 2.3 Recall preservation

- Every denominator identity ends in an exact terminal disposition or explicit unresolved debt.
- Every emitted chain hypothesis is represented in typed downstream delivery or explicit unresolved debt.
- No deletion, retry, deduplication, compatibility fallback, or publication failure can silently remove a found candidate.
- Negative dispositions cannot be treated as proof merely because the proposing producer wrote persuasive prose.

### 2.4 Publication

- Final publication consumes an immutable terminal snapshot and exact committed bytes only.
- Root compatibility outputs are written only by a newly pre-armed final publication transaction.
- A completed publication marker cannot authorize future root writes.
- Re-arming unresolved work cannot mutate prior committed root outputs or invalidate their recorded hashes.

## 3. Consolidated blocking findings

### B1. Work-unit copies are not strictly bound to originals, packets, and sources

**Observed failure**

The work-unit recording and validation path accepts a copied input after the copy, original, or self-declared digest has been changed and its local digest recomputed. The current checks establish that a document is internally well-formed, but not that it is the exact copy of the exact original selected by the scheduler and bound into the launch packet.

**Why this matters**

The MODEL may reason over different bytes or a different pair set than the DRIVER later believes it authorized. This defeats PhaseIO's core claim that an accepted output is a function of a frozen input set.

**Required repair**

Use one strict shared loader for both arming and validation. It must enforce:

- exact schema and schema version;
- exact work-unit index and shard identity;
- exact normalized relative paths;
- no absolute path, traversal, symlink escape, alias, or case-normalization ambiguity;
- exact pair identities, order, and denominator;
- exact packet and source references;
- exact current SHA-256 of the original and copy;
- exact original-to-copy byte equality where a copy is required;
- exact linkage from launch receipt to the same input set.

Local self-declared hashes are evidence fields, not authority.

**Required red-to-green fixtures**

1. Mutate the copy, recompute its self-digest: reject.
2. Mutate the original after arming: reject.
3. Swap two valid work-unit paths: reject.
4. Substitute a same-shaped work unit from another shard/run: reject.
5. Use traversal, absolute, alias, or case-variant paths: reject.
6. Exact unchanged original/copy/packet/source set: accept.

---

### B2. A rejected lock contender can delete the owner's scheduler lock

**Observed failure**

The scheduler lock cleanup unconditionally removes the lock path. A nested contender correctly fails to acquire the lock, but its cleanup removes the first owner's lock. A third contender can then acquire the lock while the first owner remains in its critical section.

**Why this matters**

Concurrent schedulers can materialize the same shard, advance cursors twice, or race semantic and receipt writes. File existence alone is not mutual exclusion if a non-owner can unlink it.

**Required repair**

- Write a unique owner token into the lock.
- Track whether the current context actually acquired it.
- Unlink only if the on-disk token still equals the context's owner token.
- Treat a changed or missing lock during owned cleanup as a consistency issue.
- Preserve atomic acquisition semantics.

**Required red-to-green fixture**

Owner A acquires; contender B is rejected; contender C must still be rejected until A releases. B's exit must not alter the lock bytes or path.

---

### B3. The scheduler journal is incorrectly used as the final semantic denominator

**Observed failure**

Deleting or truncating `started_shards` in the scheduler journal can make final readiness observe no shards and can allow finalization to omit real scheduled or completed work.

**Why this matters**

The design declares the journal non-authoritative, yet final exact-set computation depends on it. Operational history loss therefore becomes semantic recall loss.

**Required repair**

Derive the canonical shard denominator from immutable sources:

- the canonical manifest and work-unit identities;
- materialized canonical shard directories or immutable shard preparation records;
- committed terminal DRIVER receipts;
- committed control-history events if introduced.

The scheduler journal may answer “what should run next,” but never “what existed” or “what final must include.” Final readiness must prove exact set equality among expected units, committed MODEL units, committed terminal DRIVER units, and the terminal snapshot.

**Required red-to-green fixtures**

1. Delete the journal after one committed shard: final must debt/reconstruct, never return an empty denominator.
2. Remove one `started_shards` row: exact-set mismatch.
3. Add a phantom journal row: it cannot add semantic work.
4. Reorder journal rows: no semantic effect.

---

### B4. Semantic advancement and terminal disposition commit are not crash-atomic

**Observed failure**

A failpoint after the control ledger advances but before the terminal disposition receipt is written leaves the cursor advanced and `active_shard` cleared with no committed terminal receipt. Retry sees no active shard and cannot reproduce the missing transaction. The success direction has an analogous window.

**Why this matters**

This is a direct found-then-dropped failure mode: semantic work can be marked consumed while its authoritative result is absent.

**Required repair**

Create a durable per-shard transaction state machine, for example:

1. `ARMED`: exact contract and predecessor set are frozen.
2. `MODEL_COMMITTED`: exact transcript bytes committed.
3. `DISPOSITION_PREPARED`: proposed semantic delta and terminal receipt payload frozen.
4. `DISPOSITION_COMMITTED`: terminal DRIVER receipt committed.
5. `APPLIED`: mutable scheduler/control projection advanced idempotently from the committed receipt.

The precise names are flexible. The properties are not:

- durable intent precedes semantic mutation;
- receipt content is frozen before application;
- application is idempotent;
- retry determines the last committed state and rolls forward;
- success and failure use the same transaction discipline;
- concurrent transitions use a lock/CAS tied to the exact prior generation.

**Required failpoint matrix**

Inject a crash before and after every durable write/rename in both success and failure paths. Every restart must produce exactly one terminal receipt and exactly one semantic application, or explicit debt with no silent advancement.

---

### B5. Transcript-less failed shards can crash finalization

**Observed failure**

A failed shard is recorded with an empty `output_path`. The finalizer joins that empty value to the scratchpad path and attempts to read a directory as a transcript/archive.

**Why this matters**

Haltless degradation is violated on the exact path that should degrade safely. A worker failure can turn into a finalizer exception.

**Required repair**

Represent terminal failure explicitly:

- terminal kind/status is `DEBT`/failure;
- transcript is optional and explicitly absent;
- no archive read occurs for transcript-less terminal failures;
- exact failure reason and predecessor lineage remain in the terminal snapshot;
- final status remains degraded and visible.

**Required red-to-green fixtures**

1. Initial MODEL failure with no transcript finalizes as explicit debt.
2. Later DRIVER failure after a committed transcript preserves the transcript and finalizes as explicit debt.
3. Empty path is never resolved as the scratchpad directory.

---

### B6. Final authority can be reconstructed from a mutable control ledger

**Observed failure**

After terminal work, control-ledger evidence can be changed, the ledger digest recomputed, and final readiness can remain green. Final publication then emits the modified evidence even though the final contract did not bind that control-ledger version.

**Why this matters**

A digest proves only integrity relative to itself. It does not prove authorized provenance. Mutable control state can overwrite committed model/driver semantics.

**Required repair**

Build an immutable terminal semantic snapshot from:

- the immutable manifest;
- exact committed per-shard terminal DRIVER receipts;
- exact committed MODEL transcripts for successful dispositions;
- exact committed primary-coverage DRIVER receipt;
- exact deterministic publication rename mapping, if renaming is required.

The final PhaseIO contract binds the snapshot digest and exact predecessor receipts. The mutable control ledger becomes a convenience projection checked for parity; it cannot supply or override final evidence.

Do not mutate the snapshot during CH identity collision handling. Compute a deterministic publication mapping and publish a derived view while preserving original identities and lineage.

**Required red-to-green fixtures**

1. Mutate and rehash the control ledger after terminal commits: readiness/final rejects parity or ignores the mutation; output remains derived from committed receipts.
2. Delete the control ledger: final can reconstruct from committed authority or emits explicit consistency debt, never loses work.
3. Reorder mutable rows: snapshot and final bytes remain deterministic.

---

### B7. Production/legacy separation is inferred only from journal presence

**Observed failure**

After isolation-era artifacts exist, deleting the scheduler journal can make the system take a legacy reconciliation path and accept a stale root `chain_iteration2.md` as complete.

**Why this matters**

A missing marker downgrades the security mode. Isolation must be sticky once begun; deletion or corruption must increase debt, not restore permissive legacy behavior.

**Required repair**

Legacy reconciliation requires explicit positive eligibility plus the absence of every isolation-era marker, including:

- isolation control directory/state;
- work-unit originals or copies;
- shard directories/transcripts;
- PhaseIO model/disposition/failure units;
- terminal snapshot or final-publication generation files;
- scheduler history.

Once any isolation marker exists, missing or corrupt isolation state is debt. Do not infer legacy mode from one absent file.

**Required red-to-green fixtures**

1. Create isolation, delete journal, seed stale root delta: reject/debt.
2. Corrupt journal after isolation: reject/debt.
3. Genuine historical legacy run with explicit eligibility and no isolation markers: compatibility path remains usable.

---

### B8. A terminal failure receipt can reach final authority without a DRIVER producer

**Observed failure**

Calling the failure recorder directly can create a terminal failure receipt without a corresponding PhaseIO artifact state. Final readiness accepts it.

**Why this matters**

The receipt self-certifies its authority. A final exact set of files is insufficient if the files have no authorized producer.

**Required repair**

For every terminal shard result:

- require exactly one `ACTIVE`/`OUTPUT_COMMITTED` DRIVER PhaseIO producer;
- use the authorized unit kind for disposition or failure;
- bind contract key, run ID, launch receipt, complete input set, predecessor set, output path, and output SHA-256;
- reject duplicate or ambiguous producers;
- require successful dispositions to reference exactly one committed MODEL predecessor;
- make the frozen terminal snapshot consume these producer receipts, not untrusted terminal files.

**Required red-to-green fixtures**

1. Direct failure-recorder call without DRIVER producer: final rejects.
2. Failure receipt from another run/shard: rejects.
3. Output hash mismatch: rejects.
4. Exact committed failure DRIVER receipt: accepted as explicit debt.

---

### B9. Initial isolated-model failure and continuation exceptions are not terminalized

**Observed failure**

The terminal failure recorder is reached only in the later continuation loop. If the initial isolated model attempt exhausts retries, or if the chain validator catches a continuation exception, the broader phase can soft-checkpoint with an active/PENDING scheduler row and no terminal DRIVER receipt.

**Why this matters**

The first shard receives weaker guarantees than later shards. A phase completion marker can coexist with semantically unfinished chain work.

**Required repair**

Unify initial and continuation execution through one transaction wrapper. Every non-success exit—return code, timeout, exception, validation failure, retry exhaustion—must commit an authorized terminal failure/debt transaction or prevent phase completion with an explicit scheduler-debt artifact.

**Required red-to-green fixtures**

1. Initial MODEL attempt fails twice: one terminal failure DRIVER receipt, degraded final, no active shard.
2. Continuation callback raises: same outcome.
3. Validator catches exception: phase gate cannot mark complete without terminalization.
4. Retry/restart does not create duplicate terminal receipts.

---

### B10. `driver_merge` can bless a stale root delta without a committed final parent

**Observed failure**

With otherwise valid upstream ChainAgent2 ownership, isolation can be initialized and a stale shared `chain_iteration2.md` seeded. Invoking the merge recorder can mark the merge `APPLIED` and merge the stale chain section while no `tail_reconcile` unit exists.

**Why this matters**

The final compatibility artifact becomes an alternative semantic ingress that bypasses the isolated final transaction.

**Required repair**

The exact input to `driver_merge` must be the exact output of one `ACTIVE`/`OUTPUT_COMMITTED` `tail_reconcile` producer from the same run and generation. Check output path and digest parity. If isolation markers exist, shared root compatibility consumers must fail/debt before final publication.

**Required red-to-green fixtures**

1. Stale shared delta with no `tail_reconcile`: reject.
2. Delta digest differs from committed final output: reject.
3. Same-named output from another run/generation: reject.
4. Exact committed final output: merge applies once.

---

### B11. Finalization reads an unbound mutable shard archive

**Observed failure**

The final contract binds the isolated MODEL transcript, but aggregation reads `_chain_tail_shards/shard_XXXX.md`. Modifying that archive after the MODEL/disposition commits can inject a new CH section into the root final output while readiness remains green.

**Why this matters**

The bytes used to publish semantic findings are not the bytes committed by the producer.

**Required repair**

Preferred: finalization reads the exact committed MODEL transcript path and verifies its PhaseIO receipt and digest.

If an archive is operationally necessary, it must have a DRIVER-owned copy receipt that binds source path/digest, destination path/digest, and byte equality. The archive still should not become a separate semantic source.

**Required red-to-green fixtures**

1. Tamper archive after commit: final rejects or ignores it and uses committed transcript.
2. Delete archive while transcript remains: no semantic loss.
3. Tamper committed transcript: producer digest validation rejects.
4. Cross-shard archive substitution: rejects.

---

### B12. Primary ChainAgent2 coverage reaches final authority without a PhaseIO producer

**Observed failure**

A raw primary coverage table can be ingested, marked complete, and used in the final transaction without a corresponding artifact-ledger/PhaseIO producer. In the reproduced case the only final artifact-ledger producer was `tail_reconcile`.

**Why this matters**

Part of the final semantic denominator has stricter authority than another part. The less-protected primary source can be modified or directly injected.

**Required repair**

Give primary reconciliation its own pre-armed DRIVER PhaseIO transaction. It must:

- validate the exact `ACTIVE`/`OUTPUT_COMMITTED` ChainAgent2 MODEL predecessor or other explicitly authorized producer;
- bind current source bytes/digests, run, launch receipt, and input identities;
- emit an immutable primary terminal receipt/snapshot fragment;
- be consumed by the frozen final snapshot;
- treat mutable primary ledger/control state as a parity projection only.

**Required red-to-green fixtures**

1. Direct raw primary ingestion without producer: reject.
2. Source changed after producer commit: reject.
3. Producer from another run/backend: reject.
4. Exact committed source and primary DRIVER receipt: accepted.

---

### B13. Generic retry quarantine can destroy a committed MODEL transcript

**Observed failure**

If disposition arming fails after the MODEL unit has already reached `OUTPUT_COMMITTED`, generic retry quarantine moves the nested transcript into a flat quarantine path. The committed transcript disappears. The retry path has no authority to rerun the model, and generic restore would restore the basename to the wrong directory.

**Why this matters**

Retry destroys the strongest available evidence and can strand or duplicate work. It also violates “MODEL before DRIVER” by treating a committed MODEL output as stale merely because a later stage failed.

**Required repair**

Use PhaseIO-aware recovery:

- if MODEL is committed, never rerun, quarantine, rewrite, or relocate its transcript; resume the DRIVER disposition/failure transaction;
- if MODEL is armed but uncommitted, retry only the exact pre-bound unit;
- exclude isolated transactional artifacts from generic quarantine;
- if quarantine remains for unrelated artifacts, preserve exact relative path, origin, digest, authority state, and restoration location.

**Required red-to-green fixtures**

1. Force disposition-arm failure after MODEL commit: transcript path/hash unchanged; retry resumes disposition.
2. Restart after the same failure: no second MODEL invocation.
3. Uncommitted MODEL retry uses the same contract/input set.
4. Nested quarantine restore, if used elsewhere, restores the exact relative path.

---

### B14. Orphan chain hypotheses silently disappear from typed candidate delivery

**Observed failure**

Aggregation includes every parsed CH section from shard output. `_write_composition_candidates`, however, emits only chain IDs referenced by `COMPOSED` pair rows. A model-emitted CH section not linked by a pair row is present in `chain_hypotheses.md` but absent from the authoritative candidate sidecar. The typed compound adapter treats the sidecar as authoritative.

**Why this matters**

This is a direct found-then-dropped recall failure. Whether the extra section is valid, malformed, or hallucinated is a discriminator question; silently omitting it is not a valid disposition.

**Required repair**

Reconcile exact sets:

- every accepted CH section identity must be referenced by one or more typed pair rows; and
- every `COMPOSED` row must resolve to exactly one accepted CH section in its committed transcript.

An unlinked CH becomes a typed unresolved proposal/debt item routed to ordinary verification or flagged human review. It must never disappear. When multiple pair rows legitimately reference one CH, emit one candidate with unioned pair/constituent lineage, or emit explicit visible ambiguity debt; do not create a duplicate-ID dead end.

**Required red-to-green fixtures**

1. Valid terminal pair plus an unlinked `CH-777`: final cannot be `COMPLETE` with an empty candidate sidecar; CH is routed or debt.
2. `COMPOSED` row with no section: explicit debt.
3. One section referenced by two pair rows: deterministic single candidate with full lineage or explicit visible debt.
4. Section identity reused divergently: explicit ambiguity debt, no guessed mapping.

---

### B15. `final_publication.armed` is a permanent root-write capability

**Observed failure**

After final publication, the marker remains present. Control helpers such as re-arm write root ledger, receipt, projection, and candidate outputs whenever that marker exists. A reproduced post-final re-arm changed the committed root ledger hash outside PhaseIO, created a new active shard, and left `validate_chain_tail_authority()` green.

**Why this matters**

Final authority is not stable after commit. A historical “armed” marker grants future scheduler operations permission to mutate published semantic bytes without a new contract.

**Required repair**

Make final publication generation-scoped:

1. New generation is prepared with exact predecessor snapshot and expected output set.
2. Generation enters `ARMED`.
3. Exact outputs commit through PhaseIO.
4. Generation enters `COMMITTED`; the armed capability is consumed.
5. Subsequent scheduling/re-arm mutates control-only state.
6. A later publication requires a new generation, new pre-arm, new snapshot, and new output receipts.

Root compatibility outputs must change exclusively inside that transaction.

**Required red-to-green fixtures**

1. Complete final publication; re-arm unresolved work: every root output hash and prior `tail_reconcile` receipt remains unchanged.
2. Validator detects root mutation not backed by a new committed generation.
3. New final generation publishes changed bytes only after pre-arm and commit.
4. Crash before/after marker transitions recovers deterministically.

---

### B16. The broader acceptance cluster contains four red integration tests

**Observed failure**

The added broader cluster completed with `141 passed, 4 failed`. All failures were in `scripts/test_compound_adapter_runtime_p0_af.py`:

- two queue-routing denominator tests expected success but invoked typed routing without pre-arming outputs and received `typed verify-queue routing outputs were not armed before generation`;
- two missing-compound-artifact tests expected a required-output debt, but the earlier not-armed error masked that assertion.

**Why this matters**

The production fail-closed behavior appears directionally correct, but the acceptance evidence is internally inconsistent. A security checkpoint cannot be called green while integration tests encode an obsolete lifecycle.

**Required repair**

Do not weaken or bypass pre-arm. Update the integration fixture to:

1. create the exact routing contract;
2. pre-arm the complete expected output set;
3. generate/seed outputs through the authorized fixture path;
4. record typed routing;
5. then remove one compound artifact for the missing-output cases.

The missing-output tests must prove both that pre-arm succeeded and that exact terminal set validation reports the intended missing artifact.

**Required acceptance fixture**

The same cluster must be `145 passed, 0 failed`, with no xfail or skip added to suppress these cases.

## 4. Nonblocking hardening and next-program items

These do not replace the blockers and should not be smuggled into the repair without explicit ownership. They should remain recorded.

### N1. Bind state-symbol compatibility reads to immutable authority

`state_symbol_authority.validate_chain_state_resolution` reads the root compatibility ledger to compare state/type denominator counts. It does not currently grant chain disposition authority, so this was not elevated to the frozen checkpoint blocker roster. It should eventually read the immutable manifest/snapshot, or treat missing/invalid compatibility state as explicit debt.

### N2. Disable permissive compound fallback under isolation

The compound adapter can fall back to root `chain_hypotheses.md` when the typed candidate sidecar is absent. That may preserve historical primary candidates, but under an isolation-era run it can bypass typed validation. Isolation markers should force a typed-source requirement or explicit debt.

### N3. Add independent discrimination for negative pair dispositions

`EXPLORED` and `REJECTED` are currently largely producer-authored conclusions supported by nonblank evidence. This recreates the user's measured “agent found it, then wrongly called it safe” failure class. Extend negative-closure authority to chain pairs:

- independent skeptic/discriminator for high-risk negatives;
- deterministic evidence requirements by claim type;
- stratified sampling of remaining negatives;
- unresolved/debt when the negative premise is not proven;
- no automatic severity inflation.

This is a recall program item rather than a narrow PhaseIO repair, but it is high leverage.

### N4. Normalize shared-chain lineage

If several pair rows refer to the same valid CH section, downstream compilation currently risks duplicate `chain_id` issues and no work. Prefer one canonical candidate with the union of pair IDs and constituent lineage. If equivalence is uncertain, emit visible ambiguity debt rather than guessing.

### N5. Preserve the prior committed presentation until replacement commits

Final preparation currently deletes root compatibility outputs before the new final contract has successfully armed and committed. This is recall-safe only because control state remains, but it creates avoidable presentation loss on an arm failure. Prefer build/freeze/arm first, then atomic replacement, while retaining the prior committed generation for recovery.

## 5. Evidence lanes

### 5.1 Static evidence

- Python compilation succeeded for:
  - `scripts/chain_tail_authority.py`
  - `scripts/phase_io_contracts.py`
  - `scripts/plamen_driver.py`
  - `scripts/test_chain_tail_isolated_phase_io_p0_t.py`
- Search for `_record_chain_tail_authority_phase_io(` found:
  - the function definition;
  - two old test calls;
  - no production caller.
- The reviewed isolated tests include distinct transcript paths for successive shards and a Claude hook test that grants only the unique shard transcript.
- The final publication marker is consulted as a general condition for writing root ledger, receipt/projection, and candidate sidecar, which supports B15.

### 5.2 Green lanes reported or independently observed

| Lane | Result | Interpretation |
|---|---:|---|
| Implementer focused lane | 95 passed | Useful local evidence, not a full authority proof. |
| Implementer broader lane | 193 passed | Useful blast-radius evidence. |
| Implementer authority lane | 354 passed | Stronger regression evidence, but missed adversarial state transitions in B1–B15. |
| Independent initial lane | 8 passed | Initial handshake only. |
| Independent selected chain/PhaseIO lane | 163 passed | Selected integration behavior green. |
| Added compiler/controller/compound lane | 141 passed, 4 failed | Acceptance blocker B16. |

Passing test counts are not additive because suites may overlap.

### 5.3 Adversarial repro classes used in the review

- mutate-and-rehash a copied input;
- nested lock contention;
- delete or alter a non-authoritative journal;
- inject failure between semantic mutation and receipt commit;
- finalize a transcript-less failure;
- mutate-and-rehash mutable control state;
- delete the isolation marker used for mode selection;
- directly create a terminal receipt without its producer;
- fail the initial model path and continuation callback;
- seed a stale shared root delta;
- tamper an archive not bound into the final contract;
- ingest primary coverage without a producer;
- fail disposition after MODEL commit and observe generic quarantine;
- emit an unlinked CH section;
- re-arm after final commit and compare root hashes;
- run the broader typed compound integration slice.

These are generic process/authority tests. They contain no target-specific exploit logic.

## 6. Repair sequencing recommendation

The blockers are coupled. Implementing them as sixteen unrelated patches would create more state drift. Recommended order:

### Stage A — canonical records and strict loading

1. Fix B1 strict work-unit binding.
2. Fix B2 lock ownership.
3. Define canonical shard/work denominator independent of the journal (B3).
4. Define immutable producer/terminal record schemas needed by B8 and B12.

### Stage B — recoverable per-shard transaction

1. Implement the state machine for B4.
2. Route success, failure, initial execution, and continuation through it (B5, B8, B9).
3. Make retry PhaseIO-aware and remove generic quarantine authority over committed transcripts (B13).
4. Add failpoints before proceeding.

### Stage C — immutable terminal snapshot

1. Add the primary reconciliation producer (B12).
2. Reconstruct exact terminal set from committed receipts (B3, B8).
3. Consume committed transcript bytes rather than archives (B11).
4. Reconcile chain-section identities and candidate delivery (B14).
5. Freeze the terminal semantic snapshot (B6).

### Stage D — final publication and compatibility

1. Make legacy eligibility explicit and sticky isolation debt (B7).
2. Make final publication generation-scoped and consumptive (B15).
3. Require the committed `tail_reconcile` parent for `driver_merge` (B10).
4. Preserve the prior committed generation until replacement.

### Stage E — integration closure

1. Correct the typed-routing fixture lifecycle without weakening pre-arm (B16).
2. Run focused red-to-green fixtures.
3. Run the complete failpoint matrix.
4. Run broad authority, driver, compound-delivery, Claude-boundary, and ecosystem-neutral lanes.
5. Refreeze before independent review.

## 7. Second-review acceptance boundary

The next review begins only after the implementer sends an exact `TREE_QUIESCENT` declaration containing:

- new `HEAD`;
- complete relevant `git status`;
- file sizes, last-write UTC values, and SHA-256 hashes for every changed authority/driver/test file;
- a blocker-by-blocker disposition table for B1–B16;
- red-to-green fixture names and results;
- the full crash/failpoint matrix and results;
- broad test commands and unabridged pass/fail summaries;
- confirmation that no test was skipped, xfailed, deleted, or weakened to obtain green;
- confirmation that no production call to the obsolete post-hoc authority recorder was introduced;
- confirmation that no root compatibility file is read as authority before committed final publication;
- confirmation that the implementer stops editing after the declaration.

### 7.1 Mandatory second-review probes

The independent reviewer will, at minimum:

1. rerun the strict input-tamper matrix;
2. rerun three-party lock contention;
3. delete/corrupt journal and isolation markers;
4. inject crashes at each shard transaction boundary;
5. test initial and continuation failure terminalization;
6. mutate control ledger, transcript, archive, and root compatibility bytes independently;
7. create missing, duplicate, cross-run, and direct terminal receipts;
8. test primary coverage without and with its exact producer;
9. test stale root merge without `tail_reconcile`;
10. test post-final re-arm root-hash immutability;
11. test orphan and shared CH identity routing;
12. test two or more Claude shards for unique transcript/output authorization;
13. rerun the previously green authority lanes and the exact previously red 145-test lane.

### 7.2 Acceptance rule

The checkpoint is accepted only if:

- all sixteen blockers have executable regression fixtures;
- every mandatory probe is green;
- failures degrade to explicit durable debt without halting unrelated work;
- no repair restores a Markdown/root artifact as semantic authority;
- exact producer/predecessor lineage holds for every final semantic input;
- the root publication is immutable between committed generations;
- all broad lanes are green; and
- the second reviewer finds no new blocking authority or recall-loss path.

Test counts alone are not acceptance. The semantic invariants above are the acceptance criteria.

## 8. Final verdict

The current checkpoint demonstrates a credible direction but not a complete commit-authority design. The highest-risk remaining failures are precisely the pipeline's empirically dominant failure mode: a result is generated, but a later lifecycle transition can omit it, overwrite its evidence, accept an unauthorized substitute, or leave it stranded without a terminal receipt.

The implementation is worth repairing. The changes should not be discarded or replaced with a looser Markdown workflow. The correct next move is the coherent authority redesign described here, implemented behind red-to-green fixtures and crash recovery tests. Once that is complete, independent checkpoint review should focus on exact lineage, immutable publication, and recall preservation before any end-to-end audit benchmark is allowed to treat the driver as ready.
