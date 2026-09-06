# Plamen — Claude Blocking-Review Verdict (Release-0 + R10.1 + Neutral Evaluator)

**Date:** 2026-07-16
**Reviewer:** Claude (independent, non-implementing model — authored the R10 baseline + the implementation spec; did NOT implement the code under review)
**Role:** blocking diff review + blinded adjudicator, per the operating agreement in `Plamen_Claude-to-Codex_Implementation_Handoff_2026-07-15.md`
**Method:** grounded in the actual diffs + fixture-first revert-testing in isolated git worktrees (not the implementer's self-report), via a 4-area adversarial review; every load-bearing finding independently re-verified by the reviewer.

## Pinned versions reviewed (so later edits cannot be mistaken for the reviewed state)

| Artifact | Identity |
|---|---|
| Production impl repo | `plamen-codex-implementation` @ `codex/recall-app-benchmark-r10_1` head **`67a0f85adc7a8169d79a286908b00bef7adb764a`** (9 commits over R10 baseline `9ca8861`) |
| Neutral evaluator repo | `<PRIVATE_EVALUATOR_REPO>` @ `main` head **`345d016d0c86b6201e90cec908c37c6a66f739c3`** (separate repo) |
| Codex review handoff | SHA-256 `664def020d68fd26703a7997f0aad5c684dfc7cf0727e4bb15d78458a74fee7f` |
| B0 dry-run receipt | SHA-256 `af4ee07bc0fd89e6ec28c2343e267006483b0638ab2b01f48f99c7032d6ebe98` |
| Claude spec (governing) | SHA-256 `e69831fc4735254ad4cc41a06639a124fc1261b31447a581b5ed7b288794c5ea` (matches Codex handoff §2) |

## Verdict: **APPROVE for cutover** — nothing blocks; 3 tracked non-blocking concerns; 1 reviewer overcall corrected

Cutover (merge/push) remains the **user's** call as human acceptance gate. Nothing was pushed by this review.

### Per-area
| Area | Verdict | Fixture-first evidence (pre-fix red, verified by reverting the real impl) |
|---|---|---|
| **R10.1** (defects 8/5/7) | **PASS** | defect-8 positive: 1 red; defect-5 internal-stability negative: 2 red; defect-7: correct no-op (G3 preserved); R10 baseline 15/15 green. 155 LOC narrow predicates, Part-0 clean, no smuggled architecture. |
| **R0-2 + R10 id-join** | **PASS** | id-join **survives table-scoping** under the private regression fixture; the exact private finding and inventory IDs remain outside Git; regression fixture red pre-fix (`KeyError`). The false-merge and split-loss classes are fixed. |
| **Neutral evaluator** | **PASS** | separate repo, zero Plamen imports, `isolation.py` rejects same-user-out-of-tree + requires signed `rag_disabled` probe; <PRIVATE_REGRESSION_TARGET> regression-only (never scored); grader deterministic (receipt hash regenerated from scratch); per-stage metrics + earliest-failure localizer; B0 receipt schema airtight (`synthetic:true`, `B0_TEST_ONLY`, `NO_COMPARATIVE_CLAIM`); Part-0 zero. |
| **Release-0 remainder** | **PASS** | every load-bearing fix red→green verified (breadth kernel 8-red, PoC label 5-red, recon owner 2-red, loud caps 26-red, graph self-check 21-red, honest receipts 17-red, snapshot mutation 21-red). |

### Concerns to track (non-blocking)
1. **`audit_snapshot.py` (1396 LOC)** bundles §11-deferred operational hardening (remote-doc materialization, a **15s exclusive startup lock**, scratchpad archival) around the in-spec R0-8c/d digest core. Not smuggled *recall* architecture (no ledger; doesn't touch discovery/dedup/severity), but significant new **startup-time surface** on a hang-averse pipeline. Confirm cheap-on-warm + **fail-open** (never blocks a run); consider splitting ops-hardening from the digest. *(Independently confirmed by the reviewer.)*
2. **Eval B1 label leak:** intermediate `campaign_analysis`/`experiment_analysis` docs hardcode `B1_PUBLISHABLE` + synthetic comparator deltas during B0. Not in the shared receipt (hash-referenced, need synthetic keys) so the deliverable can't overclaim — stamp them `synthetic` or downgrade the tier so a standalone reader can't misread.
3. **<PRIVATE_REGRESSION_TARGET> fire-set is codex-claim-only** (temp copy, not reproducible from repo/bench). Correct as *regression evidence, not a scored gate*; commit a synthetic <PRIVATE_REGRESSION_TARGET>-shaped replay fixture if durable teeth are wanted.

### Reviewer overcall corrected (transparency)
A sub-reviewer flagged commit `6dfe5f2` as smuggling a recall-*narrowing* axis change (`_axis_examined_secondary`, GAP→EXAMINED from prose cues). **Refuted on independent verification:** that function is **pre-existing baseline code** (introduced v2.2.2 `b3aefae`, ancestor of `9ca8861`); no R0-branch commit touches it (`git log -S` over `9ca8861..67a0f85` is empty). `6dfe5f2`'s real `enumeration_gate` change is the recall-**safe** R0-7 word-boundary tightening + a docstring sync. **No action needed.** (Recorded to model no-self-certification at every level — even the reviewer's own agents' findings are grounded before relay.)

### Adjudication owed — the exploratory 8th-scratchpad R10.1 candidate
**Deferred; does not gate cutover.** Honestly disclosed as exploratory (not a release metric). Cannot be fairly adjudicated now — the temp scratchpad is gone, so the artifacts to judge true-under-demotion vs correct-non-fire are unavailable. If reproduced into a committed synthetic fixture, I will rule.

## The real gate (unchanged)
The **code is cutover-ready**; the **program** is blocked at the **external B1 boundary** — independently-governed held-out corpus, secure launcher with denial probes, separated authorities, pinned Pashov V3 adapter, real treatment artifacts. This is an external-evidence prerequisite, **not** a code defect. **No comparative / recall / precision / superiority claim can be made from synthetic B0.** Neither model should synthesize this boundary. The honest next step is external B1 enablement, not more code.

---
*This artifact records the review disposition only. It does not authorize a push, a merge, or a published result.*
