# Plamen V3 Reliability and E2E Qualification Plan

Status: active implementation plan, 2026-09-16

## Objective

An audit is reliable only when the public driver reaches the correct terminal
state under the declared fault envelope. Reliability is separate from recall:
this plan freezes the existing discovery denominator and proves orchestration,
durability, recovery, and terminal classification before coverage is measured.

`COMPLETE` means all required phase commits and the final acceptance receipt
exist, every committed artifact replays from its recorded preimage, verification
preceded report publication, and no terminal debt remains. A clean process exit
or the presence of `AUDIT_REPORT.md` is not completion authority.

## Engineering method

Use a state-machine-first, failure-model-driven program:

1. Specify each transition, durable precondition, postcondition, retry class,
   and recovery action before changing implementation.
2. Reproduce a failure with an exact retained fixture or deterministic fault.
3. Repair the smallest shared invariant, not the individual run directory.
4. Prove the repair at component, composed-transition, crash/resume, package,
   and public-launch boundaries.
5. Freeze one package generation and run fresh DODO canaries. Never repair or
   rewrite an incompatible historical audit in place.

The implementation remains aligned with the existing Plamen decision to use
typed immutable JSON, PhaseIO, content-addressed artifacts, and exact
reconciliation. This plan does not introduce SQLite or a second state authority.

## Reliability invariants

- One persisted immutable attempt plan owns a worker's input set, contract
  digest, output manifest, semantic denominator, backend, and attempt identity.
  Launch, record, commit, and downstream admission reuse that plan.
- A phase becomes complete only through one typed durable phase commit.
  Sentinels, filenames, and mutable checkpoint lists are projections.
- Every provider/process result has one closed typed outcome. Timeout,
  throttling, provider refusal, malformed output, invariant failure,
  cancellation, and environment failure are not interchangeable return codes.
- The driver is the sole retry owner. Ambiguous completion reconciles retained
  output before retry. Repeated deterministic fingerprints terminate without
  spending another model call.
- Attempts are fenced by run, work unit, generation, and invocation identity.
  A late or orphaned attempt cannot publish canonical output.
- Parallel fan-out commits valid children independently and retries only missing
  children. The phase barrier commits after exact roster reconciliation.
- The audit graph is frozen per epoch. Dynamic additions create a new persisted
  epoch; resume never silently interprets a different graph.
- A single OS-held writer lease is acquired before state reads that can lead to
  mutation. Durable publication uses staged bytes, file flush, atomic replace,
  directory flush, and replayable commit metadata.
- Inactive analysis experiments may emit diagnostics but cannot create terminal
  debt until a real consumer activation record makes them part of the recall
  denominator.
- Reliability changes must preserve the frozen coverage vector: graph IDs,
  obligation IDs, gap matrix, promoted candidate IDs, and candidate lifecycle.
- Artifact selection and artifact authentication are separate capabilities.
  Phase manifests and publisher-specific registry projections select actions;
  `canonical_identity` authenticates an already-selected artifact/local-ID
  pair. A parser or aggregate may not reuse a publication capability as an
  identity oracle.
- Every source action has exactly one inventory mutation owner. Recon-prepass
  IFACE/PSET actions publish in the manifest-bound canonical inventory
  transaction; depth-owned `niche_*` actions publish through the specialized
  post-depth lifecycle. Filename overlap cannot grant both paths authority.

## Typed outcome and retry policy

| Outcome | Examples | Driver action |
|---|---|---|
| `SUCCEEDED` | validated output and committed postimage | commit once |
| `TRANSIENT_DEPENDENCY` | 429, retryable 5xx, connection reset | bounded jittered retry |
| `PROCESS_LOST` | crash, signal, stale heartbeat | fence, reap tree, retry within budget |
| `AMBIGUOUS_COMPLETION` | deadline after possible output | reconcile attempt, then decide |
| `PROVIDER_REFUSAL` | explicit policy refusal | terminal; no prompt-shape retry |
| `OUTPUT_CONTRACT` | missing, truncated, malformed output | one bounded repair policy |
| `ENVIRONMENT` | missing executable, auth, ENOSPC, read-only path | fail fast unless corrective action exists |
| `INVARIANT_OR_CONFIG` | graph drift, impossible transition, schema mismatch | terminal diagnostic |
| `CANCELLED_OR_BUDGET` | operator stop or exhausted budget | terminal cancellation |

Retry budgets are per operation and per run. A retry preserves the logical
idempotency key when the request is identical; reusing a key for changed request
bytes is a contract failure.

## Qualification ladder

### Gate 1: source closure

- Runtime closure renders from the exact reviewed tree.
- Runtime imports succeed under isolated CPython 3.12.
- Full pytest collection succeeds with an exact public/private denominator.
- The composed historical regression pack passes serially.

> **Gate 1 must run against a FROZEN checkout, and this is not optional.**
> `toolchain_control_authority` derives the runtime closure at IMPORT time and
> calls `path_index.verify_unchanged()`; any write under `scripts/` while that
> scan runs raises `runtime path index changed during derivation` and aborts
> collection for the whole invocation. A measurement taken against a writable
> tree is therefore meaningless, and silently so: the same command over the
> same 48 files produced **126 failed / 389 passed** on a live tree being
> edited versus **20 failed / 495 passed** on a byte-frozen snapshot of that
> same tree — roughly 106 phantom failures from tree mutation alone. Those
> phantoms are easy to misread as order-dependent tests; in the observed case
> they were not, and chasing them cost real time. Snapshot the tree (rsync to
> a scratch path), run the pack there, and cite the snapshot digest with any
> pass/fail count.

### Gate 2: deterministic failure matrix

Inject a crash at every durable boundary: before and after attempt publication,
provider return, output write, validation, promotion, phase commit, dependent
scheduling, fan-out barrier, verification, and report publication.

For every cell assert byte-identical convergence with an uninterrupted run,
no rerun of committed work, no accepted stale result, no false completion, and
no orphan process. Include duplicate completions, late results, malformed and
oversized output, ignored termination, disk/resource failures, 429/5xx/timeout,
concurrent driver start, Ctrl-C, and sleep/wake where the host permits.

### Gate 3: packaged hermetic audit

- Install one immutable compatibility generation through its supported
  transaction; never copy source into the installed tree.
- Run a deterministic provider emulator through the public launcher across the
  complete smart-contract phase graph.
- Interrupt and resume at generated phase boundaries.
- Verify the final acceptance receipt and package generation binding.

### Gate 4: DODO canary

- Use a fresh DODO destination and one frozen installed generation.
- Run at least three consecutive clean Codex audits plus explicit interruption
  and resume canaries without changing source or package bytes.
- Preserve every failed run. A repair produces a new generation and a new DODO
  destination; it never rewrites old evidence.
- After correctness stabilizes, execute at least 100 seeded deterministic DODO
  runs spanning clean, transient, crash/resume, malformed-output, and resource
  failure scenarios.

## Release acceptance

- 100% correct terminal classification.
- 100% automatic recovery for failures declared retryable.
- Zero false phase completions or reports published before verification.
- Zero corrupt canonical artifacts or accepted stale attempts.
- Zero reruns of already committed work.
- Zero live descendant processes after shutdown or timeout.
- Every failure has a bounded, replayable event/receipt trail identifying the
  failed invariant and next safe action.
- The frozen recall vector has no removals; additions require explicit review.

## Current execution order

1. Preserve runs 23 and 24 as forensic evidence. Neither may consume a changed
   snapshot or be rewritten in place.
2. Finish the run24 repair qualification: conditional-absence replay,
   registered-action delivery, final confidence sealing, typed application
   planning debt, parser identity, and the late severity compatibility path.
3. Regenerate the runtime closure and prove the focused/composed regression,
   public archive, isolated import, install, and doctor boundaries.
4. Install one immutable generation and launch DODO run25 from pinned commit
   `d4834a468f7dad56b007b4450397289d4f767757` through the public Codex
   compatibility launcher.
5. Babysit run25 without source/package mutation. A failure freezes run25,
   records the first causal transition, repairs the shared invariant, and uses
   a new generation plus a new destination.
6. After the first clean terminal receipt, run two more byte-identical DODO
   canaries plus interruption/resume qualification before recall measurement.

## Qualification status -- 2026-09-16

- Run23 exposed capability confusion between canonical identity authentication
  and publisher selection. The composed inventory path is repaired and
  regression-covered.
- Run24 crossed that boundary and exposed two independent defects: historical
  replay rejected valid absent conditional enumgap outputs, then semantic
  publication omitted registered actions based on confidence/debt metadata.
  Both are repaired at shared authorities; run24 remains frozen.
- Confidence consensus is now sealed only after final input-driven projection;
  every provisional generation has PhaseIO ownership.
- Application-skeptic planning debt is a validated typed alternative to a
  success work plan, not a size-only escape hatch.
- Focused delivery, depth, Axis, candidate-debt, package, and public-archive
  suites pass. The repository-wide historical baseline remains non-green and
  is tracked separately from this release gate.
- The late Codex severity E2E fixture now keeps provider-owned runtime state
  outside the audited target, matching production custody. Its remaining
  assertion was corrected to distinguish terminal `COMPLETED_UNRESOLVED`
  business results from missing or uncommitted work.
- Runtime-closure derivation ignores interpreter-owned `__pycache__` churn but
  still rejects changes to governed source/runtime entries, removing a
  first-import qualification race without weakening the reviewed denominator.

## Research basis

- Temporal event history and deterministic replay:
  <https://github.com/temporalio/temporal/blob/main/docs/architecture/history-service.md>
- AWS idempotent API and retry guidance:
  <https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/>
- AWS timeout, retry, backoff, and jitter guidance:
  <https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/>
- Python subprocess lifecycle and timeout semantics:
  <https://docs.python.org/3/library/subprocess.html>
- Erlang/OTP bounded supervisor restart principles:
  <https://www.erlang.org/doc/system/sup_princ.html>
- AWS failure-injection guidance:
  <https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_testing_resiliency_failure_injection_resiliency.html>
- FoundationDB deterministic simulation and real-boundary testing:
  <https://sigmodrecord.org/publications/sigmodRecord/2203/pdfs/08_fdb-zhou.pdf>
- POSIX atomic rename semantics:
  <https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html>
- Linux file and directory durability semantics:
  <https://man7.org/linux/man-pages/man2/fsync.2.html>
- Persist-generation-before-effect, the canonical form of the fencing fix:
  GFS SOSP 2003 section 4.5 (chunk version number recorded in persistent
  state "before any client is notified and therefore before it can start
  writing") <https://www.cs.cornell.edu/courses/cs614/2004sp/papers/gfs.pdf>;
  Raft figure 2 ("updated on stable storage before responding to RPCs")
  <https://raft.github.io/raft.pdf>; Paxos Made Simple section 2.5
  <https://lamport.azurewebsites.net/pubs/paxos-simple.pdf>; HDFS QJM
  (HDFS-3077) section 2.3, epoch "written durably (fsynced)" before any edit;
  Kafka KIP-98 producer-epoch fencing.
- Resource-side token validation (the half of fencing that provides safety):
  <https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html>
- Crash-injection bounded to persistence points:
  CrashMonkey/ACE, OSDI 2018
  <https://www.usenix.org/system/files/osdi18-mohan.pdf>
- Order-dependent test taxonomy (victim/polluter vs brittle/state-setter):
  iFixFlakies, ESEC/FSE 2019
  <https://taoxie.cs.illinois.edu/publications/esecfse19-ifixflakies.pdf>

### Corrections to earlier citations in this file

An external review found three citation errors that were propagating into
design discussion. They are recorded here rather than silently edited:

- **RFC 9239 is NOT about rate limiting.** It is "Updates to ECMAScript Media
  Types" (May 2022) and registers `text/javascript`. It must not be cited as
  rate-limit guidance.
- `Retry-After` is **RFC 9110 section 10.2.3**, and its ABNF is
  `HTTP-date / delay-seconds` — BOTH forms are legal. A delay-seconds-only
  parser is non-conformant, and is precisely the parser that mishandles a
  far-future reset, since the HTTP-date form is how a provider expresses
  "next month".
- The RateLimit header fields work is **draft-ietf-httpapi-ratelimit-headers**,
  still an Internet-Draft (rev -11, 2026-05-23, HTTPDIR early review "Not
  ready") — it is not an RFC, and the current design uses RFC 9651 structured
  fields `RateLimit` and `RateLimit-Policy`, not the older field names.
- There is no standards-track HTTP idempotency key:
  draft-ietf-httpapi-idempotency-key-header expired in October 2025.

## Open architecture debt from the research review

These items are not run24 root causes and must not be mixed into its repair.
They are required before claiming the complete fault envelope rather than a
clean DODO canary:

1. Define an append-only, ordered/hash-chained transition history and replay
   algorithm. Current phase/checkpoint maps are state projections, not a
   replay-complete event history.
2. Version the whole replay contract: executable closure, phase graph,
   schemas, validators, runtime, and provider protocol. Retained histories must
   be replay-tested before a generation is installed.
3. Specify one stable logical idempotency key plus immutable intent digest,
   separately from fresh attempt/fencing identity. Persist retention and
   same-key/different-intent behavior.
4. Persist numeric retry/deadline budgets, `Retry-After`, retry-owner inventory,
   and deterministic jitter seed. Nested provider/SDK retries must be disabled
   or charged to the same budget.
5. Replace checkpoint `write_text`/`replace` publication with the exact durable
   sequence: intent, staged bytes, file flush/fsync, same-directory atomic
   replace, directory fsync, committed receipt. Define one multi-artifact
   visibility/linearization rule and a recovery action for every prefix.
6. Replace the stale-PID run lock with an OS-held lease and monotonic writer
   epoch. Every mutation-capable read and commit CAS must reject a former
   owner, including a late child that outlives its coordinator.
7. Specify cancellation as a durable transition: fence admission, graceful
   process-group/job termination, bounded wait, hard kill, drain/wait, and an
   explicit descendant-extinction proof before publishing the outcome.
8. Define a fault-campaign manifest containing seed, deterministic schedule,
   package/graph/oracle versions, normalization rules for approved time/UUID
   fields, replay command, coverage metric, shrink policy, blast radius, and
   stop conditions. Simulation must be paired with real OS/filesystem/provider
   canaries.
