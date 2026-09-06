# Plamen P0-AM Worker Lifecycle Forensic

Date: 2026-07-24  
Status: blocker specification; not implemented or accepted  
Scope: Claude PTY, Claude headless, Codex, verifier/repair workers, native tools

## 1. Verdict

P0-AM is a release blocker. The current build cannot prove that no model or
descendant writes after a phase is recorded or committed.

Safe synthetic reproductions:

- A headless root returned success after approximately 0.077 seconds; a detached
  child wrote into the run directory approximately 1.5 seconds later.
- `_NonBlockingWorkerPool` returned after approximately 0.053 seconds while its
  future was still running; the future wrote approximately 1.25 seconds later.

The new Worker Execution Receipt (WER) module is a useful substrate, but it is
not production-integrated. Its PTY seam is documentation-only.

## 2. Production paths

| Path | Consumers | Current boundary | Defect |
|---|---|---|---|
| Generic Claude PTY | Inventory, invariants, skeptics, chain, verification, report | Transcript/disk/root exit, then best-effort termination | Tree closure not proven |
| Generic Claude headless | Headless Claude phases | Root exit | Descendants may outlive root |
| Generic Codex exec | Generic Codex, breadth/depth, repair | Root exit | Same detached-child risk |
| Recon PTY leaf | Recon/dependency waves | Transcript | PhaseIO recorded before termination |
| Breadth PTY leaf | Breadth pool | Transcript or disk-idle | Can commit while PTY is alive |
| Rescan PTY leaf | Rescan pool | Transcript | PhaseIO recorded before termination |
| Depth PTY leaf | Depth pool | Transcript | Fuzz finalization/PhaseIO before termination |
| Dynamic verifier | Verify/recovery | Transcript/root exit | Verifier/severity/PhaseIO receipts can be minted without closure |
| Missing-only PTY recovery | Failed disk gate | Old root liveness | Descendants invisible; canonical names reused |
| Recon native subprocess | Static/build recon | Root exit | Normal-exit descendants unowned |
| Fuzz secure launcher | Fuzz tools | Windows Job Object | Strongest existing implementation |

Retired raw launchers must be proven unreachable and removed or wrapped.

## 3. Confirmed blockers

1. Production does not call the WER execution provider.
2. PTY paths validate and record PhaseIO before owned-scope termination.
3. Pool cancellation deliberately uses `shutdown(wait=False)`.
4. PTY sessions unregister before termination, creating a cancellation blind
   window.
5. Workers in a pool share write authority over multiple outputs.
6. Retries reuse canonical filenames without attempt-specific staging/CAS.
7. Model-owned children are not represented by a driver WorkPlan.
8. Parent phase commit cannot see a required child whose receipt is missing.
9. PhaseIO does not bind prompt/argv/executable/environment/process/attempt/tree
   closure/transcript/incorporation.
10. POSIX process-group termination cannot prove exhaustive descendant closure;
    a child can escape with a new session.
11. WER multi-output publication lacks crash roll-forward/rollback.
12. WER process ownership does not alone restrict filesystem authority.
13. WER `assessors` are names rather than linked assessor executions.
14. Job cleanup can fail after completion/publication is persisted.

## 4. Required unified boundary

Every model/tool worker uses one typed `WorkerTransaction`:

```text
immutable WorkPlan
  -> attempt arm
  -> provider-owned process and write scope
  -> launch
  -> join or terminate complete scope
  -> prove closure
  -> parse exact staged output
  -> immutable CAS object + execution completion/debt
  -> PhaseIO incorporation receipt
  -> driver-only aggregation
  -> phase commit after exact WorkPlan parity
```

The worker never receives a canonical output path. It writes only inside a
unique attempt staging directory. The provider captures immutable bytes; the
driver alone projects canonical Markdown.

Haltless behavior remains recall-safe: untrusted/quarantined bytes may be
retained as proposal material, but cannot satisfy a mandatory work denominator
or authorize a negative.

## 5. WorkPlan

Canonical JSON rows bind:

- logical work-unit ID, generation, and stable retry identity;
- exact source/input snapshot;
- exact instantiated prompt and methodology/tool-policy digests;
- backend, model, transport, argv, executable, environment allowlist, timeout,
  and capacity class;
- exactly one owned output assignment, parser/schema, and canonical projection;
- dependency denominator and aggregation predicate;
- retry/reuse policy;
- terminal debt behavior.

A retry can reuse a prior completion only when every binding matches. If one of
six workers is missing, the new plan reuses five exact completions and schedules
one attempt.

## 6. OS authority

### Windows

Consolidate WER and the fuzz Job Object path:

1. spawn suspended;
2. assign to a Job with `KILL_ON_JOB_CLOSE`;
3. resume;
4. on success/cancel, terminate/close the Job;
5. verify active process count is zero;
6. only then issue execution completion.

Assignment, resume, termination, verification, or close failure yields debt and
no authoritative completion.

### Linux

Process groups are insufficient. Use a delegated cgroup-v2 subtree, preferably
with pre-execution placement, `cgroup.kill`, and
`cgroup.events populated=0`. Without an owned cgroup, the provider cannot claim
exhaustive closure.

### macOS and other POSIX

Use a native sandbox/VM/helper that prevents descendant escape or emit explicit
closure debt. Attempt-local staging can prevent canonical late mutation but is
not equivalent to process-tree proof.

## 7. Red-to-green matrix

1. Root exits while a detached child writes later.
2. PTY emits `end_turn` while root/child remains alive.
3. Breadth disk-idle completion while process remains alive.
4. Six workers: one completes, five continue; coordinator exits.
5. Rate-limit/Esc while futures run.
6. Input restoration while a worker unwinds.
7. Old attempt writes after retry begins.
8. Worker A attempts worker B's output.
9. Parent phase attempts clean commit with a missing child receipt.
10. Verifier output exists without WER completion.
11. Report aggregation starts before every required child is incorporated.
12. Retry reuses five valid completions and schedules exactly one.
13. Retry preserves the full semantic contract.
14. Windows Job assignment/resume/terminate/close failure.
15. POSIX child escapes its process group.
16. Crash after publication arm and after the first of multiple outputs.
17. Legacy canonical output exists without execution authority.
18. Claude PTY/headless/Codex yield the same logical denominator.
19. No canonical or protected-input mutation after phase commit.
20. Static gate forbids raw model `Popen`/PTY construction outside providers.
21. Required child with no receipt prevents clean parent commit.
22. Stale/reordered attempt receipts cannot bind a new run.
23. Sandbox denies source/other-worker/canonical writes.
24. Assessor claims require separate linked receipts or are renamed non-authoritative.

## 8. Migration

1. Add the red fixtures and freeze new raw launch sites.
2. Factor `OwnedProcessScope` from WER and fuzz authority.
3. Fix WER POSIX capability semantics, publication recovery, assessor wording,
   and cleanup order.
4. Integrate headless Claude, Codex, dynamic verification, and repair workers.
5. Wrap `ClaudePtySession` as a terminal codec inside a provider-owned adapter.
6. Cut recon, breadth, rescan, and depth to one-output WorkPlan rows.
7. Cut generic PTY/report phases.
8. Link completion and incorporation receipts into PhaseIO.
9. Require phase-level exact WorkPlan parity and zero active attempts.
10. Remove or wrap raw termination, unsafe nonblocking pool, direct model-owned
    orchestration, and retired launchers.
11. Add static raw-launch prohibition and full crash/resume matrix.

Do not immediately remove Claude PTY; it is operationally useful for the legacy
subscription backend. Retire its independent lifecycle authority. PTY becomes a
codec, not an owner, publisher, or completion authority.

## 9. Existing evidence

- WER focused tests: 72 passed.
- Windows fuzz detached-child containment passed.
- Existing pool tests pass but two encode unsafe `wait=False` behavior and must
  be replaced.

These are substrate evidence only. P0-AM remains incomplete until every
production model/tool launcher uses the unified boundary and final
fault/resume/backend tests pass.
