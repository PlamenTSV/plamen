# Plamen WorkerTransaction P0-AM Implementation Design

Date: 2026-07-24  
Status: implementation design; no repository changes or acceptance claimed  
Scope: Claude PTY, Claude headless, Codex, verifier/repair workers, native tools, process/write authority, PhaseIO incorporation

## 1. Core verdict

Do not wire the current `worker_execution_receipts.py` directly into
production. It is useful test substrate, but its current authority model is
insufficient:

- Production never calls `run_observed_worker`.
- Linux can emit a completion even though its own capability record says
  descendant containment is non-exhaustive.
- Canonical outputs are published before the Windows Job handle is closed. A
  close failure can therefore occur after purported completion/publication.
- Canonical publication belongs in PhaseIO, not the execution observer.
- `assessors` are names and invocation IDs, not linked execution receipts.
- Filesystem ownership is not enforced; the process still sees the shared
  scratchpad/project.
- Multi-output publication has only best-effort rollback after a partial crash.
- Its root-exit completion model does not cover PTY `end_turn`, artifact-idle
  cutover, or cancellation safely.
- It does not provide phase-level WorkPlan parity or parent/child denominator
  accounting.

The required architecture is:

```text
PhaseWorkRoster
  -> immutable WorkPlan per logical unit
  -> attempt-specific arm, staging view, OS scope
  -> provider launches child
  -> provisional completion signal
  -> terminate complete process scope
  -> prove scope empty and cleanup successful
  -> parse staged bytes
  -> immutable CAS + execution receipt/debt
  -> driver-only PhaseIO incorporation/projection
  -> exact roster reconciliation
  -> phase commit only with zero active attempts
```

A model/tool never receives a canonical output path.

## 2. Current live launch inventory

Line numbers are from the current shared tree during this review; symbols are
the durable migration anchors.

### 2.1 Driver-owned model launches

| Live seam | Launch site | Consumers / observations |
|---|---:|---|
| `_execute_dynamic_verifier_launch` | `plamen_driver.py:13885` PTY, `:13923` headless | Called by `_run_dynamic_verifier_unit:14178` and `_run_verify_recovery_unit:20762`. Writes coupled verifier Markdown/proposals directly into scratchpad. |
| `_run_verify_recovery_shard_legacy_retired` | `:19839` | Raw legacy `Popen`; no production caller found. Must be deleted or statically proven unreachable. |
| `_respawn_via_resume` | `:22431`, spawn `:22439` | No production caller found. Retired authority that still violates a future raw-launch lint. |
| `_respawn_missing_only` | `:22830`, spawn `:22838` | Called by `_run_supervised_pty_loop:23120`; reuses shared canonical scratchpad. |
| `_run_single_recon_worker_pty` | `:23796`, spawn `:23808` | Pool and dependency-research leaf. Records PhaseIO before the `finally` termination path. |
| `_run_recon_worker_pool_pty` | pool `:24138` | Uses `_NonBlockingWorkerPool`; shared output allowlist and shared inputs. |
| `_run_single_breadth_worker_pty` | `:29282`, spawn `:29294` | Disk-idle/marker cutover may validate and record output before lifecycle cleanup. |
| `_run_breadth_worker_pool_pty_core` | pool `:29679` | Shared output authority; abnormal exit uses non-waiting shutdown. |
| `_breadth_run_wave_extension` | pool `:30115` | Same lifecycle problem, though additive/best-effort. |
| `_run_single_rescan_worker_pty` | `:30714`, spawn `:30726` | Same shared-scratchpad and pre-termination recording issue. |
| `_run_rescan_worker_pool_pty` | pool `:30910` | Same cancellation issue. |
| `_run_single_depth_worker_pty` | `:33687`, spawn `:33699` | Finalizes fuzz/PhaseIO state before termination; fuzz workers also own separate mutable workspace state. |
| `_run_depth_worker_batch` | pool `:33949` | Shared output set, input restoration, `shutdown(wait=False)`. |
| `_run_one_codex_exec` | raw `Popen :36065` | Shared helper for auxiliary model leaves, evidence repair, methodology repair, exploration repair, breadth/depth fanout, DA, and generic Codex phases. |
| `_run_one_claude_headless_breadth_worker` | raw `Popen :36226` | Same consumers on Claude headless. |
| `run_phase` generic Claude PTY | `:38117`, spawn `:38128` | Generic inventory/invariants/skeptics/chain/report and remaining PTY phases. |
| `run_phase` generic headless | raw `Popen :38267` | Generic non-PTY Claude path. |
| `_terminate_process_tree` | `taskkill :3263` | Best-effort PID-tree cleanup, not ownership or proof. |

Shared headless/Codex helper callers include:

- `_execute_auxiliary_model_work_unit`
- `_run_report_evidence_repair_once`
- `_run_methodology_repair_producer`
- `_run_exploration_clear_lifecycle`
- `_run_breadth_backend_fanout`
- `_run_depth_codex_fanout`, including DA iteration
- generic `run_phase`

### 2.2 PTY transport

`pty_exec.py` currently owns lifecycle:

- Windows `winpty.PtyProcess.spawn`: line 920.
- POSIX raw `Popen`: line 967.
- Windows best-effort `taskkill`: line 1079.

`ClaudePtySession` must become a codec only: prompt delivery, PTY bytes,
transcript observation, and turn-signal parsing. It must no longer spawn,
terminate, publish, or certify completion.

### 2.3 Existing WER/fuzz process authorities

- `worker_execution_receipts.run_observed_worker`: raw `Popen` at line 1743;
  production-unused.
- `fuzz_workspace_authority._popen_contained`: raw `Popen` at line 1632.
- Fuzz `_terminate_process_tree`: `taskkill` at line 1677.

These duplicate Windows Job Object code and must converge onto one
`OwnedProcessScope`.

### 2.4 Native/tool subprocesses

| File | Sites | Treatment |
|---|---|---|
| `recon_prepass.py` | `_run_hardened:2097`, tree kill `:2036` | Replace with `NativeCommandAdapter`. Current consumers include dependency installs, Foundry/SVM, build status, SCIP Go/Rust, OpenGrep, Sec3, govulncheck, cargo-audit. Some mutate build/dependency trees and need explicit mutation leases. |
| `mechanical_verify.py` | tests `:1080/:1148`, prewarm `:2021/:2079` | Proof-critical. Must migrate early; raw timeout can leave descendants. |
| `audit_snapshot.py` | git head `:1305`, submodules `:1325`, tool versions `:1589` | Read-only probes, but their bytes affect snapshot authority. Use a read-only command transaction. |
| `supply_chain_gate.py` | scanner `:147` | Authority-affecting native command; bounded execution receipt required. |
| `spike_mechanical_poc.py` | `:377` | Standalone/legacy CLI. Wrap or retire; static lint must not exempt it indefinitely. |
| `plamen_display.py` | diagnosis `Popen :777`, taskkill `:732` | Advisory only, but can still leave children. Use stdout-assigned low-authority transaction. |
| `preflight_pty_transports.py` | raw Claude PTY and version calls | Non-audit preflight, but should consume the same provider so it tests reality rather than a parallel implementation. |

### 2.5 Current write-authority seams

- Codex pre-creates canonical expected files and normally grants the project
  root and scratchpad as writable directories.
- Claude PTY/headless prompts carry canonical scratchpad paths.
- PTY pools give each worker the entire current round's output allowlist, so
  worker A can write worker B's file.
- Input restoration occurs only after a batch and cannot detect a transient
  mutation that another concurrent worker consumed.
- Generic phases can mutate multiple canonical outputs directly.
- Dynamic verifier units write several verifier/proposal files directly.
- Native recon/build/verification tools intentionally mutate build caches,
  dependencies, generated tests, or fuzz workspaces without a unified mutation
  receipt.
- Claude transcripts live under the global Claude project directory rather
  than an attempt-owned evidence scope.

## 3. Target schemas and APIs

### 3.1 `PhaseWorkRoster`

Freeze the roster before any launch:

```json
{
  "schema": "plamen.phase_work_roster.v1",
  "run_id": "...",
  "phase": "depth",
  "generation": 1,
  "required_work_unit_ids": ["..."],
  "optional_work_unit_ids": ["..."],
  "work_plan_digests": {"unit": "sha256"},
  "aggregation_predicate": "ALL_REQUIRED_INCORPORATED",
  "roster_digest": "sha256"
}
```

Adaptive work must be added through a prelaunch `RosterAmendment`, not inferred
after workers finish. Stable unit IDs prevent retries or extra waves from
inflating the denominator.

### 3.2 `WorkPlan`

Minimum bound fields:

```json
{
  "schema": "plamen.worker_work_plan.v1",
  "run_id": "...",
  "phase": "...",
  "work_unit_id": "...",
  "generation": 1,
  "phase_roster_digest": "...",
  "phase_io_contract_digest": "...",
  "phase_io_launch_digest": "...",
  "phase_io_input_set_digest": "...",
  "prompt_sha256": "...",
  "methodology_digests": [],
  "source_snapshot_digest": "...",
  "provider": {
    "backend": "claude|codex|native",
    "model": "...",
    "transport": "pty|headless|exec|native",
    "resolved_executable": "...",
    "executable_sha256": "...",
    "argv": [],
    "environment_allowlist_digest": "...",
    "timeout_seconds": 0,
    "stream_limits": {}
  },
  "assignment": {
    "assignment_id": "...",
    "members": [{
      "staged_relative_path": "...",
      "canonical_identity": "scratchpad:...",
      "parser_binding": {},
      "projection_mode": "CREATE_ABSENT|REPLACE_EXACT_PRESTATE",
      "canonical_prestate": {}
    }]
  },
  "write_scope": {},
  "child_denominator": {},
  "completion_policy": {},
  "retry_policy": {},
  "terminal_debt_policy": {},
  "work_plan_digest": "sha256"
}
```

Use one logical assignment per WorkPlan. Normal pool leaves have one member.
Truly atomic coupled outputs, such as a verifier unit's Markdown and typed
proposals, may be one exact bundle, but not a set shared with another worker.

### 3.3 Attempt and completion

Each attempt gets an immutable, unique directory and ordinal:

```text
.worker_transactions/
  <phase>/<work-unit>/<plan-digest>/<attempt-id>/
    arm.json
    view/
    output/
    streams/
    cas/
    completion.json | debt.json
```

`AttemptArm` binds the WorkPlan, OS capability, process/write-scope identity,
output prestate, and provider implementation digest before launch.

`ExecutionCompletion` is emitted only after:

1. A valid provisional completion signal.
2. Complete scope termination.
3. Verified zero process population.
4. Required OS cleanup succeeds.
5. Streams/transcript are closed and bounded.
6. Inputs/executable/parser bindings replay.
7. Exact staged denominator parses.
8. CAS blobs are immutable.

`ExecutionDebt` records any failure without authorizing an output. Raw bytes may
be retained as proposal material.

### 3.4 Public API

```python
compile_phase_work_roster(...)
compile_worker_plan(...)
execute_worker_transaction(plan, adapter, cancel_token) -> ExecutionRef
recover_worker_transactions(run_id, scratchpad) -> RecoveryStatus
incorporate_worker_execution(execution_ref, phase_io_contract) -> IncorporationRef
reconcile_phase_work_roster(roster) -> PhaseExecutionStatus
```

There must be no public "write completion receipt" API.

## 4. Shared primitives versus backend adapters

### 4.1 Shared lifecycle authority

`OwnedProcessScope` owns:

- Arm-before-launch.
- Native root creation.
- Windows Job/cgroup assignment.
- Process identity.
- Stream ceilings.
- Cancellation.
- Termination.
- Population-zero proof.
- Cleanup.
- Crash recovery/debt.

Adapters cannot call `Popen`, `winpty.spawn`, `taskkill`, `killpg`, or cgroup
APIs.

### 4.2 Backend adapters

- `ClaudePtyAdapter`: CLI shaping, PTY codec, prompt/bootstrap, transcript
  parsing, rate-limit/turn-end signals.
- `ClaudeHeadlessAdapter`: CLI shaping and JSON/text result parsing.
- `CodexExecAdapter`: CLI shaping, last-message handling, auth/capacity
  classification, sandbox configuration.
- `NativeCommandAdapter`: argv/tool-policy validation and stdout/file parser.
- All adapters return provisional transport observations only. They cannot
  certify process closure or publish outputs.

### 4.3 Scheduler

Replace `_NonBlockingWorkerPool` with a bounded scheduler that:

- Registers an attempt before child creation.
- On Esc/rate-limit, signals cancellation to every started transaction.
- Marks queued work `CANCELLED_BEFORE_LAUNCH`.
- Waits for every started transaction to reach a closure/debt receipt.
- Returns only when the active-attempt registry is empty.
- Uses ordinary `shutdown(wait=True)` after lifecycle completion.

If cleanup exceeds the bounded OS grace, the phase cannot clean-commit; the
driver may exit/degrade, but must not pretend workers stopped.

## 5. OS process and write authority

### 5.1 Windows

Required sequence:

1. Create non-inheritable Job with `KILL_ON_JOB_CLOSE`; disallow breakaway.
2. Create target suspended.
3. Assign target to Job.
4. Record root creation identity.
5. Resume the exact primary thread.
6. Observe provisional completion.
7. `TerminateJobObject` even after natural root exit.
8. Query Job accounting until `ActiveProcesses == 0`.
9. Wait for root handle and bounded stream EOF.
10. Close Job handle and verify `CloseHandle` success.
11. Only then emit completion.

Assignment, resume, terminate, population query, root wait, or close failure
produces debt and no authoritative completion.

Current `winpty.spawn` cannot satisfy pre-execution assignment. Use one of:

- A reviewed `plamen-worker-host` launched suspended inside the Job; once
  resumed, it creates the ConPTY/winpty child, which inherits the Job.
- A pywinpty/ConPTY integration exposing suspended creation before user code
  runs.

A post-spawn `AssignProcessToJobObject` is not acceptable.

For filesystem authority, the strongest practical Windows design is a
low-integrity/restricted worker token:

- Source, canonical scratchpad, and methodology remain
  medium-integrity/read-only.
- Attempt view/home/output are explicitly low-integrity writable.
- Job and restricted token are applied before execution.
- If the backend cannot operate under this token, capability becomes degraded
  and outputs cannot be clean authority.

### 5.2 Linux

A process group is insufficient.

Required capability:

- Delegated cgroup-v2 subtree per attempt.
- Trusted launch helper blocks before spawning untrusted code.
- Provider places the helper in the cgroup before releasing it.
- Worker cannot write/migrate itself to ancestor/sibling cgroups.
- All descendants inherit membership.
- Completion cleanup calls `cgroup.kill`.
- Wait until `cgroup.events` reports `populated 0`.
- Remove subtree successfully before completion.

Use a mount/user namespace, Landlock, or reviewed sandbox helper to expose:

- Source and canonical scratchpad read-only.
- Attempt view and declared tool workspaces writable.
- No undeclared writable root.

If cgroup delegation or write confinement is unavailable, Linux may run
proposal-only but cannot emit clean execution completion.

### 5.3 macOS and other POSIX

Treat as explicit capability debt until a native sandbox/VM/helper proves both
descendant and write containment.

Attempt-local staging prevents canonical late mutation but is not process-tree
proof. Do not label process-group cleanup exhaustive.

## 6. PTY and completion semantics

A PTY signal is provisional:

- `end_turn`
- COMPLETE marker plus disk-idle
- output-cap/context fallback
- rate limit
- timeout
- user cancellation

After any provisional terminal condition, the provider must close the entire OS
scope before parsing or accepting output.

For an intentional PTY cutover, a non-zero root code caused by provider
termination is expected. The receipt records:

```text
completion_signal = TURN_END | OUTPUT_READY | RATE_LIMIT | TIMEOUT | CANCEL
root_exit_origin = NATURAL | PROVIDER_TERMINATED
```

Only `TURN_END` or a mechanically accepted `OUTPUT_READY` may lead to
completion, and only after closure and strict output validation. Rate limit,
timeout, cancellation, stream overflow, or observation failure always lead to
debt.

## 7. Owned staging and canonical projection

Every worker receives:

- An attempt-specific scratchpad view.
- Exact copied/read-only PhaseIO inputs.
- A read-only source snapshot or declared copy-on-write tool workspace.
- One output assignment under its staging root.
- Attempt-specific HOME/config/cache roots where backend operation requires
  them.

No prompt contains a canonical output path. Runtime placeholder compilation
must target the view.

The worker's staged output becomes a CAS blob after closure. It is not published
by WER.

PhaseIO performs canonical projection using a durable projection arm:

1. Validate execution receipt and CAS.
2. Revalidate PhaseIO input and output-prestate digests.
3. Persist projection arm.
4. Project each member with exact CAS.
5. Persist per-member progress.
6. Roll forward after a crash.
7. Record an incorporation receipt.
8. Call `record_work_unit_artifacts` with the incorporation receipt as
   mandatory `execution_authority`.

For actor `MODEL`, `record_work_unit_artifacts` must quarantine/proposal-only any
output lacking a valid execution and incorporation chain.

For multi-member bundles, use durable roll-forward. Do not rely on best-effort
rollback. Phase readers cannot begin while the projection arm is incomplete.

## 8. Retry, resume, crash, and denominator rules

### 8.1 Retry

Stable identity is `(run_id, phase, work_unit_id, generation)`. Attempts have
unique IDs and never reuse directories or output paths.

A prior completion is reusable only if all bindings match:

- WorkPlan digest.
- Source/input snapshot.
- Prompt/methodology.
- Backend/model/transport.
- Executable and argv.
- Environment allowlist.
- Tool/write policy.
- Parser.
- Assignment/projection.
- PhaseIO contract/launch/input-prestate.

A backend fallback or model change creates a new plan generation; it cannot
adopt the earlier completion.

If six rows were planned and five exact receipts exist, schedule only the
missing sixth row.

### 8.2 Crash

- Windows driver death closes non-inheritable Job handles and kills members. On
  resume, an armed attempt without completion becomes
  `INTERRUPTED_PROVIDER_CRASH` debt and is retried; it is never retroactively
  completed.
- Linux resume reopens the persisted cgroup identity, kills it, waits for
  `populated 0`, removes it, then records interrupted debt.
- A completion persisted after full closure but before incorporation can be
  replayed and incorporated.
- A crash during projection is rolled forward from the projection arm.
- Legacy canonical bytes without execution authority remain proposal-only and
  are rescheduled; never mint a retroactive receipt.

### 8.3 Parent/child denominator

A parent phase cannot clean-commit merely because output files exist.

The phase reconciliation requires:

- Every required WorkPlan has one incorporated completion.
- Every launched attempt is terminal.
- No active process scope remains.
- Every required declared native child/tool receipt is linked.
- Optional/adaptive rows have explicit terminal dispositions.
- No stale or reordered attempt receipt binds the new roster generation.

Nested model-owned Task orchestration cannot provide independent execution
authority. Migrate those tasks into driver-owned WorkPlans or retain explicit
child-execution debt. Prefer disabling nested Task/Agent use once a phase has
driver-owned fanout.

## 9. Failure-path behavior

| Condition | Required result |
|---|---|
| Spawn/assignment/resume failure | Arm + debt; prove/attempt cleanup; no completion or projection. |
| Natural zero root exit | Still terminate scope and prove zero descendants. |
| Detached child | Job/cgroup contains it; completion waits for zero population. |
| Timeout | Terminate scope, bounded stream capture, TIMEOUT debt. |
| Output/stream limit | Immediate scope termination, bounded blobs, LIMIT debt. |
| Rate limit | Terminate all active provider scopes before coordinator returns/backoff. |
| User cancel/Esc | Cancel queued rows; terminate and join every started transaction. |
| Parser/schema exception | Process is already closed; retain CAS/proposal bytes, emit parsing debt. |
| Job/cgroup cleanup failure | No authoritative completion. |
| Input/executable/parser drift | Debt; output quarantined. |
| Worker writes another worker's stage | Sandbox denial; otherwise entire batch quarantined. |
| Protected source/canonical mutation | No clean completion; do not let another concurrent worker consume it. |
| Missing child receipt | Parent roster remains debt; no negative/safe authority. |
| Legacy output exists | Proposal-only retention; does not satisfy denominator. |

## 10. Migration order

### Stage 0 - freeze unsafe expansion

- Add red fixtures first.
- Add AST lint in warning mode to enumerate every raw launch.
- Mark the two retired driver launchers as deletion targets, not permanent
  allowlist entries.
- Preserve current canonical validators and output names.

### Stage 1 - consolidate OS authority

- Extract `OwnedProcessScope` from WER and fuzz Job code.
- Add Windows population-zero and close-before-receipt semantics.
- Add Linux cgroup-v2 implementation.
- Change unsupported POSIX to explicit debt.
- Remove WER's ability to complete under non-exhaustive containment.
- Remove mandatory assessor-name claims.

### Stage 2 - WorkPlan, attempts, CAS, recovery

- Add roster, WorkPlan, AttemptArm, completion/debt, CAS, and active-attempt
  registry.
- Stop WER canonical publication.
- Add PhaseIO incorporation/projection receipt and crash roll-forward.
- Require execution authority for new model-owned ACTIVE artifacts.

### Stage 3 - native command authority

First migrate the strongest existing path:

1. Fuzz `_popen_contained` and `_bounded_version`.
2. Mechanical PoC test/prewarm execution.
3. Snapshot git/tool-version probes.
4. Supply-chain scanners.
5. Recon/build/SCIP/OpenGrep/Sec3/dependency commands.
6. Advisory failure diagnosis.
7. Retire standalone raw spike launcher or wrap it.

Mutation-capable native commands get explicit write-root/mutation contracts;
read-only commands get stdout-assigned output.

### Stage 4 - shared headless providers

Replace internals of:

- `_run_one_codex_exec`
- `_run_one_claude_headless_breadth_worker`
- `_execute_dynamic_verifier_launch` headless branch

Keep their outer signatures temporarily as compatibility facades.

This automatically migrates auxiliary typed work, evidence repair, methodology
repair, exploration repair, breadth fanout, depth/DA fanout, verification, and
recovery.

### Stage 5 - PTY provider

- Implement trusted Windows/Linux PTY host.
- Reduce `ClaudePtySession` to codec.
- Migrate dynamic verifier PTY.
- Migrate recon, breadth, rescan, and depth leaves.
- Give each leaf its own stage/output assignment.
- Replace `_NonBlockingWorkerPool` and active-session registry.

### Stage 6 - generic phases and continuation

- Migrate generic `run_phase` PTY/headless.
- Represent missing-only continuation as a new attempt of the same stable
  WorkPlan.
- Remove `_respawn_via_resume` if still unreachable.
- Split any generic nested-agent orchestration into driver-owned work rows or
  retain explicit debt.

### Stage 7 - phase commit enforcement

- Freeze exact phase rosters before launch.
- Require incorporation parity and zero active attempts in phase commit/resume
  reconciliation.
- Preserve haltless behavior as `COMPLETED_WITH_DEBT`, but prohibit debt
  outputs from negative/safe authority.
- Turn raw-launch lint from warning to blocking.
- Remove taskkill/process-group/pool compatibility code.

## 11. Fixture and fault matrix

### 11.1 Schema and authority

- Duplicate/unknown fields, unsafe paths, case aliases, physical aliases.
- WorkPlan digest stability.
- Backend/model/argv/env/parser drift invalidates reuse.
- One logical assignment; exact bundle denominator.
- Assessor claims require linked execution receipts.
- Legacy bytes cannot become authority.

### 11.2 Process lifecycle

- Root exits and detached child writes later.
- PTY emits `end_turn` while root/child remains alive.
- Breadth output-idle fires while PTY remains alive.
- Timeout, rate limit, output overflow, cancel, keyboard interrupt.
- Spawn, Job assignment, resume, terminate, query, close failures.
- Linux child calls `setsid`; cgroup still contains it.
- Linux missing delegation or writable ancestor produces debt.
- Unsupported POSIX cannot emit clean completion.
- Driver crash during a live attempt.

### 11.3 Write authority

- Worker A attempts worker B's stage.
- Worker attempts canonical scratchpad/source mutation.
- Fuzz worker may mutate only its declared copy-on-write workspace.
- Old attempt writes after retry begins.
- No canonical/protected mutation after phase commit.
- Concurrent transient input mutation cannot be consumed by another worker.

### 11.4 Pool and denominator

- Six workers: one completes, five remain active; coordinator cannot return.
- Rate limit in one worker closes all started workers.
- Queued rows get `CANCELLED_BEFORE_LAUNCH`.
- Five exact completions are reused and one row is scheduled.
- Missing receipt prevents clean parent commit.
- Optional/adaptive roster amendment does not change the baseline denominator
  retroactively.

### 11.5 Crash boundaries

Inject crashes:

- Before arm persistence.
- After arm, before spawn.
- After spawn/assignment.
- After provisional completion, before termination.
- After process closure, before CAS.
- After CAS, before completion.
- After completion, before incorporation.
- At every member of a multi-output projection.
- After incorporation, before phase commit.

Every resume must either roll forward an already-safe transaction or retain
debt and retry. It must never infer completion from canonical presence.

### 11.6 Backend/OS matrix

- Windows real Job Object tests, including detached descendants and close
  failures.
- Linux cgroup-v2 CI runner with actual `cgroup.kill`/`populated 0`.
- macOS/unsupported-POSIX explicit-debt tests.
- Claude PTY, Claude headless, Codex exec, and native command adapters must
  yield identical logical roster/denominator semantics.
- Backend-specific auth/capacity behavior changes retry state only, never
  output authority.

## 12. Acceptance gates

P0-AM is complete only when all hold:

1. No reachable model/native launcher bypasses `WorkerTransaction`.
2. AST lint forbids raw subprocess/PTY/process-kill construction outside the
   reviewed provider modules.
3. No execution receipt can be emitted without exhaustive process closure or
   explicit unsupported debt.
4. Job/cgroup cleanup finishes before completion persistence.
5. A worker has no shared canonical output authority.
6. PhaseIO is the only canonical publisher.
7. Every model-owned ACTIVE artifact binds an execution and incorporation
   receipt.
8. Exact required WorkPlan parity and zero active attempts precede phase
   commit.
9. Retry/resume never adopts legacy or stale bytes.
10. Detached-child, cancellation, crash, concurrent-worker, and late-write
    fixtures pass on each supported OS.
11. Claude PTY/headless and Codex have the same logical denominator.
12. Full serial and parallel suites, fault matrix, resume matrix, and bounded
    non-ground-truth backend canaries are green.

## 13. Backward-compatible rollout constraints

- Preserve current canonical artifact names and validators while changing who
  is authorized to publish them.
- Use compatibility facades around current launcher functions during
  migration, but route their internals through the provider.
- Do not dual-execute a model merely to obtain a shadow receipt. A
  provider-owned execution can project through legacy canonical interfaces
  while new receipts are validated.
- Existing unreceipted artifacts are retained as proposal material. They are
  never retroactively adopted as clean authority.
- A migrated phase may degrade with visible lifecycle debt rather than halt,
  but lifecycle debt cannot authorize a SAFE/REFUTED/terminal-negative
  disposition.
- A fallback backend/model is a new WorkPlan generation, not an invisible retry
  of the original execution.
- Do not remove Claude PTY. Preserve it as a transport codec because it remains
  operationally important for the legacy subscription backend.
- Do not claim macOS/other-POSIX support until process-tree and write-scope
  authority have real platform proofs.

No repository or configuration files were edited and no tests or audits were
run while producing this design.
