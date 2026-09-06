# Runtime acceptance evidence addendum

Observed 2026-09-06, approximately 12:51 Europe/Bucharest.

This supplements, and does not replace, the Goal Acceptance Ledger dated
2026-07-17 and Architecture Supersession Crosswalk dated 2026-07-24. It is a
partial evidence reconciliation, not a complete requirements inventory.

## Evidence boundary

Repository: `<LOCAL_CHECKOUT>`.

Run scratchpad: `<PRIVATE_AUDIT_SCRATCHPAD>`.

The process with PID 17832 was observed alive with creation time 12:46:39.
The driver log recorded first Recon worker launch at 12:49:57. This proves
launch reachability only, not worker success or completed E2E acceptance.

## Requirements and current evidence

| Requirement | Classification | Evidence and remaining proof |
|---|---|---|
| Truthful build coverage | active-required | `build_status.md` reports exit 1 and FAILED. Its compiler output reports unresolved OpenZeppelin upgradeable and Uniswap imports. The driver explicitly recorded degradation. Successful compiler-backed coverage is not established. Whether files are absent or path resolution is wrong remains undiagnosed. |
| Program Facts runtime integration | active-required | `_plamen.log` at 12:48:58 reports `UNSUPPORTED`, `consumer_activation=False`, and `prior_runtime_debt_cleared=False`. This run cannot establish integrated provider or consumer acceptance. |
| Slither coverage | active-required | Prepass records `SKIPPED:TOOLCHAIN_AUTHORITY_DEBT:OBSERVED_NONAUTHORITATIVE`. Source-derived graph output is not proof of Slither execution. Applicable support requirements must be reconciled before closing this debt. |
| Auxiliary filesystem recovery | active-required | Log at 12:49:31 records recovery completed with quarantine debt. Recovery completion does not establish debt-free lifecycle acceptance; the underlying receipt and quarantined contents require review. |
| Claude backend parity and resume | active-required | The governing ledger requires a fresh legacy-Claude path exercise and clean resume. p18 is configured for Codex; it cannot discharge the Claude requirement. No current Claude completion evidence was established in this review. |
| Completed E2E runtime validation | active-required | p18 was still in Recon at observation. A launch, live PID, or generated prepass files are insufficient completion evidence. |
| Old-versus-new benchmarking and ground-truth scoring | intentionally deferred | Explicitly excluded by the current user goal and assigned to a later separate goal. This supersedes inclusion of comparative scoring in older acceptance recipes for this goal only. Runtime validation remains required. |

## Interpretation

A report produced after degraded prerequisites would establish only the paths
actually exercised. It would not close missing build, provider, backend, or
resume evidence. Historical matrices and test counts require current binding
and scope checks before being promoted to implemented-and-proven.

Clock observation: the system reported 12:51:03 +03:00 and the independent
clock tool reported 09:51:03 UTC. These agree with one another but do not explain
the user's reported 14–15 hour interval. No claim about that interval is made.

## Auxiliary recovery receipt review

The startup receipt with SHA-256 field
`9239e932ec1d2f705ec0fe8c17b2a1ffe0fc27f2c7f28be34629ce33ebf9c4e9`
reports ten roots with disposition `QUARANTINED` and reason
`LEGACY_OR_UNJOURNALED_ROOT`. They are under
`%LOCALAPPDATA%\Plamen\runtime\auxiliary-writable-roots\v1`.
It reports zero active registry entries and zero live entries at startup.
The profile lifecycle replay reports 2,018 scanned and 2,018 terminal records.

The outer startup state is `COMPLETE`, while reconciliation explicitly has
`complete: false` and `ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT`. These refer to
different completion boundaries: startup finished processing, but legacy-root
debt remains. Neither the number of terminal records nor the absence of live
registry entries authorizes deletion of unknown roots. Root contents, byte
sizes, ownership, and retention obligations were not established by this read.
No files were deleted or moved.

This narrows the lifecycle acceptance gap to recorded legacy/untracked-root
disposition and retention evidence; it does not establish a current disk leak
or successful cleanup. The receipt digest above is a recorded field, not an
independently recomputed authenticity claim.

### Bounded disk inventory

A subsequent read-only traversal of exactly the ten receipt-listed roots
found eight with no files and two with one 99-byte file each, for 198 bytes
of total logical file content. No reparse points were encountered and no
directory reads failed. This excludes these ten roots as a material source
of the reported C-drive space consumption; it does not measure the whole
runtime namespace or filesystem allocation overhead. Their directory
modification timestamps were July 28, 2026.

The first attempt to read the long receipt path through ordinary PowerShell
path syntax failed with a misleading file-not-found error. Reading the same
receipt using the Windows extended-length prefix succeeded. No missing-file
or terminal-process conclusion was inferred from that observation failure.

Cleanup remains unperformed. The 198-byte measurement reduces the urgency of
space reclamation for these roots but does not discharge retention policy or
legacy ownership requirements.

## Terminal lifecycle retention review

`scripts/auxiliary_writable_root_lease.py` invokes
`owned_directory_guard.reconcile_owned_directory_cleanup_ledgers` during
startup while holding the registry mutation guard. In
`scripts/owned_directory_guard.py`, `_MAX_RECONCILIATION_LEDGERS` is 10,000.
The reconciliation function inventories the directory, enforces count/byte
bounds, and replays every retained ledger, including terminal ones. It does
not retire terminal ledgers in that function. The count check occurs after
materializing the directory inventory.

Classification: **active-required, retention closure unproven**. The observed
2,018 terminal ledgers are below the count limit. This is not evidence that
the limit will be reached, that all callers retain indefinitely, or that the
whole repository lacks a separate retirement mechanism. Such a mechanism
must be located and its caller reachability, ownership checks, and retained
evidence validated before bounded long-term operation can be claimed.

Required evidence: a documented terminal-record retention policy; a reachable
implementation that preserves recovery and evidence obligations; repeated-run
tests demonstrating bounded retained state; and restart tests that retain
valid interrupted-cleanup recovery. Increasing the entry limit alone would
not prove this requirement. No production edits or cleanup were made during
this review.

### Caller trace refinement

Production Python searches for the lifecycle directory and reconciliation
entrypoint found allocation in `claude_attempt_profile.py`, startup replay
in `auxiliary_writable_root_lease.py`, and replay implementation in
`owned_directory_guard.py`. Each guard allocation creates a randomly named
`guard-<id>.jsonl`. The separate `_compact_terminal_journal` function archives
outer auxiliary lease journals; it is not a retirement implementation for
these profile guard ledgers.

Crucially, Claude profile revocation verification directly replays
`profile._directory_guard.ledger_path` in `claude_attempt_profile.py` around
line 4150. Therefore relocating or deleting a terminal guard ledger without
updating its replay contract can invalidate already-issued revocation
evidence. A correct retention implementation needs archive-aware replay and
an explicit retention boundary; a generic age-based deletion pass is
insufficient. Reconciliation also enforces a 512 MiB cumulative byte limit.

No guard-ledger retirement caller was found in the inspected production
Python paths. This is stronger evidence of a missing integration than the
initial single-function review, but does not establish repository-wide
absence of dynamically named or external maintenance tooling.

## Reproducible storage inventory utility

Utility: `<LOCAL_VALIDATION_WORKSPACE>\inspect_lifecycle_retention.py`.
Tests: `<LOCAL_VALIDATION_WORKSPACE>\test_inspect_lifecycle_retention.py`.
Both are outside the frozen production checkout.

From that directory, run:

```powershell
python -B -m unittest test_inspect_lifecycle_retention -v
python -B inspect_lifecycle_retention.py '%LOCALAPPDATA%\Plamen\runtime\auxiliary-writable-roots\v1\profile-lifecycle-v1'
```

Observed validation: four tests passed. Tests cover read-only contents,
incomplete count-limited enumeration, missing-root reporting, and avoiding
recursion into unexpected child directories. Real inventory completed with
2,018 regular ledgers, 11,936,989 logical bytes, and no issues. This is storage
metadata validation only; ledger semantic validity and retention closure are
not claimed. It reads no ledger contents and performs no production writes.

The initial test exposed a utility defect: Windows cached DirEntry metadata
did not supply the hard-link count needed for validation. The utility now
uses fresh `os.stat(..., follow_symlinks=False)`; both tests and the real
inventory passed afterward. The initial all-invalid inventory was therefore
a utility error and is not evidence of corrupt production ledgers.

## p18 Recon gate observation at 13:00

The driver remained alive and logged Recon completion at 12:57:52,
instantiation completion at 12:58:51, and first Breadth worker launch at
12:59:20. These are phase progression evidence, not whole-run acceptance.

New contradictory dependency evidence: the 12:57:30 R-EXT warning rejected
staged dependency evidence because cited sources were absent from typed
Codex web-search events. The subsequent dependency wave and parity records
both report zero researched and 25 unresolved. Therefore the current run
does not reproduce the previously reported p17 25/25 dependency coverage.
The warning identifies an evidence-admission failure, not proof that the
dependencies lack documentation. No validator was relaxed and no debt was
reclassified as researched.

The Recon gate allowed progression with this recorded debt. Whether that is
the intended degraded-run policy must be reconciled with governing acceptance
requirements; gate success must not be described as complete dependency
research. The log also records materialized Slither-named flat files despite
earlier Slither execution being skipped, so file existence alone remains
insufficient evidence of actual tool execution.

## p18 Breadth gate observation

At 13:08:14 the driver logged Breadth completion with five analysis files;
at 13:08:23 it wrote the rescan manifest. PID 17832 remained alive at the
13:08:58 observation. The log records 20 canonical finding blocks, but this
review does not establish their validity, uniqueness, severity, or quality.

At 13:08:11 OpenGrep coverage telemetry reported 79 input rows and zero
obligation receipts. The log explicitly says this check is warning-only and
does not fail the artifact gate. Classification: **active-required evidence
reconciliation**; source-level analysis coverage is not proven by the gate.
The absence of receipts does not itself prove the input rows were ignored.
The governing requirement must establish whether receipt production is
mandatory or informational before any enforcement change is justified.

## p18 per-contract missing-output observation

At 13:19:48 the driver recorded PC3's assigned output denominator mismatch:
expected `analysis_percontract_GatewayTransferNative.md`, observed no output.
It retained debt and launched PC4. The process remained alive at 13:20:39.

Classification: **active-required, failed attempt observed**. PC3's initial
attempt does not prove successful output publication. This observation does
not determine why the worker omitted the file, whether a later retry will
recover it, or whether the final phase gate will reject the missing artifact.
Those outcomes require later receipts. No manual output was fabricated,
worker relaunched, or artifact gate changed during this review.

Later observation supersedes the unresolved-attempt status for phase
progression: the driver launched PC3 attempt 2 at 13:24:28, followed by a
methodology repair worker at 13:26:11. Rescan passed its gate at 13:27:08
with three rescan files and seven per-contract files (including a re-emitted
self-exclusion artifact). Inventory preparation followed at 13:27:17.
This proves the driver's bounded retry path was reached and the later phase
gate accepted the output set. It does not erase the failed first attempt,
prove candidate quality, or establish complete end-to-end acceptance.

## p18 Inventory and invariant enrichment observations

Inventory chunk A passed its gate at 13:35:58. B and C were explicitly
skipped for zero assigned files. At 13:37:39 the driver committed a
single-chunk aggregate of 16 findings. These counts are runtime observations,
not ground-truth scoring or finding-quality claims.

The invariants worker launched at 13:38:08. At 13:40:03 the driver reported
semantic invariant enrichment failed or timed out and wrote
`semantic_invariants.md` using the documented `state_variables.md` fallback.
Classification: **active-required, model enrichment unproven**. Fallback
reachability is observed; successful model enrichment is not. The warning
does not distinguish failure from timeout, so this review assigns neither
specific cause without additional evidence. PID 17832 remained alive at
13:40:26.

The fallback invariant gate passed at 13:40:31, and the second invariants
pass passed at 13:41:48 with a 65.3 KB artifact. This does not supersede the
first enrichment failure. At 13:44:42 the Depth preparation log recorded
three authentication external-research obligations as UNKNOWN, explicitly
withholding favorable or adverse external-semantics claims and requiring
governed research or human review. At 13:45:18 the driver recorded 15 Depth
jobs, 12 initially ready, and concurrency 1. Classification for the three
obligations remains **active-required, unresolved**; scheduling jobs does not
discharge them.

## Supplemental storage-checker validation (14:11 local)

The standalone, read-only inventory helper outside the frozen production
repository now has seven passing unit tests. Three added tests exercise an
actual Windows hard link (excluded from ledger counts while preserving both
paths and target content), zero/exact-1-MiB/over-1-MiB ledger-size boundaries,
and invalid scan-limit values. Reproduce from
`<LOCAL_VALIDATION_WORKSPACE>` with
`python -B -m unittest test_inspect_lifecycle_retention -v`.
Observed result: seven tests passed, no skips, exit code 0.

This proves only those helper behaviors. It does not prove production
retention, cleanup, semantic ledger replay, race resistance, or integration.
Production retention remains active-required and unproven.

At 14:09:15 local, a read-only Get-PSDrive check reported 177.75 GiB free on
C: and 221.80 GiB free on D:. No cleanup was performed. These are point-in-time
capacity observations, not attribution of disk growth to any process.
At 14:11:10, p18 driver PID 17832 remained alive; its latest log transition
was the blind-spot-b Depth worker launch at 14:10:06. No Depth gate completion
was established by this check.

## p18 terminal failure observed at 15:10 local

At 15:10:14 on September 6, the process query returned no driver PID 17832.
The log records Depth complete and its gate passed at 14:49:39 (six
`depth_*_findings.md` files), with unresolved security-obligation authority
warnings immediately preceding that gate. A gate pass does not discharge
those warnings.

Attention repair queued seven items at 14:49:48. Both attempts were rejected
by staged semantic validation: `worker receipt row 5 is CONFIRMED without
ATT-5`. The first rejection was at 14:51:27; the second at 14:53:09.
At 14:53:18 the driver recorded no predicate progress, suppressed further
identical attempts, and reported a critical boundary failure with missing
`attention_repair_summary.md`. p18 is a failed end-to-end attempt, not a
successful audit or a currently running process.

Classification: attention-repair completion is **active-required, missing**.
Bounded retry and critical-boundary termination were observed in this run;
the log alone does not establish whether the rejection originates in worker
output, the validator, or their contract. No gate was weakened and no run
was restarted during this observation. The prior monitoring sample was at
14:19:07; this dossier does not claim continuous observation across the gap.

## Lifecycle acceptance scope reconciliation

Reviewed the complete `Plamen_P0-AM_Worker_Lifecycle_Forensic_2026-07-24.md`
from Downloads. Its historical status is a blocker specification, not current
implementation proof. Sections 4, 6, and 7 require owned process-scope closure
before completion/publication, explicit debt for OS cleanup failures, and
fault/resume/backend coverage. Section 7 contains 24 separate test obligations;
the standalone storage helper's seven tests do not satisfy that matrix.

Process lifecycle closure and disk retention are distinct requirements. A
missing root PID, including p18's missing PID, does not prove exhaustive
descendant closure. Conversely, a directory inventory cannot prove cleanup
ordering, completion authority, backend parity, or safe retirement/replay of
historical ledgers. No P0-AM acceptance item is promoted to implemented-and-proven
by the observations in this addendum. Current production evidence and the
applicable superseding specification must be checked before closing each item.

The July 29 `review_fixtures/wer_wtx_windows_long_path_independent_review_r1.md`
binds three exact source hashes. Current SHA-256 checks differ for all three:

| File under scripts/ | Current SHA-256 |
|---|---|
| worker_execution_receipts.py | 4200E17CFA4D0964344F544D8A8C8DD559E7669581E992097857A13BA3F91AC7 |
| worker_transaction.py | 736CBC0B024D2586AA6513DB1404FF76FA507B5B574DCD7DED7217B400D8B610 |
| test_wer_windows_long_path_p0_am.py | 4A2A7C97701566FAA81D6186D490C824727F88A7A1B11EE4BA8FDAF26D2CAF00 |

Consequently that review's passing test counts and BLOCK disposition are
historical evidence for its frozen snapshot, not proof of the current files'
behavior. The underlying requirements remain unresolved by this comparison;
changed hashes alone prove neither a fix nor a regression. No current test
execution or supersession closure is claimed here.

### Current narrow Windows path regression evidence

After inspecting the full current long-path test module, ran only two isolated
path-contract tests (no audit/model launch), from the implementation checkout:

```powershell
python -B -m pytest -q -p no:cacheprovider scripts/test_wer_windows_long_path_p0_am.py::test_wtx_safe_relative_file_rejects_case_distinct_spelling scripts/test_wer_windows_long_path_p0_am.py::test_shared_native_path_owns_extended_spelling_and_rejects_injection
```

Result: **2 passed in 0.75s**, exit code 0, no skips. The first creates an
ordinary temporary CaseDir/File.JSON and confirms rejection of a case-distinct
relative spelling. The second checks drive normalization, ordinary UNC
conversion, and rejection of caller-supplied extended namespace spellings.
These are current passing examples for two path predicates. They do not prove
full long-path execution/replay, containment, cleanup, backend parity, or all
cases identified by the historical review. Production source was not edited.

Also ran the current synthetic terminal-record enumeration test:

```powershell
python -B -m pytest -q -p no:cacheprovider scripts/test_wer_windows_long_path_p0_am.py::test_wtx_reconcile_enumerates_long_existing_phase_tree
```

Result: **2 passed in 0.59s**, exit code 0, no skips. At scratchpad lengths
238 and 270 characters, reconciliation recognized the synthetic terminal-debt
record as debt rather than missing work. The 238-character case explicitly
asserts a 259-character transaction root and a 265-character phase directory;
the 270-character case puts both beyond the legacy boundary. No provider or
model was launched. This directly tests two long-directory enumeration cases
relevant to the historical B3 issue; it is not full transaction recovery,
resume, ledger-retention, or process-closure acceptance.

### Current public long-input fixture: failed precondition

Ran:

```powershell
python -B -m pytest -q -p no:cacheprovider scripts/test_wer_windows_long_path_p0_am.py::test_public_wtx_executes_with_long_attempt_scoped_semantic_inputs
```

Result: **1 failed in 0.97s**, exit code 1. Before native execution or the
intended long-input assertion, `worker_transaction._safe_file` rejected
`<LOCAL_PYTHON>`:
the observed stat metadata had `st_nlink=2`, while the validator requires a
single link. This does not reproduce the historical long-input bug and does
not prove it fixed. Classification: public long-input runtime acceptance
remains **active-required, unproven**; fixture executable precondition failed
on the current host. The executable and its links were not modified, and the
single-link guard was not relaxed.

The harness review records identify `<PACKAGED_PYTHON>` as a separate
single-link entrypoint (distinct from `<PACKAGE_TEST_PYTHON>`). Current checks
confirmed its single link, non-reparse attributes, size 104952, and SHA-256
`4D6F5F81A4BCA11191C4C7C6B43632694D0A4CE74E068619D8FDC161D469859A`, matching
the historical entrypoint hash. This does not authenticate its whole runtime.
Reran the exact test with that existing entrypoint:

```powershell
& '<PACKAGED_PYTHON>' -B -m pytest -q -p no:cacheprovider scripts/test_wer_windows_long_path_p0_am.py::test_public_wtx_executes_with_long_attempt_scoped_semantic_inputs
```

Result: **1 passed in 0.90s**, exit code 0, no skips. The synthetic public
transaction executes with an attempt-local plan path longer than 260 characters
and validates its staged receipt on this runtime. The earlier default-Python
precondition failure remains valid evidence; this conditional pass neither
fixes that runtime layout nor closes clean-install or full lifecycle acceptance.
No runtime files, links, production source, or validation guards were changed.

### Full current Windows long-path module

Ran the full inspected synthetic module with the existing single-link runtime:

```powershell
& '<PACKAGED_PYTHON>' -B -m pytest -q -p no:cacheprovider scripts/test_wer_windows_long_path_p0_am.py
```

Result: **14 passed in 5.89s**, exit code 0, no skips. Coverage includes
259/260/261-character blob persistence and repeated receipt replay; immutable
collision rejection; long attempt-local semantic input execution; nested-root
replay at 238/270-character scratchpad lengths; long-tree terminal-debt
enumeration; case and namespace predicates; and the public incorporation
fixture at four scratchpad lengths (including injected publication crashes).
Workers in these fixtures are synthetic local Python commands, not model
providers or target audits. This is current evidence for the specified module
on this Windows/runtime combination, not a clean-install result, cross-platform
result, Claude/Codex parity result, exhaustive retention result, or full P0-AM
closure. The default-Python hard-link precondition failure remains recorded.

### Cleanup failure-path checks

Using `<PACKAGED_PYTHON> -B -m pytest -q -p no:cacheprovider`, ran
these exact nodes in `scripts/test_owned_directory_guard_p0_am.py`:

- `test_corrupt_ledger_never_becomes_cleanup_success`
- `test_invalid_zero_authority_is_rejected_before_namespace_mutation`
- `test_startup_reconciliation_fails_closed_on_corrupt_guard_ledger`

Result: **3 passed in 0.58s**, exit code 0, no skips. Fixtures create only
temporary owned directories and synthetic ledgers. Corrupted journal input is
rejected during direct recovery and startup reconciliation, while the fixture
root remains present. Malformed zero-population evidence is rejected before
ledger creation. The fixture's valid-looking digest is synthetic: these tests
do not establish actual OS process population or production closure authority.
They also do not implement or validate historical ledger retirement.

After inspecting the remaining fixtures, ran the complete module:

```powershell
& '<PACKAGED_PYTHON>' -B -m pytest -q -p no:cacheprovider scripts/test_owned_directory_guard_p0_am.py
```

Result: **14 passed in 0.83s**, exit code 0, no skips. This additionally covers
temporary nested/read-only cleanup, link-target preservation, retained-root
rename rejection on Windows, quarantine collision preservation, replay after
four injected cleanup-stage crashes, Windows ABI layout, and interrupted
startup recovery. The link fixture actually ran (was not skipped). Recovery
receipts are asserted not to grant completion authority. Cleanup removed only
disposable fixture-owned temporary content, not user runtime directories.
These module-level results still do not establish historical ledger retirement,
actual process-population proof, or full lifecycle integration.

### Process timeout and failed-cleanup retry evidence

Ran with the same single-link runtime and pytest flags:

- `scripts/test_worker_execution_receipts.py::test_timeout_terminates_the_owned_process_tree_before_returning`
- `scripts/test_worker_transaction_contracts_p0_am.py::test_recovery_blocks_retry_when_persisted_scope_cleanup_fails`

Result: **2 passed in 1.74s**, exit code 0, no skips. Timeout fixture launches
synthetic Python parent/child commands, asserts bounded return, absence of a
delayed marker, and a process-tree-terminated debt observation. Recovery fixture
injects a process-scope recovery exception and checks blocked work with no retry.

Evidence limitations from source inspection: the timeout fixture has no child
startup handshake, so it does not independently prove the child existed before
the 50-ms timeout. Marker absence alone also cannot distinguish termination
from inability to write. The recovery fixture mocks cleanup failure and is not
an actual populated-cgroup test. These passing tests therefore do not close
exhaustive descendant-closure or cross-OS acceptance.

Follow-up source inspection found
`scripts/test_worker_process_tree_adversarial_review.py::test_clean_parent_exit_cannot_leave_background_descendant`.
It likewise starts a delayed child and checks marker absence, without a
child-ready acknowledgement or independent child-handle wait assertion.
Thus this named fixture does not close the readiness evidence gap either.
No claim is made that all process tests lack stronger coverage: the targeted
search and this inspection are not an exhaustive suite audit. A closure-quality
test needs evidence the child started, could write within its assigned scope,
and is no longer alive before authoritative completion—not marker absence alone.

Subsequently located stronger low-level evidence and ran:

```powershell
& '<PACKAGED_PYTHON>' -B -m pytest -q -p no:cacheprovider scripts/test_owned_process_scope_job_only.py::test_windows_job_only_terminates_detached_grandchild_and_proves_zero
```

Result: **1 passed in 0.52s**, exit code 0, no skips. A synthetic parent records
its detached descendant's PID after creation; the observer confirms that PID
is running before job termination. After termination/close, the fixture checks
that the descendant is not running and the job reports population zero. This
is stronger than marker absence and supplies direct current evidence for this
Windows Job-only containment case. The fixture explicitly asserts write
confinement is NOT provided. It is not evidence of model-provider integration,
full transaction publication ordering, default low-integrity mode, all process
failure paths, or cross-OS closure. PID-based observation also does not retain
one process handle across the entire before/after interval.

Ran the full inspected Job-only module with the same runtime:

```powershell
& '<PACKAGED_PYTHON>' -B -m pytest -q -p no:cacheprovider scripts/test_owned_process_scope_job_only.py
```

Result: **6 passed in 0.65s**, exit code 0, no skips. In addition to detached
descendant termination, this covers capability declarations, isolated module
loading with a mocked native handle, rejection of write-lease inputs before job
creation, default-mode lease acquisition with a mocked lease, and two live
Job-only scopes without a shared low-integrity lease. Mocked cases are not
native integration evidence. This module does not establish that every
production launcher uses the intended scope or that default-mode concurrency
can safely be increased.

### Created-but-not-attached process cleanup

Using the same runtime and pytest flags, ran these nodes from
`scripts/test_owned_process_scope_launch_state_p0_am.py`:

- `test_real_created_process_cleanup_is_cross_platform_and_close_safe`
- `test_created_process_cleanup_timeout_or_error_never_mints_proof`

Result: **3 passed in 0.53s**, exit code 0, no skips (the second node has two
parameters). The native fixture creates a local sleeping Python process with
the default scope, terminates the exact created process before attachment,
checks exit, and closes the scope. The two mocked cases inject wait timeout
and kill failure and assert no termination proof is granted. Despite the first
test's name, this execution occurred only on Windows; it supplies no Linux or
macOS run evidence. No model/audit worker was launched.

### Combined current infrastructure regression run

To check for interference within one pytest process, ran all three complete
modules and the four additional selected nodes together:

```powershell
& '<PACKAGED_PYTHON>' -B -m pytest -q -p no:cacheprovider scripts/test_wer_windows_long_path_p0_am.py scripts/test_owned_directory_guard_p0_am.py scripts/test_owned_process_scope_job_only.py scripts/test_worker_execution_receipts.py::test_timeout_terminates_the_owned_process_tree_before_returning scripts/test_worker_transaction_contracts_p0_am.py::test_recovery_blocks_retry_when_persisted_scope_cleanup_fails scripts/test_owned_process_scope_launch_state_p0_am.py::test_real_created_process_cleanup_is_cross_platform_and_close_safe scripts/test_owned_process_scope_launch_state_p0_am.py::test_created_process_cleanup_timeout_or_error_never_mints_proof
```

Result: **39 passed in 8.16s**, exit code 0, no skips. These are 39 distinct
parameterized cases, not the sum of repeated invocations documented above.
They passed together in this order on the existing Windows harness runtime.
All previously stated fixture limitations remain. No production source was
changed, no model provider was launched, and no E2E or full-goal closure follows
from this selected infrastructure regression result.

Post-run SHA-256 snapshot of selected source/test files under `scripts/`:

```text
3192B834650F7B3EDD35A7155597718D76645F6A33FF1143A2EF2FAA8B38406A rooted_path_io.py
1A7ECC763C2BAFC55FCB1217FA303D63A3AC381F2A714CC6C15B7ABDBB94F43F owned_directory_guard.py
049EBF8240C8EE7DE26D3BC696BFF8289AF76ABBDDB669155BD3271BA799858D owned_process_scope.py
4200E17CFA4D0964344F544D8A8C8DD559E7669581E992097857A13BA3F91AC7 worker_execution_receipts.py
736CBC0B024D2586AA6513DB1404FF76FA507B5B574DCD7DED7217B400D8B610 worker_transaction.py
4A2A7C97701566FAA81D6186D490C824727F88A7A1B11EE4BA8FDAF26D2CAF00 test_wer_windows_long_path_p0_am.py
4C270EC64EB3459E70250676C0D8622FE1000FF668CC6E4A5A19B33B12205ADF test_owned_directory_guard_p0_am.py
2461DEA5B89D244E20004FBAA4F45E96EF468AD175E275AB197E524BD4AFF6A1 test_owned_process_scope_job_only.py
A937502B0010656996D942A3812E10861D17EBABB40E256A2DA54D0A8FE8FF44 test_worker_execution_receipts.py
6D63183A85C3FF50CC2A8D4631AF4E59ABAF4D83BA76A18D5CC62BA601FA30B0 test_worker_transaction_contracts_p0_am.py
601E86155075055BCE16B64AB3DCB5FA3F6FDC980CB0F340190A3150C5A91D3A test_owned_process_scope_launch_state_p0_am.py
```

This is a selected post-run snapshot, not a complete dependency manifest or
an atomic pre/post execution seal. The three files also hashed before testing
(WER, WTx, and the long-path test module) retained those same hashes. A future
change to any relevant source, fixture, or runtime requires fresh validation;
these counts must not be carried forward as current proof automatically.

### Bounded-enumeration change preparation blocked by source governance

Current inspection confirms cleanup reconciliation materializes every scandir
entry into a list before checking `_MAX_RECONCILIATION_LEDGERS`. An attempted
new regression test would require stopping after limit+1 observed entries.
Pytest rejected the modified test module during collection with a fast-lane
governance source-hash mismatch; **no tests ran**, so no red reproduction was
established. The collection hook loads source-bound governance unconditionally.

Removed only this newly added test, restoring its exact prior SHA-256
`4C270EC64EB3459E70250676C0D8622FE1000FF668CC6E4A5A19B33B12205ADF`.
Production code and governance manifests were not changed. The bounded-memory
enumeration issue remains active-required and unfixed. Next implementation work
must first establish the supported source-governance successor workflow; the
manifest must not be silently rebased as proof of independent acceptance.

### Bounded-enumeration development fix

Reviewed the R75 source-governance successor author receipt, which separates
fixture acceptance from central manifest admission. Left the existing governed
test module and all governance files unchanged. Added a new development module,
`scripts/test_owned_directory_reconciliation_bounds.py`, collected with normal
conftest enabled. Its bounded iterator regression failed against the old source:
**1 failed in 0.46s** (four entries consumed where limit+1 was three).

Changed `owned_directory_guard.reconcile_owned_directory_cleanup_ledgers` to
check the count inside enumeration, retaining at most the configured limit of
paths and inspecting at most one extra entry before rejecting overflow. The
error code/message and pre-recovery rejection remain unchanged. No ledger
deletion, retirement, or runtime policy was added.

Normal-conftest run of the new module plus the existing owned-directory module:
**15 passed in 1.23s**, exit code 0, no skips. Classification: bounded-enumeration
fix implemented with focused development proof; independent review, broader
regression, and release/test-roster admission remain unproven. The earlier
39-case result predates this production source edit and must not be represented
as validation of the modified source until rerun.

Reran the exact combined infrastructure command above with
`scripts/test_owned_directory_reconciliation_bounds.py` added as its first
selector: **40 passed in 8.50s**, exit code 0, no skips, normal conftest enabled.
This replaces the 39-case pre-edit observation for the selected regression
scope only. Current hashes:

- `scripts/owned_directory_guard.py`:
  `5E101B6D69A17EB867D2E77FDF2E14B27B0088764DC3D984ACD65D5A44DEA86C`
- `scripts/test_owned_directory_reconciliation_bounds.py`:
  `8E97BFFEFDBEA42F1D2154EB2386CD80715D43B51B742D011FA0088827E016F2`
- Existing governed cleanup fixture remains:
  `4C270EC64EB3459E70250676C0D8622FE1000FF668CC6E4A5A19B33B12205ADF`

The source and new test are untracked in this pre-existing worktree; therefore
`git diff --check` provides no useful whitespace proof for those files. No
release-roster acceptance or independent review is inferred from collection
and execution success.

Extended the new bounded-enumeration test module with an exact-limit case:
one real terminal cleanup ledger with the limit set to one is accepted,
reported terminal without recovery, and remains byte-identical. Strengthened
overflow coverage to fail if ledger replay or cleanup recovery is invoked.
The two new-development cases plus the existing cleanup module passed together:
**16 passed in 1.29s**, exit code 0, no skips, normal conftest enabled. The
production fix was unchanged; the new test module's previously recorded hash
is historical after this extension. Temporary owned fixture content only was
removed during setup of the terminal-ledger case. No user runtime data was
deleted, and the fixture uses synthetic process-zero evidence.

Final combined development regression after the exact-bound extension:
**41 passed in 8.60s**, no skips, normal conftest enabled, using the same
combined command including `test_owned_directory_reconciliation_bounds.py`.
Post-run production SHA remains
`5E101B6D69A17EB867D2E77FDF2E14B27B0088764DC3D984ACD65D5A44DEA86C`;
the final new-test SHA is
`B2C51E22A063CCB58DFD12F6CFB0CAB8F29718FFCEE3DEB5C62209B46CA06BD5`.
This is the current selected regression result for the enumeration fix.
It does not supersede any unrelated open acceptance requirement or confer
independent review/release acceptance.

### New reproduced long-directory false-absence defect

Host registry reports `LongPathsEnabled=0`. Added a real Windows boundary
fixture in the new development test module which creates an empty, existing
270-character ledger directory through its native path spelling, calls public
cleanup reconciliation with the ordinary spelling, and requires
`directory_present=True`. The directory is a checked child of pytest's
temporary root and is removed nonrecursively in a finally block.

Exact test:
`scripts/test_owned_directory_reconciliation_bounds.py::test_existing_long_ledger_directory_is_not_reported_missing`
using the same runtime/normal-conftest flags. Result: **1 failed in 0.50s**.
Reconciliation incorrectly returned `directory_present=False` even though the
native directory existence assertion passed. This is a currently reproduced
false-absence defect, separate from the fixed enumeration bound. Classification:
**active-required, missing fix**. The new red test remains in the development
module; the prior 41-case result predates it and does not cover this defect.
No production fix for long-directory reconciliation is claimed yet.

Follow-up path trace identifies multiple legacy-path operations in the same
cleanup subsystem: reconciliation uses `os.path.lexists(directory)`,
`directory.lstat()`, raw `os.scandir(directory)`, and `path.lstat()`;
`_ledger_records` uses `path.lstat()` and `path.read_bytes()`; stage append uses
`os.path.lexists(path)` and raw `os.open(path, ...)`. The existing shared
`rooted_path_io` module provides native-path conversion, lstat, existence,
and bounded checked-handle reads. Therefore an empty-directory-only fix would
not establish nonempty ledger replay or interrupted cleanup support. Required
next validation includes a valid terminal ledger and interrupted cleanup under
long paths, in addition to the existing empty-directory red fixture. Do not
claim long-path closure from fixing only the initial absence predicate.

### Long-ledger development repair and runtime evidence

Added terminal-ledger and interrupted-at-INTENT_DURABLE cases with a real
270-character ledger directory. Before the repair, the two cases failed in
private-directory setup and the empty-directory case failed its presence
assertion: **3 failed, 2 deselected in 0.69s**.

Migrated the guard's ledger directory creation/stat, ledger read/append,
existence checks, reconciliation enumeration/stat, and Windows absolute-handle
and volume queries to the existing shared native-path conversion. Kept logical
ledger paths unprefixed when deriving entries from native enumeration. Reads
now stop at the byte bound plus one and reject overflow rather than reading
unbounded bytes after a pre-read stat. Retained-handle cleanup, identity checks,
and completion-authority rules were not relaxed.

New development plus existing cleanup modules: **19 passed in 1.48s**.
Full selected combined infrastructure run: **44 passed in 8.84s**, exit code 0,
no skips, normal conftest enabled, same single-link Python runtime. These runs
exercise empty-directory presence, valid terminal-ledger reconciliation, and
recovery/appending after an injected interruption with long ledger paths, plus
the preceding infrastructure cases. Only synthetic temporary fixture content
was removed. Classification: implemented with current development evidence;
independent review, packaging/cross-OS validation, and release admission remain
unproven. No historical ledger retirement or audit relaunch was performed.

### Packaging validation failed before import

Ran the inspected public archive test with normal conftest and the same runtime:

```powershell
& '<PACKAGED_PYTHON>' -B -m pytest -q -p no:cacheprovider scripts/test_public_packaging_freeze.py::test_clean_archive_compiles_and_imports_runtime_from_itself
```

Result: **1 failed in 14.92s**, exit code 1. Archive construction rejected a typed
asset digest mismatch for `scripts/artifact_ledger.py`. Compilation and isolated
imports were not reached; this result neither proves nor disproves availability
of the cleanup guard's new shared-path import in the package. The fixture uses
a temporary Git index/archive; no commit or external publication was performed.
No asset hash was rebased, and `artifact_ledger.py` was not edited during this
work. Classification: packaging acceptance remains **active-required, failed**,
with artifact identity reconciliation needed before this test can pass.

Read-only comparison of the failed archive's `scripts/artifact_ledger.py`
against the current worktree found byte-for-byte equality. Under the declared
`utf8-lf-v1` digest mode, both hash to
`54e6091b7465f4cf9376e3f0bef0fcb429fbbcded572afb8f60512c0e31fa9c9`, while the
runtime asset row expects
`5df195c3e0b769b06cf6907a0287cc59622de7a2dc509b0dabd18a66bdf017db`.
Thus the observed failure is declaration/current-source identity drift, not
packaging corruption of this member or a line-ending-only discrepancy. Which
source revision should be admitted still requires change-history and authority
review; updating the expected digest alone would not establish that.

Checked all 293 currently declared runtime asset rows against worktree bytes,
applying each row's declared digest mode. Found 11 digest mismatches and no
read/decode errors: `artifact_ledger.py`, `attention_repair_shards.py`,
`audit_snapshot.py`, `fuzz_workspace_authority.py`, `headless_worker_runtime.py`,
`owned_directory_guard.py`, `phase_io_contracts.py`, `plamen_driver.py`,
`plamen_validators.py`, `program_facts_source_manifest.py`, and
`worker_transaction.py` (all under scripts/). This is a declared-roster check,
not proof that the roster includes every runtime dependency.

The owned-directory guard mismatch includes this work's two reliability fixes;
its current declared-mode digest is
`0d753ee5b6c39d305865b5ee15d984fe1811e93e297bba96b59fcd5803472d67`, versus
declared pre-fix `1a7ecc763c2bafc55fcb1217fa303d63a3ac381f2a714cc6c15b7abdbb94f43f`.
The other ten files were not edited in this continuation's cleanup work. All
11 identities require explicit reconciliation before packaged-runtime
acceptance; passing the first mismatch alone would not close the package gate.

Direct read-only inspection of the already-created failed archive confirms both
`scripts/owned_directory_guard.py` (84,574 bytes) and `scripts/rooted_path_io.py`
(91,055 bytes) are regular archive members and byte-exact matches to the current
worktree. Their raw SHA-256 values are respectively
`0d753ee5b6c39d305865b5ee15d984fe1811e93e297bba96b59fcd5803472d67` and
`3192b834650f7b3edd35a7155597718d76645f6a33ff1143a2ef2faa8b38406a`.
This establishes inclusion of this immediate import dependency only. No archive
extraction or import execution was performed in this check, and the typed asset
identity gate remains failed.

Extended long-ledger lifecycle coverage to a second layout where the retained
parent path itself is 270 characters and both the owned root and ledger
directory are longer. Both normal completion and interrupted cleanup recovery
passed in both layouts. Native-spelling existence checks verify the long owned
root is actually absent after cleanup; legacy Path.exists is not used for this
assertion. The updated development module plus the existing cleanup module:
**21 passed in 1.54s**, exit code 0, no skips, normal conftest. Production source
was unchanged in this test extension. This adds retained-parent/owned-root
long-path evidence, but does not resolve the package identity gate.

Reviewed current pytest lane rules: unclassified modules default to the unit
lane, whose documented contract excludes real I/O. Marked the new regression
module explicitly `integration` because it exercises real temporary filesystem
and native directory handles; marked the Windows-specific cases `windows_only`.
No conftest/manifest or existing test markers were edited. Explicit integration
execution of this module passed **7 tests in 0.72s**, exit code 0, no skips.
This corrects development-test lane placement; it does not claim acceptance of
the expanded full release roster or cross-platform execution.

Added a bounded-read regression for synthetic ledger growth between metadata
inspection and open. With a 128-byte test bound, the file grows from one to
256 bytes; the reader requests exactly 129 bytes and rejects overflow before
parsing. The fixture records that bounded read size and confirms the file
remains 256 bytes (the reader does not truncate it). The new integration module
now passes **8 tests in 0.77s**, no skips. This proves the size-bound branch for
the injected growth case, not general concurrent file identity/race safety.

Latest combined selected infrastructure result, including all eight new
development integration cases: **47 passed in 9.13s**, exit code 0, no skips,
normal conftest enabled, same combined command and single-link runtime.
Post-run raw SHA-256:

- `owned_directory_guard.py`:
  `0D753EE5B6C39D305865B5EE15D984FE1811E93E297BBA96B59FCD5803472D67`
- `test_owned_directory_reconciliation_bounds.py`:
  `FC5553AD4EA6E4D071B3F923B1600655F57AA2C01725595DD8AEC49F22DFCD9A`

This supersedes earlier selected-test counts for the current development
snapshot only. Packaging remains failed on declared asset identities, p18
remains a failed end-to-end attempt, and independent acceptance/retention work
remain open. No whole-goal completion or release readiness is claimed.

### Inaccessible-directory false-absence repair

A new metadata-permission-error regression failed before the change:
**1 failed in 0.52s**, because reconciliation returned the missing-directory
result instead of raising. `os.path.lexists` suppresses filesystem access
errors. Replaced the initial existence predicate with explicit native-path
lstat: only FileNotFoundError produces the missing-directory result; other
OSError cases raise RECONCILIATION_DIRECTORY_UNAVAILABLE. The same inspected
metadata row is used for directory-type validation.

New development plus existing cleanup tests: **23 passed in 1.63s**, exit code
0, no skips, normal conftest. The permission failure is injected, not an actual
Windows ACL alteration. No ACLs or user directories were changed. Broader
regression and final hashes must be refreshed after this production edit;
the prior 47-case result applies to the preceding source snapshot.

Added a genuine-missing-directory case asserting the explicit empty result,
zero counts, no completion authority, and no directory creation. Reran the
combined infrastructure selection: **49 passed in 9.38s**, exit code 0 confirmed,
no skips, normal conftest enabled. Post-run hashes:

- `owned_directory_guard.py`:
  `133193974894384C095F2C9A28F661771B5C7ECA954DC69A6E8B29191E5BB851`
- `test_owned_directory_reconciliation_bounds.py`:
  `75D4BDE91204272638B4A8105A048D88D59675E98D78D70FE49F4C4A8083A95D`

This is the current selected development regression result. Existing package
identity declarations were not changed; their cleanup-guard mismatch now refers
to this newer source. Independent acceptance, retention, and E2E remain open.

### Outer startup caller-boundary checks

Inspected and ran these nodes from
`scripts/test_auxiliary_writable_root_recovery_p0_am.py` with the same runtime
and normal-conftest pytest flags:

- `test_profile_lifecycle_recovery_precedes_outer_orphan_cleanup`
- `test_profile_lifecycle_recovery_failure_blocks_outer_orphan_cleanup`

Result: **2 passed in 0.63s**, exit code 0, no skips. The outer startup code
invokes the profile cleanup boundary before orphan-root removal; an injected
profile-recovery error denies new leases and preserves the temporary root's
sentinel. These tests mock the profile reconciler and owner-death observation,
so they prove caller ordering/error handling, not the actual long-path helper
through the full startup stack. Temporary fixture namespace only was used.

### Real profile-inventory failure through startup

Added `test_startup_real_invalid_profile_inventory_preserves_outer_root`
to `scripts/test_owned_directory_reconciliation_bounds.py`. This uses an
actual temporary lease, registry lock, and profile reconciler. An unexpected
file in the profile ledger directory causes startup to return
`PROFILE_LIFECYCLE_RECOVERY_UNPROVEN` and `DENY_NEW_LEASES`. Both the outer-root
sentinel and invalid inventory file remain unchanged. Owner inspection and
outer cleanup are replaced with forbidden-call assertions; neither is reached.
No process, provider, model call, or user runtime namespace is used.

Command: `<PACKAGED_PYTHON> -B -m pytest -q -p no:cacheprovider scripts/test_owned_directory_reconciliation_bounds.py`
from the implementation repository. Result: **11 passed in 0.88s**, exit 0,
normal conftest, no skips. This adds actual helper-to-caller failure-path
integration evidence; it does not establish successful full-stack recovery,
long-path startup integration, production retention, or backend E2E acceptance.
Production code was unchanged in this continuation. The previous test-module
hash no longer describes the expanded module; the previous 49-case combined
run remains evidence for its earlier test selection, not a rerun of this case.

### Real startup replay and interrupted-cleanup idempotence

Added two cases of `test_startup_real_profile_replay_is_idempotent` to the
development reconciliation module. With only the runtime namespace redirected
to a pytest temporary directory, these exercise the real startup registry lock,
profile reconciler, ledger replay, and cleanup implementation. One starts with
a terminal ledger; the other injects `INTENT_DURABLE` interruption. First startup
reports one terminal ledger, recovers exactly the interrupted case, and confirms
the synthetic profile directory is absent. A second startup reports zero new
recoveries, preserves terminal ledger bytes exactly, and does not recreate the
directory. Both reports retain `completion_authority: false` in profile details.

The guard receives synthetic subject/zero-population digests; no worker process
exists. These tests do not prove process-evidence issuance, whole-provider crash
recovery, outer orphan-lease disposal, or long-path startup integration.

Expanded module: **13 passed in 1.12s**. Repeated the previously documented
combined infrastructure command with the expanded module: **52 passed in 9.60s**,
exit 0 confirmed, no skips, normal conftest. This supersedes the 49-case selected
regression count for this development snapshot, not any full acceptance claim.
Production source was unchanged. Current raw SHA-256:

- `owned_directory_guard.py`: `133193974894384C095F2C9A28F661771B5C7ECA954DC69A6E8B29191E5BB851`
- `test_owned_directory_reconciliation_bounds.py`: `CEC7365C026E0CB9B0501D233339BBB35CB15A2768D5DCBC3995189A56A526A3`

Only synthetic temporary profile directories were removed by the cleanup under
test; no user runtime directories were removed. Packaging declarations, retention
policy, audit phases, and backend acceptance were not altered. Full goal remains
unproven and active.

### Retention requirement: terminal records can exhaust startup inventory

Current-source inspection distinguishes two stores: profile guard ledgers in
`owned_directory_guard.py`, and outer lease journals handled by
`auxiliary_writable_root_lease.py::_compact_terminal_journal`. The latter moves
an exact terminal journal to its archive; it does not retire profile guard
ledgers. Profile reconciliation counts all directory entries before replay,
with `_MAX_RECONCILIATION_LEDGERS = 10_000` and a 512 MiB aggregate byte bound.
Terminal profile ledgers remain inputs on later startup.

Added `test_startup_terminal_ledger_accumulation_denies_new_leases`: creates two
actual terminal guard ledgers, confirms their synthetic roots are absent, lowers
the test-only count bound to one, and invokes real startup. Startup returns
`DENY_NEW_LEASES` / `PROFILE_LIFECYCLE_RECOVERY_UNPROVEN`; both ledger byte strings
are preserved. This is a passing characterization of an unresolved operational
debt, NOT a passing retention acceptance test. It reproduces the count-bound
branch at small scale, not a 10,001-file production load test.

Expanded module: **14 passed in 1.12s**, exit 0, no skips, normal conftest. No
production limit, deletion policy, archive, or runtime data was changed. The
earlier 52-case combined run was not rerun after this test addition.

Scoped requirements classification (supplements, does not replace, full ledger):

| Requirement | Classification | Evidence / remaining acceptance |
|---|---|---|
| Bounded startup guard-ledger enumeration | implemented-and-proven, scoped | Limit-plus-one enumeration test and actual startup overflow characterization; not long-duration storage boundedness |
| Preserve ambiguous cleanup evidence and deny unsafe allocation | implemented-and-proven, scoped | Invalid-inventory and terminal-overflow startup tests preserve files; full process ownership scenarios remain separately required |
| Sustainable profile-ledger retention | active-required; implementation not established | Current terminal accumulation reaches the startup denial branch. Needs reference-aware retirement/archival contract, replay compatibility, crash recovery, and bounded repeated-cycle evidence |
| Outer journal compaction substitutes for profile-ledger retention | not a valid supersession | Different stores and caller paths; no equivalence evidence |

The retention requirement comes directly from the active user objective's
lifecycle/retention and operational-resilience scope. The historical July 17
goal ledger's evidence rule also requires integrated and resume evidence before
DONE; the selected development tests do not satisfy that rule in full. No
historical requirement is declared superseded by this entry. A safe retention
change must first establish which consumers still require exact ledger paths,
heads, and bytes; a count threshold alone is not deletion authority.

### Retention consumer mapping

Recorded a bounded source-reference map and required acceptance constraints in
`<LOCAL_VALIDATION_WORKSPACE>\cleanup-ledger-retention-contract.md`.
Direct inspection confirms exact-path replay in guard receipt reconstruction
and Claude profile revocation, plus recovery parent resolution relative to the
ledger directory. Moving unchanged ledger bytes is therefore not sufficient
proof of compatible recovery. Five materialization call sites were located by
text search but not individually validated; dynamic/external consumer coverage
is not claimed. The document is design-only, not an implemented retirement
policy. No production files or runtime data changed in this continuation.

### Disk-full failure before durable cleanup intent

Added two cases of
`test_disk_full_before_durable_intent_preserves_root_and_denies_startup`
to the development reconciliation module. Real guard and startup code run in a
temporary namespace. The only I/O failure injection is scoped `os.write`:
ENOSPC either immediately, or after an actual 17-byte partial ledger write.
Cleanup raises `OwnedDirectoryGuardError` instead of returning a success
receipt. The original synthetic root/sentinel remains intact. On subsequent
real startup, the zero-byte or truncated ledger causes
`PROFILE_LIFECYCLE_RECOVERY_UNPROVEN` and `DENY_NEW_LEASES`; ledger bytes and
sentinel remain unchanged.

Module result: **16 passed in 1.20s**, exit 0, no skips, normal conftest, using
the documented single-link interpreter. This proves these two injected
pre-intent failure branches, not physical disk exhaustion, fsync/power-loss
durability, later-stage failures, or automatic recovery from truncated intent.
Persistent denial for damaged evidence remains explicit debt, not a claimed
operational recovery solution. No production code or runtime files changed;
the full combined selection was not rerun after these additions.

### Read-only entry-capacity advisory

Extended the external `<LOCAL_VALIDATION_WORKSPACE>/inspect_lifecycle_retention.py`
diagnostic with an explicit runtime entry limit separate from its scan limit.
It reports an advisory at 80 percent, distinguishes reached/exceeded capacity,
and never computes remaining capacity from an incomplete inventory. Scan
overflow contributes the one extra observed entry to a lower bound only.
The default 10,000 limit is labelled a source-snapshot/operator-supplied value,
not automatically synchronized production configuration. The advisory does not
claim semantic replay, safe deletion, byte-capacity acceptance, or startup health.
CLI exit status retains its inventory-completeness/issue meaning; warnings are
reported in JSON, not a new exit-code contract.

Standalone unittest result: **10 passed in 0.029s**, exit 0. Fresh read-only scan
of the existing profile lifecycle directory: 2,018 entries, 11,936,989 logical
bytes, no metadata issues, 7,982 remaining entries against the declared 10,000
limit; below the advisory threshold. This does not prove safe long-term retention
or attribute previous C-drive exhaustion. No ledger contents were read or changed.
The diagnostic remains external, not integrated into production startup or
release packaging; operational warning integration remains active-required.

### Preserve typed startup failure diagnostics

Production change in `scripts/auxiliary_writable_root_lease.py`: profile recovery
failure details now append the guard's typed error code when it matches the
bounded `[A-Z][A-Z0-9_]{0,95}` grammar. Top-level reason, allocation denial,
runtime debt, and cleanup ordering remain unchanged. Arbitrary exception
messages and malformed codes are not exposed. Existing report replay accepts
the enriched detail and validates its newly computed report digest.

The actual terminal-overflow fixture first failed because the detail omitted
`RECONCILIATION_ENTRY_BOUND` (1 failed in 0.86s). After implementation, an
incorrect test assumption that replay returns the entire input report failed;
corrected the assertion to the replay API's `valid` result. Added four code
redaction cases (valid, path-like, overlength, None). Final selected run:
**21 passed in 1.78s**, exit 0, no skips, normal conftest; development module plus
existing profile-failure caller test. Broader regression remains required.

This is an observability repair, not retention or recovery completion. It adds
another changed production asset whose governed packaging identity must be
reviewed; no expected hashes were rebased, no package acceptance was claimed,
and no audit worker or live cleanup was launched.

### Post-diagnostics combined regression snapshot

Result: **61 passed in 10.65s**, exit 0 confirmed after polling the exact test
session, no skips, normal conftest. The selection is the previously documented
combined infrastructure command with the now-20-case development module plus
both existing startup caller nodes:
`test_profile_lifecycle_recovery_precedes_outer_orphan_cleanup` and
`test_profile_lifecycle_recovery_failure_blocks_outer_orphan_cleanup` from
`scripts/test_auxiliary_writable_root_recovery_p0_am.py`.

Post-run raw SHA-256:

- `scripts/owned_directory_guard.py`: `133193974894384C095F2C9A28F661771B5C7ECA954DC69A6E8B29191E5BB851`
- `scripts/auxiliary_writable_root_lease.py`: `FBBA922E4B14D3C00671E9E0DFF4D1655B890F20502E018957072DB5118B4574`
- `scripts/test_owned_directory_reconciliation_bounds.py`: `15B075017BB4F9A418992DCDD29AE3A13F193A605A91BA2D61B5EA6FA65E4C8D`

All three paths are currently untracked in the existing implementation worktree;
an empty `git diff --stat` for them is not proof of no changes or review. Hashes
identify the tested files but do not admit them into governed packaging. This
supersedes earlier selected regression counts for the current development
snapshot only. Retention, packaging acceptance, full-corpus reconciliation,
independent review, and backend E2E acceptance remain open. No whole-tool
completion or production-ready claim follows from these 61 tests.

### Corpus discovery and reconciliation status index

Created external `<LOCAL_VALIDATION_WORKSPACE>/downloads-corpus-inventory-2026-09-06.json`:
127 immediate Downloads entries with Plamen in their names, 5,210,228 bytes,
SHA-256 identities. Also created `requirements-reconciliation-status.md` to
separate scoped implemented evidence from active missing work, explicit
benchmark deferral, and safety-restricted unfulfilled work. No filename/version
ordering is treated as supersession authority. Nested Downloads and canonical
repository corpus enumeration, source interpretation, and per-requirement
reconciliation are not complete. The inventory captured this mutable addendum
before the present append, so its addendum hash is historical, not current.

### Historical missing-artifact observation corrected

Read the July 24 plan completion audit fully and checked all seven Section 6
named artifact paths. All exist now; source hashes and sizes are recorded in
`<LOCAL_VALIDATION_WORKSPACE>/requirements-reconciliation-status.md`. Read both short
compatibility redirects and checked relevant RFC section headings. Historical
absence is no longer a valid current-state claim, but semantic equivalence,
runtime reachability, independent acceptance, and full requirement coverage
remain unverified. No production source changed and no requirement was closed.

### Diagnostic compatibility correction from canonical RFC review

Read RFC storage/migration, rollback, conformance, and migration-debt sections.
Recorded their retention constraints in the external retention contract. The
documented machine-readable compatibility rule prompted correction of the
recent diagnostic change: preserve the original detail `reason` exactly and
place a validated code in optional `cause_code` instead. Invalid codes remain
omitted; no exception message is exposed. Top-level failure and denial are
unchanged. Existing detail replay permits the additional field, and report
digest validation passes. This does not prove every external consumer accepts
new optional fields; broader compatibility remains required.

Focused result after this production correction: **21 passed in 1.27s**, exit
0, no skips, normal conftest. Tests assert exact old reason strings, optional
code presence/omission, actual count-bound code, and valid replay. Prior
61-case results and auxiliary-root/test hashes apply to the preceding snapshot
and must be refreshed before claiming broader current regression. No manifests
were rebased and no new retention/deletion authority was introduced.

### Optional diagnostic field integrity and regression refresh

Extended the valid-code fixture: changing or removing `cause_code` without
updating the report digest causes replay rejection. A synthetic legacy-shaped
report without that optional field, issued with its own correct digest, still
replays. This proves current replay schema compatibility and digest coverage,
not authenticity against an adversary able to reissue hashes or acceptance by
every external consumer. No historical production report was modified.

Repeated the exact 61-node combined selection documented above on the corrected
source: **61 passed in 10.22s**, exit 0 confirmed, no skips, normal conftest.
Post-run raw SHA-256:

- `scripts/auxiliary_writable_root_lease.py`: `FE96ACC26A75007FC1E68255303F6E64C743DC75A5576CD1C724013A45C5CE7F`
- `scripts/test_owned_directory_reconciliation_bounds.py`: `AAA8E0B195A4E318B678C145890CFFCC846C4B36101AB3008383C51D27F9BF41`

This supersedes the preceding auxiliary-root/test hashes and selected regression
snapshot. It does not change packaging admission, independent acceptance, or
the full-goal status. No provider calls, audit execution, or runtime cleanup
occurred; all fixture filesystem changes were under temporary test roots.

### External inventory Windows long-path repair

A real 270-character temporary-directory fixture reproduced the external
inspector's failure: `DIRECTORY_UNREADABLE` / `FileNotFoundError` for an existing
directory (1 unittest failed in 0.006s). Updated only the external diagnostic
to use native extended paths for root metadata and enumeration, while retaining
the logical display path. Fresh per-entry stat uses scandir's native paths.
All existing type, hardlink, naming, size, and count checks remain.

Standalone result after repair: **11 tests passed in 0.033s**, no skips, exit 0.
The long-path fixture confirms one eight-byte ledger is inventoried and its
contents unchanged. It removes only its own exact temporary ledger and empty
directory. UNC shares and cross-OS execution are not validated by this run.
No production package source or live runtime data changed; this remains an
external diagnostic, not production monitoring integration or retention closure.

### Full numbered worker-lifecycle checklist indexed

Read the P0-AM forensic source completely and mapped all 24 Section 7 cases in
`<LOCAL_VALIDATION_WORKSPACE>/worker-lifecycle-acceptance-map.md`. The index distinguishes
scoped Windows substrate evidence from unverified backend, publication, sandbox,
and parent/child lifecycle acceptance. Every numbered case remains active-required
at its full scope. Other source requirements and eleven migration steps are
explicitly retained for further reconciliation. This is requirements/evidence
mapping progress, not a new runtime test or lifecycle completion claim.

### Static lifecycle ratchet failure

Inspected and ran the raw-launch warning inventory and the narrow Claude-headless
source check: **1 failed, 1 passed, 1 warning in 18.27s**, exit 1. The fixed-file
AST baseline rejects two installed-front assertion subprocess sites in the
driver. Both complete functions were read; they are native admission probes,
not direct model audit launches. Their timeout/captured pipes do not by themselves
establish full child ownership or bounded output. Scope limits, exact nodes,
and observations are recorded in `worker-lifecycle-acceptance-map.md`, item 20.
No exemption was added, no baseline relaxed, and no probe or model was launched.

### Native captured-output storage debt

Inspection of the generic owned-process runner shows output captured to temporary
files and truncated only when returning decoded tails. The existing returned-text
test does not prove bounded spool storage. Added a local 10,000-byte file fixture
calling the real tail helper: less than 1,200 returned bytes with a 1,024 limit,
but unchanged 10,000 backing bytes. **1 passed in 0.48s**, normal conftest, exit 0.
This characterization is recorded in the worker-lifecycle map as uncovered
storage-quota evidence, not a quota implementation or explanation of the prior
C-drive incident. No process/provider was launched or production source changed.
