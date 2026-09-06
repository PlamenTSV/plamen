# Plamen v3 next actions

This is the execution order for the active goal. It is not a completion claim.
The Python driver remains the sole owner of audit phase sequencing.

## 0. Preserve the current checkpoint

- Confirm the `Plamen-v3` branch contains the intended development source rather
  than a copied installed runtime.
- Record a source-tree manifest after all concurrent migration edits settle.
- Reconcile any deliberate source-only versus installed-only changes. Never
  repair an installed receipt by silently changing expected hashes.
- Keep failed audit runs sealed. A new validation attempt uses a distinct clean
  destination and a config with `cli_backend` set explicitly.

Exit condition: one declared editable source tree, a reproducible manifest, and
no required change stranded only in an installation, backup, cache, or scratchpad.

## 1. Make the branch portable

- Finish repository hygiene: exclude runtime generations, caches, temporary
  fixtures, audit scratchpads, logs, credentials, target sources, private
  reports, ground truth, and generated binaries.
- Ensure every required methodology, prompt, schema, agent role, rule, and
  packaged asset is versioned and reachable with repository-relative paths.
- Retain neutral evaluator and benchmark corpora as out-of-tree systems.
- Add clean macOS and Windows development/install documentation and a fast
  post-install diagnostic.

Exit condition: a new machine can clone the branch and determine prerequisites,
configuration, installation, smoke-test, audit-start, and resume commands
without local-machine knowledge.

## 2. Repair installation and package governance

- Diagnose the committed-installed-byte admission mismatch through the public
  installer and source manifest; do not bypass admission with ambient Python.
- Make build/install/repair/upgrade/rollback/uninstall transactions idempotent,
  recoverable, and path-portable.
- Verify packaged assets, dependency locks, runtime closures, symlinks, public
  launchers, and both backend adapters from clean archives.
- Add macOS fixtures for permissions, links, atomic replacement, process groups,
  and cleanup semantics corresponding to Windows coverage.

Exit condition: two clean installs from the same frozen source pass package
identity and smoke checks on Windows and macOS.

## 3. Integrate the immediate audit blocker

- Preserve the attention-repair global queue-ID contract: queue row N emits
  `ATT-N`; the heading validator accepts the canonical `### Finding [ATT-N]:`
  form and rejects locally renumbered or prefix-colliding IDs.
- Re-run focused tests, affected phase tests, full serial tests, supported
  parallel tests, and clean-package tests on the frozen source.
- Convert the existing unsealed local observation into an immutable test receipt.

Exit condition: the fix is source-, prompt-, test-, manifest-, and package-bound.

## 4. Complete requirements reconciliation

- Extract every historical P0/P1 row and program gate into stable ledger records.
- Reconcile all 166 canonical registry rows with current implementation symbols,
  production reachability, tests, independent reviews, and missing evidence.
- Complete semantic extraction of the 127-file historical discovery corpus.
- Record explicit reviewed successor edges. Do not infer supersession from date,
  filename version, code volume, or artifact presence.
- Keep benchmark/scoring work `DEFERRED_BY_USER` while retaining its interfaces
  and privacy boundary.

Exit condition: every row has a current status, owner, source locator, successor
relation, implementation reference, evidence reference, and exact remaining proof.

## 5. Close runtime and operational debt

- Complete all 24 worker-lifecycle cases plus the source's additional migration,
  binding, OS, sandbox, and evidence requirements.
- Bound backing output spools, not only returned log tails.
- Implement reference-aware cleanup-ledger retention with concurrency, crash,
  replay, path, archive, and rollback evidence.
- Integrate bounded storage-capacity diagnostics without granting deletion
  authority.
- Confine fuzz, PoC, compiler, transcript, and generated report output to owned
  output roots; add load-bearing disappearance detection and endpoint-protection
  guidance.
- Resolve coordinator no-progress oscillation, dependency/vendored-source
  scoping, PoC skip enforcement, chain grouping/ID idempotence, niche manifest
  single authority, and invariant-commitment debt.

Exit condition: fault injection, interruption, resume, retry, and repeated-cycle
tests prove no late write, silent loss, false completion, or unbounded growth.

## 6. Finish architecture and methodology reachability

- Reconcile and independently review the five normative architecture sources,
  their two redirects, and the canonical ownership registry.
- Complete PhaseIO output-prestate/CAS and all caller migrations.
- Make MethodCards authoritative for every declared consumer.
- Finish Program Facts producer/runtime integration and capability-scoped
  consumers without graph-derived negative authority.
- Finish exact axis, exploration, adaptive-attention, premise, negative,
  severity, chain, verification, deduplication, and report-projection lifecycles.
- Resolve backend routing across launch, provider terminal evidence, retry,
  resume, worker incorporation, RunBundle, and report/evaluator projections.

Exit condition: production-reachability checks and independent reviews show one
authority per decision and no silent loss across all live transformations.

## 7. Run release-candidate validation

On one frozen source/package identity:

1. Run lint, schema, ownership, duplication, and static-launch checks.
2. Run focused and full serial suites.
3. Run supported parallel suites and race/concurrency fixtures.
4. Run package, install, upgrade, rollback, repair, and uninstall matrices.
5. Run Windows and macOS lifecycle/fault/resume matrices.
6. Run bounded representative ecosystem and L1 canaries.
7. Run a fresh Codex non-ground-truth E2E audit through final report.
8. Run a fresh Claude non-ground-truth E2E audit through final report.
9. Exercise clean resume, cancellation, timeout, failure, and recovery for both
   backends without reusing failed staged output.

Exit condition: immutable evidence records satisfy the applicable requirements;
a generated report alone is not the exit condition.

## 8. Final handoff

- Refresh `REQUIREMENTS.jsonl` and `EVIDENCE_INDEX.json` against the exact release
  candidate.
- Publish supported platforms, backends, ecosystems, limitations, and explicit
  debt without overclaiming.
- Verify all setup commands from a clean clone on a new machine.
- Produce a hash-bound release/handoff receipt and obtain user acceptance.

Only after this handoff should the separate old-versus-new benchmarking goal be
opened.
