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

## 0.5. Close the August release blockers

`B-1` precedes every `P-*` item: freeze the current tree and run the full suite,
retaining the baseline instead of overwriting failures. Then close or prove
superseded all seven blockers:

- `B-2`: verify the client-confidential helper is absent and record the
  separately authorized disclosure/history disposition outside this repo;
- `B-3`: repair the tracked dependency, lock, import, and commit boundary;
- `B-4`: reverify and repair SC report-index recovery at commit, not arm;
- `B-5`: exclude private review fixtures and relocate load-bearing test support;
- `B-6`: resolve the fresh-run and report-integrity haltless contradictions;
- `B-7`: declare and clean-install `cryptography`, PyYAML, and packaging.

Exit condition: `B-1` through `B-7` each have current-tree evidence and no
private incident contents have entered Git.

## 1. Make the branch portable

- Finish repository hygiene: exclude runtime generations, caches, temporary
  fixtures, audit scratchpads, logs, credentials, target sources, private
  reports, ground truth, and generated binaries.
- Ensure every required methodology, prompt, schema, agent role, rule, and
  packaged asset is versioned and reachable with repository-relative paths.
- Retain neutral evaluator and benchmark corpora as out-of-tree systems.
- Add clean Linux, macOS, and Windows development/install documentation and a fast
  post-install diagnostic.
- Treat the current production installation truthfully as Windows-only. The
  existing macOS bootstrap is source-development support, not an audit-runtime
  dispatcher.
- Verify the 131-row research manifest: 127 published ports (54 exact and 73
  sanitized), including sanitized semantic ports for six privacy-interleaved
  core sources. Ten raw-byte rows still require separate transfer, but only
  four have no public text payload: two superseded ZIPs, the private audit
  report, and its target postmortem. Transfer all ten raw files under
  `PRIVATE_ARTIFACTS.md` and verify their original hashes on the new machine.

Exit condition: a new machine can clone the branch and determine prerequisites,
configuration, installation, smoke-test, audit-start, and resume commands
without local-machine knowledge, and can tell which commands remain unsupported
on native POSIX platforms.

## 2. Repair installation and package governance

- Diagnose the committed-installed-byte admission mismatch through the public
  installer and source manifest; do not bypass admission with ambient Python.
- Make build/install/repair/upgrade/rollback/uninstall transactions idempotent,
  recoverable, and path-portable.
- Verify packaged assets, dependency locks, runtime closures, symlinks, public
  launchers, and both backend adapters from clean archives.
- Implement a POSIX dispatcher plus keeper/recovery adapter, then add Linux and
  macOS fixtures for permissions, links, atomic replacement, process groups,
  crash recovery, and cleanup semantics corresponding to Windows coverage.

Exit condition: clean installs from the same frozen source pass package identity,
start, stop, recovery, and resume checks on Windows, Linux, and macOS. Until
then, POSIX production commands must reject before dependency or filesystem
mutation and the platform remains unsupported.

## 3. Integrate the immediate audit blocker

- Preserve the attention-repair global queue-ID contract: queue row N emits
  `ATT-N`; the heading validator accepts the canonical `### Finding [ATT-N]:`
  form and rejects locally renumbered or prefix-colliding IDs.
- Re-run focused tests, affected phase tests, full serial tests, supported
  parallel tests, and clean-package tests on the frozen source.
- Convert the existing unsealed local observation into an immutable test receipt.

Exit condition: the fix is source-, prompt-, test-, manifest-, and package-bound.

## 4. Complete requirements reconciliation

- Maintain the extracted 57 historical P0/P1 rows, 11 program gates, three
  user-acceptance gates, and three integration invariants as stable ledger
  records while implementation/evidence links are completed.
- Reconcile all 166 canonical registry rows with current implementation symbols,
  production reachability, tests, independent reviews, and missing evidence.
- Preserve and validate the completed semantic extraction of the full
  131-source research union: the current 127-name roster plus the four August
  sources. Keep the historical 127/5,210,228-byte snapshot and the current
  131/5,372,712-byte denominator as distinct facts.
- Record explicit reviewed successor edges. Do not infer supersession from date,
  filename version, code volume, or artifact presence.
- Keep benchmark/scoring work `DEFERRED_BY_USER` while retaining its interfaces
  and privacy boundary.

Exit condition: every row has a current status, owner, source locator, successor
relation, implementation reference, evidence reference, and exact remaining proof.

## 4.5. Execute the August methodology backlog in dependency order

After `B-1`, preserve these hard edges:

1. `P-8` before `P-2`; `P-13` before `P-2` and `P-7`; audit all 19 `P-11`
   call sites before any `P-11` fix; land the symbolic vacuity guard before
   `P-6`.
2. Land `P-15` liveness telemetry before `P-14`, `P-19`, or `P-20`, and land
   `P-17` bounded enumgap sharding before `P-16` or `P-19`.
3. Implement `P-14`, `P-19`, and `P-20` with known-positive and near-miss
   controls, then land `P-21` to enforce those controls.
4. Close `P-1`, `P-3` through `P-7`, `P-9` through `P-13`, `P-16`, `P-18`,
   `P-22`, and `P-23` under their row-level acceptance criteria in
   `REQUIREMENTS.jsonl`.

Rule 0 governs the work: Python enumerates completely; bounded LLM shards decide
only intent-dependent rows; exact reconciliation rejects missing/duplicate
dispositions. Do not build the rejected mutation-recall benchmark, AutoProver
agent layer, standalone symbolic tool, fan-out debate, prompt-only double-check
scaffolding, or SMTChecker migration.

Exit condition: all `P-1` through `P-23` rows are production-reachable and
proven, or have an explicit reviewed supersession; the correction/limit notes
remain attached and legacy counterparts are removed.

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
5. Run Windows, Linux, and macOS lifecycle/fault/resume matrices.
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
- On that machine, validate `CORPUS_MANIFEST.json`, copy the hash-verified
  private gap archive outside the repository, verify the 131-row source union
  and 127 portable source files against their recorded sizes and hashes, run
  source-development bootstrap, and use Windows for production audits until the
  POSIX runtime gate is proven. The research directory has 128 files: 127
  source ports plus `PRIVATE_GAP_INDEX.json`; the four raw-only sources explain
  the three-file difference from the 131-source denominator.
- Produce a hash-bound release/handoff receipt and obtain user acceptance.

Only after this handoff should the separate old-versus-new benchmarking goal be
opened.
