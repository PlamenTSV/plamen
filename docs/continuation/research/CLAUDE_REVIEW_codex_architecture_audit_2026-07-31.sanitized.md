# CLAUDE_REVIEW — Codex Architecture Audit

**Target:** `<LOCAL_USER_ROOT>\plamen-codex-implementation` (branch `codex/recall-app-benchmark-r10_1` @ `67a0f85` + uncommitted working tree)
**Reviewer:** Claude Fable 5, 8-slice parallel audit with independent verification of load-bearing claims
**Date:** 2026-07-31
**Method:** read-only. Nothing in the audited tree was created, modified, or deleted. No pipeline run was invoked.

---

## 0. Scope and what was actually measured

| Surface | Volume |
|---|---|
| New untracked production modules under `scripts/` | **180 modules / 298,761 LOC** |
| New untracked test files | **476 files / 256,409 LOC** |
| Uncommitted diff to pre-existing files | **300 files, +114,858 / −21,818** |
| Unpushed commits on the branch | 11 |
| New untracked non-code artifacts | `review_fixtures/` 289 files/133K lines, `verification_policy/` 41, `rules/schemas/` 37, `architecture/` 6, 9 `bpc_*`/`bpa_*` run dirs |
| **Total new/changed material** | **≈ 670,000 lines** |

For calibration: the pre-existing repo is ~185K LOC. **This change is roughly 3.6× the size of the codebase it modifies.**

Eight slices were audited in parallel: process/credential/filesystem security, recall-safety of the finding lifecycle, transaction & crash-consistency, executability & test health, architecture & duplication, the uncommitted core diff, new methodology/gate-registry/schemas, and artifact-hygiene/privacy.

**Claims I personally re-verified before including them** are marked ✅ **VERIFIED**. Everything else is a subagent finding reported at its stated confidence. Two subagent claims were **overturned** by my verification and are recorded in §10 — read that section, it matters.

---

## 1. Verdict

**The engineering quality is materially better than "180 unreviewed AI-written modules" implies, and materially worse than its own receipts claim.**

What is genuinely good, and I want this on record because it is unusual:

- **No orphans.** ✅ VERIFIED — of 180 new modules, **170 are referenced by production code, 0 are referenced nowhere**. The project's historic failure mode (impressive mechanisms that never run) did not recur at module granularity.
- **Imports and collects.** 656/656 new files compile; 180/180 import cleanly; 14,225 tests collect from the repo root.
- **Layering direction is correct.** 0 of 180 new modules import `plamen_driver`; 0 use star imports (the old core uses 5).
- **The IO layer is hardened well above typical.** `os.replace` not `os.rename`, fsync + directory-fsync, `O_NOFOLLOW`/reparse guards, real cross-process locks, bounded reads. **Zero** missing-`encoding=` defects in the entire transaction slice — notable on a Windows-primary project handling Unicode audit content.
- **Part 0 (no-overfit) compliance is clean.** 472 files / ~167K lines swept: 0 forbidden protocol-naming, 0 stored findings, 0 same-contest sources. Where real protocol names appear they are *anti-overfit denylists asserting absence*.

What blocks the handoff:

- **The suite is failing at scale and nobody has measured it.** One targeted slice: **36 failed / 1,161 passed**, concentrated in the author's *own new* test files.
- **CI has never validated any of this** — it tests the tracked subset, which excludes essentially the entire change; and the commit that would fix that breaks `pip install -r requirements-dev.txt` for everyone.
- **SC report-index mechanical recovery is dead end-to-end** — an intentional redesign whose replacement half does not work, with the author's own test failing.
- **Two safety gates were silently unwired** (auth fail-fast, anti-PoC-fabrication) and **three analysis capabilities silently disabled** (Sec3 X-Ray, opengrep, forge-std).
- **Two haltless violations** — `--fresh` refuses to start on any project with a prior `AUDIT_REPORT.md`, and a terminal integrity failure now **withdraws the client deliverable entirely**.
- **A private directory would be committed** by `git add -A` today, in a repo that already has one live confidentiality breach.
- **The strangler never strangled.** ✅ VERIFIED — `plamen_driver.py` went **22,280 → 78,168 lines (+251%)**. 370K lines added, **0 removed**. Every god-function grew.
- **A recurring, structural defect class**: new gates keying on fields no producer emits, and new parsers that cannot read the project's own canonical template. Each fails in the recall-unsafe direction, each has fixtures that hand-write the shape production never produces, so **all of it is green in CI**.

That last point is the thesis of this review. The dominant risk in this change is not bugs — it is **gates that are structurally disabled while reporting success.**

---

## 2. P0 — Release blockers

### P0-1. `write_dedup.py` — client-confidential findings, live on the public repo

✅ **VERIFIED INDEPENDENTLY.** This originates in the public repo but **carries into this worktree**: the file is still `git ls-files`-tracked here. Adding `/write_dedup.py` to `.gitignore` (which this diff does) **does not untrack it**.

- Public: `visibility: public`, **273 stars, 54 forks**; file currently served by GitHub (17,534 bytes).
- Exposed since `6fef0e9`, **2026-07-03** — four weeks.
- Contains a named client project, the maintainer's absolute path including a directory literally named `Private`, and ~13 rows of finding IDs, severities, verbatim vulnerability descriptions and exact `file:line` locations — several marked `[POC-PASS]`, i.e. confirmed exploitable and (as published) unfixed.
- Violates the project's own Part 0 rule, which forbids storing past-audit finding descriptions, IDs, or file:line **anywhere**.

**Action:** `git rm write_dedup.py` in both trees; decide on history rewrite and client notification. Note **54 forks mean a rewrite will not fully un-publish it** — treat as disclosure, not merely cleanup. Secondary: `scripts/plamen_validators.py:2103` and `:11269` name the same client in comments (engagement existence only).

### P0-2. The commit boundary is broken three ways

✅ **VERIFIED.** *(This section was rewritten after a late finding overturned an earlier, wrongly-stated version — see §10.6.)*

**(a) A tracked-only commit yields a non-importable pipeline.** The tracked core modules hard-import the untracked new ones: `plamen_driver.py` alone has **72 top-level imports of untracked modules** (measured), plus validators 25, mechanical 14, parsers 12. All 656 new `scripts/*.py` files are explicitly un-ignored by added `!scripts/<name>.py` lines — so they *can* be committed, but if the commit is split or partial, the pipeline does not import at all.

**(b) `pip install -r requirements-dev.txt` hard-fails for every developer.** ✅ VERIFIED — `requirements-dev.txt:5` now reads `-c requirements-ci.constraints`, and that file is **untracked**, as are `requirements-ci.lock` and `scripts/ci_dependency_authority.py`, which both new workflow jobs require. pip hard-errors on a missing `-c` target. This breaks the dev install *and* both workflows the moment the tracked half lands.

**(c) The local inner loop aborts on collection** — but **not CI**:

```
cd scripts && python -m pytest --collect-only -q
→ ModuleNotFoundError: No module named 'scripts.bounty'   (exit 2)
```

One file uses `from scripts.bounty import` where 53 siblings use `from bounty ...`, and there is no `scripts/__init__.py`. ✅ VERIFIED that `scripts/bounty/` is **gitignored and untracked**, so it is absent from a CI checkout and CI is unaffected. This breaks only the documented local workflow. One-line fix.

The related `sys.path` fragility is real but likewise local-only today: ~30 test files import repo-root `review_fixtures` / `verification_policy`, resolving only because another test earlier in alphabetical order hand-rolls a `sys.path.insert` — nondeterministic under `-n auto`. Those test files and directories are themselves untracked, so CI never sees them.

**Net:** CI today is green because it tests the *tracked* subset, which excludes essentially all of this work. That is not reassurance — it means **this change has never been validated by CI at all**, and the first real commit will turn CI red for reasons (a) and (b). Fix: track the requirements files, add `scripts/__init__.py` or normalize the import, and add the repo root to `pythonpath`.

### P0-3. `review_fixtures/` would be committed today

✅ **VERIFIED** — `git status --porcelain` reports `?? review_fixtures/`; `git add -A` stages **271 files / 165,596 lines / 8.3 MB**.

The repo's **own** packaging guard already declares it private, in the same tuple as the file that caused the live breach:

```python
# scripts/test_public_packaging_freeze.py:25
_INDEX_ONLY_REMOVALS = (".plamen-manifest.json", "review_fixtures", "write_dedup.py")
# :50
_FORBIDDEN_ARCHIVE_PREFIXES = (..., "review_fixtures/", "scripts/bounty/", ...)
```

`.gitignore` gained `/write_dedup.py` in this diff but **never gained `review_fixtures/`**. Same omission class, one line short.

Contents are internal author↔reviewer handoff docs and pytest logs — **no client data** (see §9) — but they disclose the private bug-bounty lane's module roster, CLI syntax, and the existence of `<PRIVATE_BOUNTY_INPUT_PATH>` holding *"private program/acquisition input"*. `<PRIVATE_FIXTURE_PATH>` does `from bounty import ...`, which would publish a broken import against a never-public lane.

Also unignored: 9 `bpc_*`/`bpa_*` pytest basetemp dirs (172 files), three containing `.credentials.json` with a real-shaped `claudeAiOauth` blob (synthetic value) and absolute `<LOCAL_USER_ROOT>/...` paths.

**Caveat that must be resolved, not papered over:** 5 of the 289 files are load-bearing — `program_facts_r2_1_b0_red_support.py` alone is imported by **23 public tests**. Gitignoring keeps local tests green while making the public suite unrunnable from a clean clone. Move those 5 to `scripts/_test_support/` and update the 24 imports.

### P0-4. Three deterministic regressions in recall-critical recovery paths

Measured, reproduced, not flakes:

| Test | Failure | What it guards |
|---|---|---|
| `test_contract_hardening_regression.py:1127` | `_repair_sc_report_index_from_prior(sp)` returns **0**, expected 1 | Report-index repair — a haltless-recovery mechanism |
| `test_driver_helpers.py:76` | `FileNotFoundError: inventory_reemit_receipt.json` | Driver no longer writes the inventory re-emit receipt |
| `test_V249_P51_index_completeness_retry_hint_uses_norm_indexed` | Hint file missing | Index-completeness retry hint |

**Diagnosis completed. Verdicts:**

1. **REGRESSION** — `_repair_sc_report_index_from_prior`. The redesign was intentional (the old version read back the very quarantine that exists to hide bad artifacts, and a new test asserts `repaired == 0` for that case) — **but only half of it landed.** The replacement requires a ledger `artifact_bindings` entry that is written only at **commit** (`artifact_ledger.py:8116`), never at pre-spawn arm, and `report_index.md` is an `expected_artifact` that quarantine reaches. So the repair is reachable essentially only on fresh-process resume. The author's **own** replacement test fails: `test_failed_retry_preserves_committed_prior_successor_and_history` → `assert ['report_coverage.md'] == []`, i.e. generic retry quarantine displaced the committed canonical head because the exemption at `plamen_validators.py:20535-20545` does not cover `report_coverage.md`. Two more of the author's updated tests fail on the same new precondition. **SC report-index mechanical recovery is dead end-to-end.**
   *Fix: extend the canonical-head exemption to `report_coverage.md`; seed the binding at arm time, or accept an unbound live root as a degraded input rather than returning 0.*

2. **STALE TEST.** `_validate_inventory_parity` became a pure predicate; re-emission moved to `_record_inventory_reemit_phase_io` and is wired at both the inventory and chunk gates. Its 35 dedicated tests pass, all raise-paths are contained to issue strings, haltless preserved.

3. **STALE IN FORM, DEGRADED IN CONTENT.** The default flipped `write_retry_hint: True → False` and the driver does still publish a hint — but the surviving branch (`plamen_validators.py:16724-16732`) truncates to `dropped[:5]` while still telling the reader *"See report_index_retry_hint.md"*, a file that no longer holds the full list. **Real recall degradation whenever more than 5 IDs drop.**

### P0-4b. The diff is broadly unvalidated — "3 failures" is a large undercount

Running one targeted slice (`-k "report_index or severity or index_completeness or repair"`) measured **36 failed / 1,161 passed**, concentrated in the author's *own new* suites — `test_semantic_dedup_repair_fault_matrix.py` (×18), `test_severity_shadow_phase_runtime_p0_ag4.py` (×4), and four more files. **Run the full suite before any further review; the true failure count is unknown.**

Also: a new module **contradicts its own new test** — `test_artifact_ledger_v2_p0_ae.py::test_exact_chain_merge_records_both_targets_and_legacy_projection` asserts legacy fixed-key chain-tail merges are supported; `phase_io_contracts.py:6932` raises `CHAIN_TAIL_LEGACY_FIXED_GENERATION` on exactly that. Deterministic 2/2. One of the two is wrong and it shipped that way.

### P0-5. `cryptography` is an undeclared, unguarded hard dependency

`claude_executable_observation.py:364,585` does a bare `from cryptography import x509`. The package is in **no** requirements file — not `requirements.txt`, not `-dev.txt`, not `requirements-ci.lock`. It is installed on this machine (46.0.7), which masks it locally. A clean install gets an `ImportError` at runtime on the Windows publisher-verification path, which no test exercises. `PyYAML` and `packaging` are also undeclared (both guarded/lazy, so lower severity).

---

## 3. Security — process, credential, filesystem authority

12 findings. The four HIGHs are all reachable without LLM cooperation.

### S-1 (HIGH) Windows `.cmd` shim + `list2cmdline` → `cmd.exe` re-parses argv

`pty_worker_host.py:190-196` → pywinpty `ptyprocess.py:90` joins argv back into one string via `subprocess.list2cmdline`, which implements MSVCRT quoting only — it never escapes `& | ^ % < >`. When argv[0] is a `.cmd`, `CreateProcessW` routes through `cmd.exe /c`, which interprets those **before** MSVCRT unquoting. `shell=False` does not help. `claude.cmd` is the standard npm install and is allowlisted (`plamen_types.py:344-363`); it exists on this host.

**Failure:** a client repo cloned into a path containing `&` (legal on NTFS, e.g. `R&D-vault`) reaches argv verbatim at `plamen_driver.py:63972` via `--add-dir`; `cmd.exe` splits on the unescaped `&` inside the quoted region and executes the tail at the auditor's integrity level, before Claude starts. `%VAR%` expands likewise.

**Scope precision:** the newer materialization path *is* gated (an npm `.cmd` is classified `NO_PROOF_GRADE_LAUNCH`, `claude_executable_observation.py:1238-1242`). This is the **legacy PTY path only**.

**Fix:** refuse `.cmd`/`.bat` as argv[0] — resolve to `node.exe` + `cli.js` (the shim is already parsed at `claude_executable_observation.py:1008-1014`) — or reject argv elements matching `["&|^<>%\r\n]` on Windows.

### S-2 (HIGH) `CLAUDE_BIN` executable hijack

```python
# plamen_types.py:344-363
override = os.environ.get("CLAUDE_BIN")
if override:
    return override                    # no validation whatsoever
for name in ("claude", "claude.cmd", "claude.exe"):
    found = shutil.which(name)         # Windows: cwd searched FIRST
CLAUDE_BIN = _resolve_claude_bin()     # resolved at MODULE IMPORT time
```

No absoluteness/existence/basename check; `shutil.which` prepends `os.curdir` on Windows; resolution happens at import, when cwd is routinely the audited client repo. Downstream validation enforces canonical spelling and no-reparse-point but **never that the path lies outside `project_root`**. `C:\audited-repo\claude.exe` passes every check.

**Fix:** require an absolute existing path; pass `path=` explicitly to `shutil.which`; reject any executable resolving inside `project_root`.

### S-3 (HIGH) The configured CLI is executed with the full ambient environment *before* the authority gate

```python
# claude_executable_observation.py:1245  — the binary RUNS
result = run_owned_process([str(executable), "--version"], env=env, ...)
# :1303  — authority decided AFTER the child already executed
```
with `ambient_environment = dict(os.environ)` at `plamen_driver.py:18039`.

Chained with S-2: a planted binary executes once with `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` / `GH_TOKEN` inherited. The run is *later* marked `NO_PROOF_GRADE_LAUNCH` and blocked — but the code already ran and the credentials already left. The 3 s / 512-byte probe bounds output, not side effects.

**Fix:** move the authority decision before `run_owned_process`; probe with a minimal allowlisted env.

### S-4 (HIGH) Fuzz probe allowlist is basename-only; argv[0] exempt from containment

`fuzz_workspace_authority.py:1839-1878` checks `command[1:]` for path escapes but never `command[0]`; the code comments the hole itself at `:1424`. The whole argv is model-supplied (`plamen_driver.py:53076` passes `argparse.REMAINDER` verbatim). A repo shipping `vendor/tools/forge.exe` gets it executed because `_tool_family` strips the extension and matches the allowlist. Bounded by `shell=False`, env allowlist, writable-roots, ≤3600 s — contained execution, not host takeover.

### S-5 (MEDIUM-HIGH) The driver permanently disables a global Claude Code safety control

`plamen_driver.py:70653-70670` writes `skipDangerousModePermissionPrompt: true` into the user's **global** `~/.claude/settings.json`, and sets `bypassPermissionsModeAccepted` / `hasCompletedOnboarding` in `~/.claude.json` (`:70625-70634`). Workers launch with `--dangerously-skip-permissions` unconditionally.

After one Plamen run, **every subsequent unrelated Claude Code session on that machine** — any project, any workflow — loses the one-time bypass warning. Never reverted, user never asked. The justification (a PTY worker has no stdin to answer the dialog) is real; the remedy is global and permanent rather than child-scoped.

**Fix:** scope acceptance to the child (`--settings` overlay / child `CLAUDE_CONFIG_DIR`); if unavoidable, restore on exit.

### S-6 (MEDIUM) `os.chmod(..., follow_symlinks=False)` raises `NotImplementedError` on both shipped platforms

`auxiliary_writable_root_lease.py:1746-1762` — the `except OSError` at `:1759` does **not** catch `NotImplementedError` (a `RuntimeError` subclass), and no production caller catches it either. Verified on the target runtime (CPython 3.12.10 win32): `os.chmod` is not in `os.supports_follow_symlinks`. The only self-healing branch in the leased-root cleanup path is **unreachable on Windows and Linux**; orphaned roots are re-quarantined on every startup instead of recovered.

### S-7 (MEDIUM) Credential-value SHA-256 written into a durable on-disk receipt

`skeptic_execution_work.py:255-256` digests key **and value** pairs; `:1164` writes `environment_effective_sha256` unconditionally; `:1199` persists it to `{scratchpad}/.../inputs/intent.json`. `ANTHROPIC_API_KEY` is deliberately in that env (`plamen_driver.py:45134`). Redaction **exists but is applied only to the sibling arm record and only for the claude backend** (`:1839-1851`) — a gap in an implemented control.

Yields an offline confirmation oracle: with sibling receipts supplying the name list and `PATH`/`HOME` locally observable, candidate keys can be tested. Neither `runbundle_privacy.py` nor `runbundle_export.py` redacts it.

**Fix:** force `None`; reuse the correct existing pattern at `worker_execution_receipts.py:3904-3915` (`persist_value_digest=False`).

### S-8 (MEDIUM; HIGH on Linux/macOS) Unauthenticated guard ledger → arbitrary recursive tree deletion

`owned_directory_guard.py:547-553` reconstructs a parent from a ledger-supplied relative path rejecting only *empty* components — `..` is permitted, unbounded — and `:2445-2452` takes the "expected" subject from the file it is validating. Integrity is an **unkeyed** SHA-256 over the file's own contents.

A planted ledger with `parent_relative_path: "../../../../Users/<LOCAL_USER>"` and `original_component: "Documents"` drives quarantine-rename → `_empty_tree` (unbounded recursive delete). **Honest caveat:** on Windows the worker is low-integrity and the lifecycle dir has a protected DACL, so a worker cannot plant it. **On Linux/macOS there is no equivalent** — same-uid worker, full write access.

### S-9 (MEDIUM) `ResourceGrant` ceilings are digested into receipts but never enforced

`resource_grant.py:1360-1401` seals ceilings; only the *digest* survives downstream. Neither `resource_grant.py` nor `resource_policy_authority.py` imports `os`, `subprocess`, `signal`, or `resource`, and none of the four `Popen`-owning files mention the grant. The actual cap is an unrelated hardcoded `output_limit_bytes=8*1024*1024`. **A run that exceeded the granted ceiling produces a receipt indistinguishable from one that respected it.**

### S-10 (MEDIUM) The Job object confining untrusted builds sets no memory/CPU/process limit

`owned_process_scope.py:705-716` (and `isolated_execution_host.py:2636-2648`) declare the full `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` then set exactly one flag, `KILL_ON_JOB_CLOSE`. No memory/active-process/CPU flag exists anywhere in `scripts/`. `forge test` runs in the audited project — a malicious `foundry.toml`/`build.rs` can fork-bomb or OOM the auditor's host for the full timeout window. Process-tree *reaping* is proven; resource *containment* is not.

### S-11 (MEDIUM) Recon-supplied `build_root` is never confined to `project_root`

`mechanical_verify.py:481-506` accepts an arbitrary absolute path from LLM-written `build_status.md`, validated only by `resolve(strict=True)` + `is_dir()` — though the module owns a containment primitive at `:832-833`. Prompt injection in an audited repo can point it at a *different client's* checkout, whose `.sol/.toml/.json/.sh` files are then hashed and copied into workspace, manifest, and durable receipts. **One client's source disclosed into another client's audit artifacts.**

### S-12 (MEDIUM) `closure_broker_v2._load_arm_bindings` bypasses the module's own path validator

`:1235-1241` rejects `/` and `\` but not `:`; the module's own validator rejects `:` for exactly this reason at `:1063`. `arm_name = "C:evil.json"` passes, and Windows `pathlib` drive-replacement resolves it off the process CWD, outside the scratchpad. Also skips the reparse walk and containment check, with no byte cap on the read.

**Verified clean (recorded so it isn't re-investigated):** containment is never string-`startswith` (uses `os.path.commonpath`); NTFS ADS / drive-relative / device paths rejected; recursive delete never follows links (handle-relative with `FILE_OPEN_REPARSE_POINT`; POSIX fully `dir_fd`-relative with `O_DIRECTORY|O_NOFOLLOW`); TOCTOU-on-delete genuinely closed via full `st_dev/st_ino` re-stat; no credential in child argv or exception messages; child env is a real allowlist built from `{}` upward; `hmac.compare_digest` throughout; credential file permissions use real DACL inspection, not `chmod`; `isolated_execution_host` fails **closed** on non-Windows; no `pickle`/`eval`/`yaml.load` on external input; `shell=True` appears in no spawn path.

---

## 4. Recall safety — the finding lifecycle

**This is the most important section.** Four independent new gates each key on a finding field that **no producer prompt instructs any agent to emit**, and a fifth cannot parse a field the canonical template *mandates*. Each fails recall-unsafe. Every one has fixtures; every fixture hand-writes a shape production never produces; therefore **all of it is green.**

### R-1 (CRITICAL) In Thorough mode the depth-promotion completeness gate is disabled for every non-CONFIRMED finding

✅ **VERIFIED** (formula and thresholds read directly at `plamen_driver.py:2493-2509`).

A consensus observation is `CURRENT` only if the depth finding carries an explicit upstream-identity label (`**Source IDs**` etc.). But the consensus denominator is the **pre-inventory depth set**, and `**Source IDs**` is mandated only from **inventory onward** — `rules/finding-output-format.md`, `prompts/shared/v2/phase4b-depth.md`, and the scanner templates contain **0 occurrences**. So consensus is `0.0` for every finding.

```python
if mode_key == "thorough":
    composite = round(evidence * 0.25 + consensus * 0.25 + quality * 0.3, 2)
classification = "CONFIDENT" if composite >= 0.7 else ...
```

With consensus pinned at 0.0 and both other axes maxed, the **ceiling is 0.55** — below the 0.7 CONFIDENT threshold. Then:

```python
# plamen_validators.py:7367  (_validate_depth_promotion_receipt, min_confidence=0.70)
if status != "CONFIRMED" and score is not None and score < min_confidence:
    continue
```

Gate P — the one mechanical gate proving a depth/scanner/niche finding actually reached `findings_inventory.md` — **opts out for every non-CONFIRMED finding in Thorough mode**. If the inventory worker paraphrased a finding away, nothing reports the loss. Note the perversity: **Core and Light keep the gate armed; Thorough, the mode chosen for completeness, does not.**

**Fix:** assert `any(status == "CURRENT")` and emit `CONFIDENCE_CONSENSUS_AUTHORITY_DEBT` otherwise; either mandate `**Source IDs**` in the depth contract *and* fixture-test the join, or derive independence from worker identity. Gate P must not key on an axis that can be structurally pinned.

### R-2 (HIGH) Three shipped niche skills emit ID prefixes the new registry rejects

| Skill (`**Finding prefix**`) | Registry accepts | Canonical ID grammar accepts |
|---|---|---|
| `semantic-consistency-audit:11` → `[SC-N]` | **No** | **No** |
| `spec-compliance-audit:11` → `[SPEC-N]` | **No** | **No** |
| `dimensional-analysis:12` → `[DA-N]` | **No** | **No** |

`finding_producer_registry.py:552-568` hardcodes a closed ~80-prefix alternation. Consequences, each traced: `local_id_valid=False` → `_content_bearing="false"` → **Gate P `continue`s again** (second independent route to R-1's failure); `chain_grouping_authority._norm_id("SC-1") == ""` → member silently removed from its group; ledgered as `RESIDUAL_DEBT`, and the renderer states content-less rows *"must not enter the client finding body"* — **a real, content-bearing Medium finding barred from the report by ID prefix alone.**

It survives today only because `plamen_mechanical.promote_niche_to_inventory` uses a *fourth* grammar that happens to accept `SC-1` — and that one rejects `P2P-1` and `T22-1`, which the registry itself lists as valid. There is **no test** cross-checking a skill's declared prefix against the registry.

**Fix:** generate the niche prefix list from the `**Finding prefix**` lines in `agents/skills/niche/*/SKILL.md` with a parity fixture. An unrecognised ID must never disarm a completeness gate.

### R-3 (HIGH) One tab character discards every mandatory re-verification obligation in the run

Producer explicitly allows `\t` (`finding_producer_registry.py:1442`); consumer rejects it (`mandatory_reverification.py:132`). Normalization runs in bulk **outside** the per-candidate `try` (`:1936-1946`), so one raise escapes the whole function; the caller sets `MANDATORY_DENOMINATOR_UNAVAILABLE` and continues with `safe_to_consume: True`, `delta_ids: []`.

An assessor overturning an author-negative on a High finding, pasting a code fragment containing a tab, discards **every reopen in the run** including twenty unrelated well-formed ones. The module docstring promises the opposite (*"never omitted or guessed"*); that contract is implemented on the sibling path at `:1724-1730` but not here.

### R-4 (HIGH) Every Critical/High/Medium body finding is stamped "Evidence limited" — including PoC-proven Criticals

`report_evidence_authority.py:438-441` requires a `preconditions` field for Critical/High/Medium; `:350-359` short-circuits to `EVIDENCE_LIMITED` **before any evidence is examined**. `_precondition_list` accepts only the labels `Preconditions | Precondition | Required Conditions | Exploitability` — and **all eight** `prompts/*/phase5-verification-prompt.md` files contain **zero** occurrences of any of them. The finding-format's `### Precondition Analysis` matches neither regex.

A Critical with a passing Foundry PoC therefore ships to the client reading *"Evidence limited — the report could not substantively complete preconditions."* The over-claim detector only checks the other direction, so nothing catches the under-claim. Not a deletion, but a uniform de-rating of exactly the tiers a human triages first.

**Compounding, same file:** `_best_evidence_fields:1104-1130` gates its code-trace branch on prose headings and does not detect the `[CODE-TRACE]` **tag**, so a CONFIRMED-by-code-trace finding records `evidence_authenticity: NOT_EXECUTED`.

### R-5 (HIGH) `_verdict()` default-deny maps eight non-refuting statuses to `UNVERIFIED`

`report_evidence_authority.py:832-840` — the catch-all is the **weakest** status. Upstream also emits `SCHEMA_INVALID`, `LOCATION_INVALID`, `LOW_CONFIDENCE`, `NEEDS_VERIFICATION`, `UNCONFIRMED`, `APPENDIX_ONLY`, `DUPLICATE`, `DROP_UNACTIONABLE_SPECULATION`. The sibling module in the same pipeline buckets all of them as `_CONTESTED` (`report_disposition_authority.py:98-109`).

A truncated `verify_H-4.md` → `SCHEMA_INVALID` ("unparseable", not "false") → disposition keeps it CONTESTED in the body while evidence records `UNVERIFIED`; the parity check at `:2738-2750` then requires the delivered verdict to match the record **exactly**, so a tier writer that correctly writes `CONTESTED` **fails parity**. The only parity-clean report is one that calls a parse failure "UNVERIFIED".

### R-6 (HIGH) The shared field parser cannot read the canonical template's own `**Material Harm** (MANDATORY):`

✅ **VERIFIED BY EXECUTION AND SIDE-BY-SIDE READ.** This is the single highest-value fix in the review.

```python
# NEW — scripts/inventory_reconciliation.py:53-57
_FIELD_RE = re.compile(
    r"(?ims)^[ \t]*(?:[-*][ \t]+)?\*\*(?P<label>[^*\n]+)\*\*[ \t]*:[ \t]*" ...

# OLD — scripts/plamen_parsers.py:6162  (has the parenthetical group)
rf"(?:\*\*)?{re.escape(label)}(?:\*\*)?(?:\s*\([^)]*\))?\s*(?::|-|=)\s*(.+)$"
```

`[ \t]*:` cannot match ` (MANDATORY):`. Replaying the live regex against the canonical template block in `rules/finding-output-format.md`:

- Labels recovered: `Verdict, Step Execution, Rules Applied, Preferred Tag, Severity, Location, Description, Impact, Evidence, Missing Precondition, ...`
- **`Material Harm` and `Depth Evidence` ABSENT** — 8/8 parenthetical labels invisible.
- Worse, the lookahead terminator never fires on a parenthetical label, so **`**Impact**` swallows the entire Material Harm line** into its own value.

**This is a regression, not an oversight** — the older shared parser solved it years ago; the new untracked module re-implemented field extraction from scratch and dropped the group. It is live: imported by `plamen_driver.py`, `plamen_validators.py`, `phase_io_contracts.py`, `plamen_mechanical.py`. Failure is silent (returns `""`), masked by the `Impact` fallback until a producer emits Material Harm without Impact.

Additionally `_canonical_blocks:357` reads `Root Cause`/`Mechanism`, which the canonical breadth schema defines **neither** of, so `source_root_cause` is empty for essentially every raw candidate; `_material_preservation_deltas:530-534` then **strips** every `UNPARSEABLE_*` delta, and both consumers gate on the material list only. A merge that discards the absorbed finding's mechanism reports no loss.

**Fix (one line, 12 modules at once):** add `(?:\s*\([^)]*\))?` to the shared template. Add a fixture that feeds the literal template block from `rules/finding-output-format.md` through the parser and asserts every mandated label is recovered — **the whole failure class is one test away from impossible.**

### R-7 → R-12 (MEDIUM-HIGH, condensed)

- **`axis_disposition.py:874-876`** — a complete AXIS finding block (title, severity, location, description, impact) is `continue`d on a field-label variant, and the debt row's frozen 5-field schema (`:3465-3478`) is structurally incapable of carrying its content. A regression from v1 in the same file, which carried location/function/axis/excerpt. Also an undisclosed 80-row cap at `:4051-4063`.
- **Axis BASE pass has no orphan-action reconciliation** — present only in the REPAIR pass (`:3133-3155`). A well-formed finding block that no complete disposition row references vanishes with **zero ledger entry of any kind**, and the phase still reports `status: COMPLETE`. Perversely, a *malformed* orphan is caught while a well-formed one is not.
- **`chain_grouping_authority.py:347-355`** — members are normalized (dropping unparseable IDs) **before** the `len(members) < 2` anti-absorption check, so the group `continue`s out of the debt table *and* the assurance denominator. Six lines below, the code asserts the exact opposite invariant for inventory metadata and handles it correctly with `REJECTED_INCOMPLETE_MEMBER_METADATA`. A safety net disappears with no row.
- **`security_obligation_authority.py:3309-3333`** — three unledgered `continue`s (notably dropping any obligation with `conflict_ids`, i.e. the ambiguous case doctrine says to keep), and `mandatory_reverification.py:1766` derives `source_obligation_count` from the **already-filtered** list, so the denominator's completeness assertion is satisfied by construction.
- **`post_verify_candidate_delta.py:1638-1692`** — a missing delta file is treated as a *certified-empty* late-candidate universe with `source_debts=()`. Nothing downstream can distinguish "no late candidates" from "the stage never ran". The dependency module states the opposite doctrine explicitly.
- **`severity_adjudication_work.py`** — the inlined methodology bundle exceeds the 65,536-byte cap (measured: 62,179 at zero items, **66,235 with one item**), so every candidate becomes `UNSCHEDULABLE_INPUT_CAP` debt: **total functional loss of the phase disguised as plausible per-candidate debt.** The zero-launch guard at `:1875` is inverted in scope (catches empty-denominator-that-launches, never full-denominator-that-launches-nothing). Every test uses a 42-byte methodology stub. Currently a *shadow* projection, which caps blast radius — but this is the layer intended to become authoritative.

**Verified recall-safe (good news worth recording):** `finding_lifecycle_authority.py` (whole file) is genuinely fail-visible — unauthorized terminal negatives are rejected and the candidate *reopens*; its one silent except drops a **negative** closure, i.e. fails toward retention. `severity_decision_ledger.py` (3,463 lines read in full) matches `report-template.md` cell-for-cell; `VIEW_FUNCTION_ONLY` is a true cap; `FULLY_TRUSTED_ACTOR` floors correctly; no modifier applies twice. `report_disposition_authority.py` defaults to **BODY**; APPENDIX requires unanimous proposals *and* severity ∉ {Critical, High, Medium}; an ID failing the regex becomes `UNACCOUNTED` + visible debt rather than a drop. `preverify_projection_authority` hard-asserts `candidate_records_removed == 0`. `post_verify_candidate_delta` re-identifies colliding candidates rather than dropping them. `application_skeptic` reopen-by-default is genuine.

---

## 5. State integrity — transactions, crash consistency

18 findings. Calibration: this layer is **hardened well above typical**, so nearly every defect is a *deviation from the file's own established standard* — which is exactly why they survived review. Three systemic patterns:

**Pattern A — the recovery machinery is the least durable part of the system.** The journal/ledger/receipt that exists to survive a crash is the one artifact written without the module's own atomicity or fsync discipline, and in two cases the recovery path actively destroys its own handle.

**Pattern B — locks and path-safety are applied everywhere except one site per module.**

**Pattern C — self-inflicted tears are indistinguishable from tampering**, so strict CAS preconditions convert the pipeline's own crash artifacts into permanent quarantines — the direct opposite of the haltless goal.

### T-1 (HIGH) Program-Facts ledger commit uses a thread lock, not the interprocess lock

✅ **VERIFIED** — `scripts/artifact_ledger.py:1613` is `with _LEDGER_LOCK:` where `_LEDGER_LOCK = threading.RLock()` (`:51`). **18 sites** use the correct `_ledger_transaction_lock`; this is the one that does not. `write_artifact_ledger` rewrites the *entire* state file, so it is last-writer-wins over **all** keys.

Worker A commits `work_units["depth:token-flow"]` under the file lock; the Program-Facts process — holding only an in-process RLock that A's file lock cannot block — writes back its stale postimage. A's entry is gone. `validate_work_unit_artifacts` then finds no owner for `depth_token_flow_findings.md` → either a completed multi-hour depth phase re-runs, or **the depth findings drop out of the audit entirely.** Silent: no exception, no log. The same window defeats the CAS at `:1651`.

**Fix: one line** — `with _ledger_transaction_lock(scratchpad):` (it is reentrant). Delete the `_LEDGER_LOCK` name so it cannot be reached again.

**This composes with T-15**: the containment check that would independently catch the resulting artifact mismatch is dead code. Two safety nets, both absent on the same axis.

### T-2 (HIGH) Public verify-queue artifacts published non-atomically → permanent quarantine

`verify_queue_transaction.py:2381-2412` — the `public_cas` branch `os.open`s the **final public path** with `O_CREAT|O_EXCL` and writes in place, while the sibling branch correctly does temp → fsync → `os.replace`. Outputs are published with the receipt forced **last**, so `verification_queue.md` is written before any receipt exists. A kill mid-write leaves a third state the design doesn't model — *present but partial* — and on resume `read_bytes() != raw` → `QUARANTINED_FOREIGN_STATE`, which nothing handles and no repair path addresses. **The pipeline's own torn write permanently quarantines the central coverage artifact.**

### T-3 (HIGH) Launcher self-hash makes prior receipts unreplayable after any edit or relocation

`worker_execution_receipts.py:9403-9407` demands an exact match on the module's own absolute path *and* SHA-256. A 5-hour audit pauses on a rate limit; the operator pulls a one-line patch — or resumes from `~/.plamen` rather than the worktree the run started in (the path check alone trips this) — and the shard can neither resume nor relaunch until a human deletes `.worker_execution_receipts/`.

### T-4 (HIGH) Debt retry whitelist has drifted from its producer

The module emits **23 distinct reason codes**; the consumer accepts **three** — and one of those three, `PROCESS_LAUNCH_FAILED`, **is never emitted anywhere in the repo** (it appears only in the whitelist). Meanwhile `_read_staged_regular_file` converts *any* `OSError` into a non-retryable semantic violation. Windows Defender opening a freshly written `assessment.json` for a 200 ms scan permanently kills that shard for the rest of the audit.

**Fix:** put `"retry_class": "TRANSIENT"|"SEMANTIC"` on the debt payload at emission and key retry off that, not a hand-maintained string set.

### T-5 → T-12 (condensed)

- **(HIGH, latent)** `worker_transaction.py:2519` creates the attempt directory 55 lines before writing `arm.json` (`:2574`); recovery treats any attempt dir lacking `arm.json` as fatal **and the raise aborts the entire recovery scan**. Arming is live in production; the recovery provider is not yet wired, so orphaned arms accumulate unreclaimed. Once wired, one kill in that window makes every resume raise → permanently unresumable audit.
- **(HIGH)** `artifact_ledger.py:828-838` — `_write_semantic_mutations` has **no flush, no fsync**, plain `os.replace`, contradicting its caller's own docstring (*"Durably arm a mutation before any semantic source bytes can change"*). Post-crash the ARMED event is missing, `apply_semantic_invalidation` never runs, and `AUDIT_REPORT.md` is assembled from artifacts derived from a superseded index.
- **(MEDIUM)** `artifact_ledger.py:12192-12246` — `quarantine_invalid_semantic_mutation_ledger` blind-resets the journal to `{"events": []}` with **no lock held** and no CAS, destroying a parallel worker's just-committed ARMED events. Same stale-report outcome, no crash required.
- **(MEDIUM)** `exploration_clear_lifecycle.py:1121-1131` — no fsync, and three durable artifacts published via three independent `os.replace` calls with no cross-file transaction; a crash between them leaves receipt and obligation queue disagreeing.
- **(MEDIUM)** Lock files are the one path bypassing the rooted MAX_PATH layer — in **four** modules. Fails loudly but *before* any arm/debt exists, raising a type callers don't catch, so the worker dies with an unexplained WinError and no evidence trail.
- **(MEDIUM)** The semantic-mutation journal bypasses every path-safety and bounding primitive the module enforces elsewhere; `:12207`/`:12224` are the module's only two unbounded `read_bytes()`; three `NamedTemporaryFile(delete=False)` writes lack `finally: unlink`.
- **(MEDIUM)** Canonical publish is non-idempotent across a hard crash — power loss between publishing the artifact and writing its receipt yields `canonical destination was not ABSENT`, a `PUBLISH_FAILED` debt outside the retry whitelist. A crash in the final second of a completed phase leaves the output on disk yet permanently un-relaunchable.
- **(LOW-MED)** `_atomic_immutable_bytes` exposes a zero-length read window that converts a benign duplicate into a hard collision.

### T-13 → T-18 (export/runbundle layer)

- **(HIGH)** `runbundle_export.py:529-534` — the **export journal**, whose sole purpose is surviving a crash, is the one artifact written non-atomically. A tear locks out both recovery and re-export: the staging dir name derives from the nonce *inside* the journal filename, so deleting the orphan makes the staged generation unaddressable while leaving it makes the freshness gate refuse a fresh export. Hours of audit output become un-exportable, un-recoverable, and un-redoable.
- **(HIGH)** `runbundle_export.py:2573-2592` — `recover_export` **unlinks the journal at `:2582` then hashes the whole staged tree at `:2583` with no journal on disk**, re-writing it only on the failure branch. A kill during the hash converts a recoverable export into an unrecoverable one. **Attempting recovery destroys recoverability.**
- **(MEDIUM)** `phase_io_contracts.validate_writes` — the entire write-containment API (`WriteObservation`, `ContractViolation`, `UNKNOWN_WRITE`, `IMMUTABLE_INPUT_WRITE`, `WRITER_MISMATCH`) has **zero production callers**. Contracts *are* enforced at runtime, but by a different implementation that validates the ledger *record* and never diffs an **observed** write set. The two checks that would catch one worker clobbering another's artifact are exactly the dead ones — in a pipeline whose stated deployment is parallel workers on one scratchpad.
- **(MEDIUM)** `_fsync_directory` no-ops on Windows justified by `MOVEFILE_WRITE_THROUGH` — but that flag is passed only in the directory-rename path, not the `os.link`/`unlink` publication paths, which have no file handle to flush. *(This revises the reviewer's own earlier "deliberate and documented — clean" entry.)*
- **(LOW-MED)** `\\?\` prefixing applied to rename/link/stat but not open/mkdir/scandir/rmtree — now confirmed across four modules, i.e. systemic.
- **(LOW)** `finally` block raises, masking the original publication error.

**Verified clean:** zero missing-`encoding=` defects; `os.rename` never used over a possibly-existing destination; `bounded_artifact_io` **cannot** silently truncate (reads `limit+1` to detect overflow, raises, and every caller propagates); receipts/ledgers are genuinely consumed, not write-only theatre; no error swallowing on any write path; `_ledger_transaction_lock` is a gold-standard implementation; `auxiliary_writable_root_lease` genuinely excludes.

---

## 5B. The core diff — halts, silent gate losses, disabled tooling

Growth is overwhelmingly additive: only **4 symbols vanished by name**, and the driver's 966 top-level functions contain **no duplicate defs** — this is genuine new architecture, not copy-paste. The real signal is **orphaned call sites** and **deliberately neutered gates**.

### D-1 (HIGH) Three haltless-design violations, in a diff that itself bumped `CLAUDE.md` to reassert haltlessness

- **`--fresh` now refuses to start.** `plamen_driver.py:69676` raises `StartupDecisionRequired(...USE_DISTINCT_RUN_DESTINATION)` → `:71399` `sys.exit(EXIT_DEGRADED)` when `has_prior_progress`. That predicate now also counts **project-root artifacts** (`:69616`), so **re-running `--fresh` on any project that already has an `AUDIT_REPORT.md` halts before recon**. Legacy pre-`run_id` checkpoints halt too. Breaks workflows documented in README and the codex-adapter. Highest-consequence haltless violation.
- **Terminal `REPORT_INTEGRITY` withdraws the deliverable.** `:78102` `_quarantine_report_integrity_no_ship` **moves `AUDIT_REPORT.md` out of the project root** (`canonical_path_removed: True`) and the snapshot then yields nothing. The old terminal block shipped the report and merely logged degraded phases. Against the stated policy of surfacing unfinished obligations as Appendix-B items, this produces **no client artifact at all**.
- **`report_assemble` and L1 `bake` degrade → exit.** Previously `checkpoint.degraded.append(...) + continue`; now quarantine + `sys.exit`. A single `OSError` writing one status file now kills an L1 run. `sys.exit` count rose 42 → 45.

No inverse violations were found (no raise→silent-pass; zero bare `except` in either version).

### D-2 (HIGH) Two safety gates silently unwired — functions intact, callers gone

Both are **one-line re-wires**, the best value/effort in this review:

| Gate | Function still exists | Old caller |
|---|---|---|
| Auth fail-fast `detect_not_logged_in` | `plamen_driver.py:29716` | `:14919` |
| **Anti-PoC-fabrication scan** `_validate_poc_pass_integrity` | `plamen_validators.py:31274` | `:20918` |

The second guarded precisely the un-cross-checked class: it downgraded `[POC-PASS]` → `[CODE-TRACE]` for missing or trivial assertions, skipping ids that mechanical verify actually passed. The first guarded the "burn the entire budget re-running an unauthenticated CLI" mode.

Also dropped with no equivalent anywhere: the cross-batch coverage ledger append (Phase 5.2), and `flip_verdict_on_integrity_downgrade` — tag demotion survives, but the `CONFIRMED → CONTESTED` flip does not, so a mechanically-disproven exploit can still ship as a verified Critical for any consumer keying on `**Verdict**:`.

### D-3 (HIGH, recall-negative) Three analysis capabilities silently disabled by changed defaults

| Capability | Change | Effect |
|---|---|---|
| **Sec3 X-Ray** | `_SEC3_XRAY_IMAGE` → `""`, new regex demands a digest-pinned ref, and the only override key `config["sec3_xray_image"]` has **2 read sites and 0 writers** | **Off for every Solana audit** |
| **Opengrep rules** | base path → `None`, clone-on-demand removed | Off wherever submodules are uninitialized — which they are on this machine |
| **forge-std bootstrap** | install → `"unpinned dependency installation skipped"` | Flat `.sol` scopes lose the harness ⇒ PoCs degrade to `[CODE-TRACE]` |

Failing *silently* rather than surfacing debt is the worst possible shape for a recall-first pipeline.

### D-4 (MEDIUM, precision-degrading but recall-safe) The severity-cap cluster is suspended

All severity-*lowering* authority was deliberately switched off pending a "typed authority cutover" that has not happened: Skeptic-Judge DOWNGRADE returns `{}`; the M4 INDEPENDENT-MIN cap has 0 callers and the validator regex now explicitly *refuses* the token; PoC-FAIL caps return `{}` (*"deliberately no live issuer yet"*); the UNRESOLVED/PARTIAL one-tier demotion was removed. `rules/phase6-report-prompts.md` was edited to match — **but `rules/report-template.md:222-232` still advertises INDEPENDENT-MIN as active**, so an LLM following the doc emits a token that trips the provenance gate.

### Recall-positive changes worth crediting

The `axis_coverage` skip-guard was retired so the phase always runs; **Gate P moved *before* `verify_queue`** so recovered orphans reach verification; promotion-dedup blocking thresholds and inventory percentage tolerances were replaced by exact reconciliation; nested `lib/` is no longer skipped. Two apparent deletions I had flagged — Gate V's `compute_axis_coverage_gaps` and `promote_enumgap_exploration_to_inventory` — **both still exist and are called**; and `FOUNDRY_PROFILE`/env propagation survived the `subprocess.run` → `_run_owned_process` swap, so the earlier RC-harness bug did not recur.

### Scaffolding: clean

Across 93,701 added lines: zero `breakpoint()`, `pdb`, `if True:`/`if False:`, `assert False`, hardcoded host paths, or personal names. The 3 `TODO` hits are placeholder-*detection* constants; 7 bare `print(` calls are CLI messaging. One pre-existing (not introduced) dead-code block: `codex_adapter.py:1097` bare `return` followed by ~245 unreachable lines.

---

## 6. Architecture — did 299K LOC make the core simpler?

**No. Measurably the opposite.** ✅ VERIFIED (driver LOC, gate wiring).

| Metric | origin/main | working tree | Δ |
|---|---:|---:|---:|
| `plamen_driver.py` | **22,280** | **78,168** | **+251%** |
| `main()` | 4,365 | **7,026** | +61% |
| `_run_phase_validators()` | 1,954 | **2,533** | +30% |
| `run_phase()` | 1,425 | **1,973** | +38% |
| functions > 300 lines | 5 | **28** | 5.6× |
| functions > 100 lines | 36 | **167** | 4.6× |

Plus `plamen_validators` +9,084, `plamen_parsers` +3,211, `plamen_mechanical` +2,138, `plamen_types` +1,183. **≈370K lines added, 0 removed.**

The tell: the two modules `CLAUDE.md` designates "the shared mechanical substrate" — `plamen_contracts.py` (386) and `plamen_markdown.py` (268) — received **+0 lines**, and `plamen_markdown` still has 2 production importers.

**A-1. The strangler never strangled.** `architecture/method-application-rfc.md` specifies a typed-sidecar strangler with 7 migration steps; steps 6–7 (delete the legacy counterpart) were never run. *Fix: make each authority's landing include deleting its legacy path; gate merges on a non-increasing driver-LOC budget.*

**A-2. The flagship gate subsystem is dead.** ✅ VERIFIED — `grep -c 'mechanical_gate' scripts/plamen_driver.py` → **0**. 9,653 LOC of `mechanical_gate_*` governs a dispatch chain it does not control; 33 of 36 registry gates are `LEGACY_ACTIVE_UNGOVERNED` with `baseline_review_status: UNREVIEWED`. `mechanical_gate_runtime.py:10-14` concedes its executions are *"observable shadow/debt receipts, not proof."*

**A-3. Markdown parsing has 23 live reimplementations and 0 reuse** of the purpose-built AST parser; 139 pipe-split sites across 30 non-test files. **Two already-fixed bugs were resurrected** — the `"---" in s` separator heuristic (rejected at `plamen_parsers.py:688-697`, live again at `chain_candidate_inventory_union.py:114` and `enumeration_gate.py:3235`) and the empty-cell index shift (fixed at `plamen_prompt.py:2250`, live again at `plamen_validators.py:14525`). Highest blast radius: every other decision reads its inputs through one of these.

**A-4. Finding-ID grammar fragmentation — 22+ live grammars, two proven opposite-direction defects.**
✅ VERIFIED: `plamen_mechanical.py:6852` is `_REPORT_DEDUP_AGENT_ID_RE = re.compile(r"\b([CHMLI]-\d{1,3})\b")`. Executed: `'L1-C-12'` → `['C-12']`, `'DEPTH-H-3'` → `['H-3']` — it **silently fabricates public report IDs from distinct internal ones**, across 6 call sites in the dedup builder, and `plamen_parsers.py:571-577` documents this exact leak as forbidden. Conversely `poc_demotion_scope.py:38` requires a ≥2-char prefix, so **every canonical report ID (`C-01`, `H-1`, `M-3`) fails `fullmatch`**. `report_disposition_authority.py:79-81` carries a comment documenting this bug class being found and fixed once — **the fix was never propagated to the other 27 modules.**

**A-5. 24 modules / 39,824 LOC are unreachable from any of the 18 entry points — all with tests.** Green tests over dead code manufacture false confidence. *(Note this is reachability from entry points, a stricter measure than the reference check that found 0 orphans; both are true.)*

**A-6. Severity: 5 independent rank tables in 3 polarities**, two opposite polarities in the same file (`plamen_validators.py:11276` 4=Critical vs `:30470` 0=Critical), plus a shadow normalizer returning `None` where canonical returns `"Medium"`, plus a real bypass at `plamen_parsers.py:7307` where a decorated cell `"**Medium**"` ranks −1 and is silently excluded from the Medium-and-above gate. Currently latent — the canonical path wins the traced decision — but this is a loaded gun.

**A-7. 53 cycles broken only by lazy in-function imports**, centred on `plamen_parsers` ⇄ new authorities. Acyclicity is a workaround, not a property.

**A-8. 135 exception classes across 128 modules, no shared base** — callers cannot write one `except`.

**A-9. Abstraction density:** median **526 LOC per call site** in the `_authority` family (range 12 → 2,122); **47 modules have exactly one production call site**, several very large (`claude_attempt_profile` 5,237 LOC → 1 site). **37 of 38 `_authority` modules appear in zero documentation.** These are *not* empty ceremony — the family averages 7.5 public + 20.4 private functions — but the suffix carries **no interface contract**: 7+ competing verb families under one name.

**Integration is mostly real:** of 15 sampled modules, **11 LOAD-BEARING** with verified control-flow effects (e.g. `plamen_driver.py:24849` raises; `:68443` sets `passed = False`; `plamen_parsers.py:10876-10888` mutates a finding's severity), 4 DEAD, 0 advisory-only. Whole-population: 145 modules / 240,921 LOC reachable from the driver.

---

## 7. Methodology, gate registry, schemas

**Part 0: PASS, zero violations** across 472 files / ~167K lines. Strongest evidence: `review_fixtures/program_facts_b0_fixture_control_roster_v1.json:7070` carries a machine-checked genericity denylist with `"hits": [], "pass": true` — a formal Part-0 receipt. Real protocol names appear only inside assertions that they are **absent**.

**M-1. The provisional gate set is pinned to a registry generation that no longer exists.** The provisional registry's `authoritative_registry.sha256` = `5acf9a84…` resolves to the **empty 14-line stub** committed at `4c22f8b` (`gate_records: []`); the live registry is `5066eda9…`. It also claims `schema_version: v1` where the live file is v2, and its own validator **hard-requires v1** — so it **cannot be refreshed** without editing its validator. A frozen fork, not a staging area. *(Good news: it is not the "two registries, one live" footgun — a hard string constant plus an equality guard means no resolution ambiguity.)*

**M-2. The canonical registry does not load against its own repo.** Every positional and digest binding has drifted — `axis.finding_delivery.inventory_append` declared at `plamen_driver.py:57464`, actually `:60817` (−3,353 lines); `migration.source_tree_digest` declared `5d062888…`, recomputed `23d35aac…`. Result:

```
GateRuntimeAuthority.from_paths(installed_root=ROOT)
  → ActivationInventoryError: activation inventory differs from deterministic source discovery
```

Digest enforcement genuinely works — it is currently reporting drift.

**M-3. The AST gate detector has zero adopters and an empty harvest passes by construction.** `discover_literal_activations()` returns **0 rows** on the real tree; all 63 manifest rows are registry echoes; and `test_mechanical_gate_stage1_static_inventory.py:39-52` **asserts** `literal_runtime_registration_present is False` for all of them. A regression breaking `visit_Call` outright would fail no repo-level test. This is precisely the project's own recorded rule — *"empty harvest + empty diff = silent pass"* — recurring.

**M-4. The anti-bloat equation has no floor.** All six `seam_budgets` have `gate_budget_ceiling: null`, so `post_change_gate_count ≤ ceiling` is unevaluable. The governance the two commits created cannot currently enforce anything.

**M-5. Live v2 payloads ship unvalidated.** `program_facts_positive_composer.py` and `program_facts_publication.py` emit and publish `mechanical_program_facts{,_receipt,_debt}.v2.json` stamped with a schema version while importing **no validator** — three detailed schemas guarding live production data that nothing enforces. Schema coverage is **inverted relative to authority**: every non-live provisional artifact has a declared schema; the live activation baseline and hash receipt have **none**. 20 of 51 schema targets are test-only; 6 cross-file `$ref`s are unresolvable and crash a stock validator.

**M-6. Prompt-vs-parser contract table** (the highest-value technical output): 13 contracts checked — **7 MATCH, 6 MISMATCH.** The worst are R-6 above (8/8 parenthetical labels), the application-skeptic vocabulary split, and an under-specified projection-table header that silently yields `None`. Best-engineered: the `phase6b0` repair contract and the skeptic row contract, both byte-exact with ordered coverage checks.

**M-7. Contradictions with existing methodology.** The RAG axis was removed in code and rules but **three docs still specify `RAG Match × 0.2`** (`docs/architecture.md:137`, `docs/audit-modes.md:20,47`) and `orchestrator-rules.md` Rule 13a still lists the RAG sweep as NEVER-CUT. Composite max is now 0.8 with **thresholds unchanged at 0.7** and `Consensus: one observer = 0.0` — the arithmetic behind R-1, and undocumented. The Core/Light formula exists **only in code**. Three new phases (`application_skeptic`, `severity_adjudication_shadow`, `report_evidence_repair`) are fully wired and appear in **zero** docs. New terminal-negative vocabulary (`OUT_OF_SCOPE`, `ALIAS_TO_SURVIVOR`, `REFUTED_FULL`, `ZERO_HARM`) has **no crosswalk** to the report template's **closed** token set — a report agent encountering closure-broker output has no legal way to record it.

**M-8. Doc claims: 15 accurate, 2 wrong, 3 stale.** `work-unit-scheduler.md:57-65` publishes a state vocabulary mis-naming 2 of 6 values vs `adaptive_attention_types.py:66`; `method-application-rfc.md:62-64` points at a retired 10-line redirect for a crosswalk that exists nowhere (circular). The 7 `adaptive_attention_*` modules are documented as dispatching work but `grep adaptive_attention scripts/plamen_driver.py` → **0**. Program Facts silently no-ops for Daml, Solana, Soroban, Move and both L1 pipelines despite a contract promising typed debt "including when empty".

**M-9.** `methodology/method-cards-v1.yaml` **is canonical JSON, not YAML** — it begins `{`, is read by a JSON parser requiring byte-exact content, and any editor/linter/CI YAML step that touches it by extension corrupts the digest chain.

---

## 8. Test and CI health

| Measure | Result |
|---|---|
| Syntax / import (656 new files, 180 modules) | **0 failures** |
| Collection from repo root | 14,225 tests, 0 errors |
| **Collection as CI invokes it** | **ABORTS — 0 tests run** |
| New-test sample (8 files, 120 tests) | 119 pass, 1 deterministic fail |
| Pre-existing sample (9 files) | 3 deterministic failures + 2 errors, 1 flake |
| Modules with zero tests | 4 (2,102 LOC) — all production-wired |
| Undeclared dependencies | `cryptography` (unguarded), PyYAML, packaging |

Untested and production-wired: `live_verify_queue_executor.py` (825 LOC), `inventory_aggregate_authority.py` (499), `late_delivery_authority.py` (472), `internal_identity_privacy.py` (306).

Other CI facts: the integration lane has **no per-test timeout** (`pytest-timeout` is not declared) and **no job sets `timeout-minutes`**; `requirements-dev.txt` pins `pytest==9.1.1` while 9.0.3 is installed; the suite contains wall-clock timing assertions that will flake on loaded runners; `test_driver_smoke.py` did not complete in 600 s and remains **unverified** (slow vs hung is undetermined).

---

## 9. Hygiene and privacy of the new material

**PRIVACY VERDICT: no client or audit data in the new untracked material.** Zero hits for wallet addresses, API keys, PEM headers, Solidity/Rust/Move/DAML source, or findings tied to a protocol, across 289 `review_fixtures/` files, 172 `bpc_*`/`bpa_*` files, `benchmarks/`, `architecture/`, `methodology/`, `verification_policy/`, `rules/schemas/`. The only finding-shaped text in 166K lines is a synthetic assertion string. **This is not a second `write_dedup.py`.**

What *is* wrong: §P0-3 above, plus —

- **364 occurrences of `<LOCAL_USER_ROOT>` across 127 files**, and the private repo name `<PRIVATE_EVALUATOR_REPO>`.
- **A real bug in the repo's own privacy guard**: `_PRIVATE_TEXT_MARKERS` is escaped wrong and matches only the doubled-backslash form, so it cannot catch the plain Windows path as it appears in markdown. Consequence: `benchmarks/application-coverage-evaluation-plan.md` is in `_REQUIRED_LIVE_ASSETS` — **guaranteed to ship** — and line 28 contains `` `<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>` ``. The guard silently passes it.
- Test-residue is a **false alarm**: 29 `.tmp*` dirs (~34 MB), all correctly ignored. (An earlier "~569 dirs" figure was wrong.)

Directory dispositions: **commit** `architecture/`, `methodology/`, `verification_policy/`, `rules/schemas/`, `benchmarks/` (after scrubbing line 28), the 3 new docs, and the CI files. **Gitignore** `review_fixtures/`. **Delete** the 9 `bpc_*`/`bpa_*` dirs and add `/bp[ac]_*/`.

---

## 10. Corrections — subagent claims I overturned

Recording these because they cut both ways and a reader should know the error bars.

1. **"No producer prompt mandates `**Source IDs**`"** — **partly wrong.** Five ecosystem inventory prompts *do* mandate it (`prompts/{evm,solana,sui,aptos,soroban}/phase4a-inventory-prompt.md:40,61`, listed among "8 required field labels"), and the parser matches them including the `- ` list prefix. **R-1 still stands** for a different and narrower reason: the consensus denominator is the **pre-inventory depth set**, and the *depth* worker contract does not mandate the field. The gate is disabled; the originally-stated cause was too broad.

2. **"`review_fixtures/` is not ignored" vs my `git check-ignore` returning 'ignored'** — the **agent was right and my first check was misleading.** `git check-ignore` behaves differently with a trailing slash on this `.gitignore` (which uses a `scripts/*` denylist plus 197 `!` negations). The authoritative signal is `git status --porcelain`, which reports `?? review_fixtures/`. It **would** be committed.

3. **An initial hypothesis that `isolated_execution_host`'s `exec(compile(...))` was attacker-influenced** was investigated and **refuted** — the source is a digest-verified, handle-sealed CAS copy, and non-Windows fails closed.

4. **A `.cmd`-injection claim against the newer materialization path** was **refuted** — that path is gated. S-1 is scoped to the legacy PTY path only.

5. One agent's own note: its first attempt to test the privacy-marker escaping was corrupted by shell quoting and produced a **false "guard works"** result; the reported verdict comes from reading the constant out of source and comparing bytes.

6. **"CI has been running zero tests" — my own error, corrected.** I reported this as a headline P0 on the strength of a reproduced local collection abort. A later slice overturned the *mechanism*: `scripts/bounty/` is gitignored and untracked (✅ verified), so it is **absent from a CI checkout** and CI does not abort. The abort breaks the local inner loop only. The underlying concern survives in a different and arguably worse form — CI is green because it tests the tracked subset, which excludes essentially all of this work, and the first real commit turns it red via the untracked `requirements-ci.constraints`. §P0-2 was rewritten accordingly. The lesson generalises: *a reproduced local failure is not evidence about CI until you check what CI actually checks out.*

---

## 11. Recommended sequencing

**Before anything else — protect the work.** 11 unpushed commits plus a ~115K-line uncommitted diff and 691 untracked paths exist on **no remote**. A bad `git clean` destroys the entire program. Push the branch and commit-or-stash the working tree first. This outranks every finding below.

**Tier 0 — do not hand off until these are closed**
1. **Run the full suite.** One targeted slice already shows **36 failures**, mostly in the author's own new tests. Nothing below can be assessed against an unknown baseline.
2. `write_dedup.py`: remove from both trees; decide history rewrite + client notification (54 forks).
3. Fix the commit boundary: track `requirements-ci.constraints` / `requirements-ci.lock` / `scripts/ci_dependency_authority.py` (otherwise `pip install -r requirements-dev.txt` fails for everyone), normalize the `scripts.bounty` import, add repo root to `pythonpath`, and commit the tracked + untracked halves **together** (the driver has 72 top-level imports of untracked modules).
4. Repair SC report-index recovery (§P0-4 #1) — the canonical-head exemption and the arm-time binding.
5. Gitignore `review_fixtures/`; relocate its 5 load-bearing modules to `scripts/_test_support/` and update the 24 imports.
6. Decide on the two halts: `--fresh` refusing to start on any prior progress, and terminal integrity failure **withdrawing `AUDIT_REPORT.md` entirely**. Both contradict the haltless contract this same diff reasserted in `CLAUDE.md`.
7. Declare `cryptography` (+ PyYAML, packaging).

**Tier 1 — one-line fixes with outsized effect**
8. Re-wire the two orphaned gates: `detect_not_logged_in` and `_validate_poc_pass_integrity`. Both functions are intact; only the call sites are gone. Best value/effort in the review.
9. `artifact_ledger.py:1613` → `_ledger_transaction_lock`. Silent, destroys committed records.
10. Add `(?:\s*\([^)]*\))?` to `inventory_reconciliation._FIELD_RE`, and add the fixture that feeds the literal canonical template through every field parser. **This one test makes the entire class impossible.**
11. Assert `any(status == "CURRENT")` in consensus, so R-1 becomes loud instead of silent.
12. Re-enable the three silently-disabled capabilities (Sec3 X-Ray's unreachable config key, opengrep, forge-std) **or** make each emit visible debt. Silent capability loss is the worst failure shape for a recall-first pipeline.
13. Fix `_PRIVATE_TEXT_MARKERS` escaping and scrub `benchmarks/…:28`; reconcile `report-template.md:222-232`, which still advertises the now-suspended INDEPENDENT-MIN cap.

**Tier 2 — structural, before this becomes canonical**
14. Generate niche ID prefixes from the SKILL.md files with a parity fixture; ban local ID regexes; kill `_REPORT_DEDUP_AGENT_ID_RE`.
15. Fix the four HIGH security items (S-1…S-4) and stop mutating the user's global Claude settings (S-5).
16. Make the recovery machinery at least as durable as what it protects (T-1, T-2, T-6, T-13, T-14).
17. Either wire `mechanical_gate_*` into `_run_phase_validators` or delete 9,653 LOC. Same question for the 24 unreachable modules / 39,824 LOC.
18. Set a driver-LOC budget and execute RFC steps 6–7, or the next 300K lines land the same way.

**The pattern worth internalizing:** the most dangerous defects in this change are not crashes — they are **gates that report success while structurally disabled**, and **fixtures that assert the shape production never produces**. Three independent instances (R-1, R-2, M-3) plus the project's own recorded history of exactly this failure mode suggest a standing rule: *every gate needs a fixture built from the real producer's output, and an assertion that its denominator is non-empty.*

---

# 12. Post-Handoff Improvement Backlog

*Added 2026-08-01, after a six-thread research round (see `CLAUDE_RESEARCH_recall_architecture_2026-08-01.md`). This section is written to be handed to Codex as post-handoff work. Presence/absence claims below were verified directly against this worktree, not inferred.*

## 12.1 The comparison, in one line

**Codex built the provenance layer — "can we prove what we did" — at enormous scale. The binding gap is the anchor layer — "is what we did true." Those are different, and this build does not close the second one.**

Ledgers, receipts, authorities, digests, debt rows and replay bindings are machinery for *recording and governing* decisions. They make the pipeline auditable. They do not make any single verdict mechanically true, because every one of them ultimately records an LLM's judgment with a hash attached. The research round converged, from six independent directions, on the conclusion that what Plamen lacks is **nodes whose verdict is produced outside agent judgment entirely**.

## 12.2 Credit where due — assets this build already created

Four of these are genuinely valuable and should be *built on*, not rebuilt:

| Asset | What it is | Why it matters |
|---|---|---|
| `program_facts_*` (~10 modules) | Typed, **emit-only** Slither provider: registry-bound plan, **pinned** `slither-analyzer 0.11.5`, digest-bound helper identity, and an explicit docstring disclaimer that no object it returns has "negative, clean, finding, severity, publication, or consumer authority" | This is precisely the *static-analysis-as-queryable-context-provider* pattern that won AIxCC for Buttercup — and it is built with correct authority hygiene. **The single best foundation in the build for what follows.** |
| `tool_coverage_ledger.py` | *"Haltless must not mean 'clean': every attempted capability records one schema-validated outcome."* stdlib-only so recon can use it pre-install | This is Trail of Bits' **"No Zero-Count Scripts"** discipline, mechanically implemented, and it is exactly the countermeasure to the silent-pass class §M-3 documents. Extend it; don't duplicate it. |
| `precedent_evidence_authority.py` + `rules/precedent-evidence-policy.md` | Precedent contributes `0.0` to mechanism/code confidence; capped at four `false` authority flags; tool failure is `UNSCORED`, not a floor score | Correct call, and independently supported by the research: historical/RAG precedent should not carry confidence weight. Keep. |
| `application_skeptic.py` | Reopen-by-default; missing assessment, self-adjudication, invalid digest and unknown outcomes all route to reopen | Verified fail-visible in §4. Sound design. |

## 12.3 What is absent — verified, not assumed

| Research recommendation | Present in this build? | Evidence |
|---|---|---|
| **Mutation testing / invariant vacuity gate** | **ABSENT** | Zero hits for `gambit`, `mutant`, `mutation score`, `slither-mutate`, `cargo-mutants`, `universalmutator` across `scripts/`, `prompts/`, `rules/`, `agents/` |
| **Symbolic execution lane** | **ABSENT as a capability** | `halmos` appears only inside command *allowlists* and harness-*detection* regexes (`plamen_driver.py:41208,42560`, `plamen_validators.py:22257`). The pipeline permits a worker to run it; nothing drives it. |
| **Agent read-coverage (aicov pattern)** | **ABSENT — but the data already exists** | `tool_calls.jsonl` is written (`plamen_driver.py:39523`). Its only consumers are `max_tool_calls_total` budget caps in `backend_capability_registry.py`. Nothing computes which source files an agent actually opened. |
| **Composition / unowned-validation-obligation class** | **ABSENT** | No skill, no trigger flag, no methodology anywhere in the tree |
| **Cross-model skeptic** | **NOT ENFORCED** | No model separation between the verifier and the skeptic that checks it |
| **Output-cap recall leak** | **CARRIED FORWARD UNCHANGED** | **48 occurrences** of `Maximum N findings` / `prioritize by severity` in this worktree's `prompts/` and `rules/` |

## 12.4 The irony worth naming

**The socket for anchors was built. It is unplugged, and it has no floor.**

`mechanical_gate_*` is 9,653 LOC with a JSON schema, an activation baseline, seam budgets and a gate-count governance equation. Verified state of the canonical registry:

```
gate_records:            36
baseline_review_status:  UNREVIEWED
seam_budgets:            6  |  ceilings: [None, None, None, None, None, None]
driver references:       0
```

So: the governance frame for mechanical gates exists, contains 36 records, is unreviewed, cannot enforce a budget (every ceiling is `null`), and is referenced nowhere in the driver. **The frame was built before the things it governs.** That inversion is the clearest single illustration of §12.1 — enormous investment in the apparatus of rigor, ahead of the rigor itself.

The good news: this makes the backlog cheaper than it looks. P-2 below plugs into a socket that already exists.

## 12.5 The backlog

Ordered by value-per-effort. Each item states where it plugs into *this* build.

### P-1 — Remove the output-cap recall leak *(hours)*
48 instances of `Maximum N findings` / `prioritize by severity` in producer prompts. Trail of Bits measured that upfront severity filtering "causes the agent to investigate thoroughly, then suppress output, making **precision rise while recall collapses** — appearing as a capability loss when it's a prompt problem."

Keep *input* caps (context management, AD-3). Remove *output* caps and severity-prioritization from producer prompts; emit everything with severity attached and filter downstream, where `report_disposition_authority` and the Material-Harm floor can **ledger what was dropped**. A suppressing agent leaves no record; your disposition machinery does. Also remove the self-certification at `prompts/*/self-check-checklists.md` (`Anti-dilution: max 5 findings per agent per iteration?`).

### P-2 — Mutation testing as the first real anchor: `[SPEC-KILL: n/m]` *(2–3 days)*
Generate mutants with Gambit (free, standalone, 34 mutants in 0.69s); an invariant from Phase 4a.5 that kills zero mutants is **vacuous** and must not support any disposition.

Calibration that makes this urgent: across two Certora Rust FV contests (47 participants, 40,000 USDC in prizes), **2,623 human-written formal rules — only 23–28% killed a single mutant.**

**Plugs directly into this build:** register `[SPEC-KILL]` as a gate in `mechanical_gate_registry.json` (which has 36 records and no live gates), record outcomes through `tool_coverage_ledger` (already stdlib-only and schema-validated), and treat a `0/m` result exactly as the existing referent-less-exclusion rule does — a suppressed unknown, re-emitted downstream, never a clean result.

**First experiment, one engineer, one day:** hand-translate one completed audit's invariants to Foundry assertions, run Gambit, measure the kill rate. Below ~25% means Phase 4a.5 produces decorative output — a bigger finding than anything else in this backlog. At or above, you have the pipeline's first mechanically-true metric.

### P-3 — Mechanical read-coverage from `tool_calls.jsonl` *(1–2 weeks; the data is already on disk)*
Replace the self-attested `| File | Lines | Opened? |` checkpoint (`rules/phase3b-rescan-prompt.md:259`) with driver-side computation of which in-scope files each worker actually opened, and auto-spawn follow-ups for under-covered files. Trail of Bits built exactly this ("aicov") after hitting the identical failure — agents "skip reading the entire codebase even when explicitly asked" — and stated the purpose plainly: *"so the model can't cheat."*

This converts a self-certifying gate into a real anchor **using a file this build already writes**, and it directly attacks the documented dominant miss class (attention/coverage), not a hypothetical one.

### P-4 — Cross-model skeptic + brocard pre-PoC triage *(routing change + small gate)*
Route the skeptic/judge to a **different model family** than the verifier that produced the finding; ToB's FP pipeline is explicitly "a two-pass false-positive gauntlet using different models." Currently the disagreement signal is correlated with the thing it checks.

Add the seven brocards as an ACCEPT / DISMISS / NEEDS-MORE-INFO gate *before* PoC spend. Brocard #2 — *"no exploit from the heavens": dismiss if the attacker's existing capabilities already encompass the claimed impact* — is a principled replacement for the ad-hoc trusted-actor severity modifier. All seven are generic and Part-0 clean. Route DISMISS to the appendix, never to a drop.

### P-5 — The composition class: three-line always-on extend, then the full skill *(3 lines, then ~150)*
Ship the one-line version first — extend the existing pre-auth panic directive with: *"…or before the generic decoder/validator whose guarantees the consumer assumes. Name the `file:line` that owns the check on this path. 'The framework validates it' without a `file:line` is not an owner."*

Then the full injectable skill (drafted and Part-0 self-audited in the research round): **frame it as ownership, not ordering** — the same researchers found two Criticals in one codebase eight days apart, and only one had an ordering defect. Detection is a matrix (rows = obligations, columns = every layer, cells ∈ ENFORCES/PARTIAL/DECLINES/DEFAULT-PERMISSIVE/ABSENT), with a **shared-fate gate** as the false-positive control and a mandatory dispositioned three-synonym grep behind every ABSENT claim. Zero budget slots — it synthesizes `trust_boundaries.md`, which this pipeline already produces and never analyzes.

### P-6 — Symbolic execution as a PoC *generator*, EVM only, refutation-only *(1 week pilot)*
For Medium+ findings terminating at `[CODE-TRACE]`: restate the existing harm assertion, run `forge test --symbolic --json`, and on FAIL feed the emitted **concrete** regression test through the PoC path that already exists.

**Never consume a PASS.** Foundry's own docs say treat incomplete as "not established, not a proof"; the lane ships with **no vacuity check**; and LLM-generated invariants compile at 96.7% but block a real exploit at **20.4%**. Blocking prerequisite: an `assert(false)` vacuity guard — Certora's default-on `rule_sanity` check, imported into a lane that lacks one. Expect near-zero conversion on AMM/lending/economic findings (nonlinear arithmetic); that is the expected result, not a tuning target.

### P-7 — Narrow-then-widen variant analysis *(medium)*
Rewrite the sibling sweep as: a pattern matching **only** the confirmed bug → generalize **one element at a time** → validate each widening mechanically (must fire on the known-vulnerable site, must stay silent on a known-correct sibling). That validation criterion is the point: it makes variant coverage checkable without LLM judgment. Targets the recorded dominant miss class.

### P-8 — Governance: give the gate registry a floor, or delete it *(small, but do it before P-2 lands)*
All six `seam_budgets` ceilings are `null`, `baseline_review_status` is `UNREVIEWED`, and the driver references the subsystem zero times. Either wire `evaluate_registered_gate` into `_run_phase_validators` and set real ceilings, or delete 9,653 LOC. **Do not add P-2's gate to a registry that governs nothing** — that reproduces the exact pattern this audit documented.

## 12.6 Explicitly do NOT build

This list matters as much as the backlog, because the failure mode this build already exhibits is accretion, and every item below is a plausible-sounding 50K-line detour.

- **A mutation-based recall benchmark.** Falsified directly: only **3.9%** of generic mutants semantically mimic a vulnerability, and in the decisive experiment — by LAVA's own authors, 80+ CPU-years — **no fuzzer found any of 50 organic bugs while routinely finding synthetic bugs in the same binaries.** Zero transfer. Use mutation for *invariant vacuity* (P-2) and regression only; never as a recall number.
- **Certora AutoProver.** Six GitHub stars three weeks post-launch, Solidity-only beta, five PostgreSQL databases, zero published benchmarks — and its parallel property-extraction phases duplicate what Plamen already does. Its "revise failed specs" loop has no documented vacuity gate, which is the textbook reward-hacking shape.
- **Any standalone symbolic tool.** Manticore and Optik archived, Halmos dormant since 2025-08-06, greed/ityfuzz/Pyrometer dead. The category is consolidating into Foundry. Adopting Halmos a year ago would have bought a dormant dependency.
- **Fan-out-then-debate as an architecture.** Six compute-matched studies find single-agent matches or beats multi-agent at equal token budget, with debate inducing sycophancy up to **85.5%**. This does *not* refute parallel **scope partition** — different agents reading different code — which is what Plamen actually does and should keep.
- **Verification scaffolding in prompts** ("double-check your answer"). ToB reports these reduce output quality; verified clean in this tree — keep it that way.
- **SMTChecker migration.** Verified unused; its BMC deprecation is a non-issue here.

## 12.7 Topology addendum — the anchor inventory

*Added after the topology analysis completed. It produced a sharper framing than §12.1 and I'd adopt its wording:*

> **Plamen's real anchors are enumeration anchors, not judgement anchors.**

Mechanically-true verdicts exist in roughly four places: PoC re-execution, recon's build/Slither/SCIP/OpenGrep subprocesses, driver-built ID sets (verification queue, coverage seed, chain/dedup candidate pairs, data-loss gate, supply-chain gate), and the fuzz-*scheduling* decision. **Every artifact carrying a security verdict** — severity, status, PoC outcome, confidence, disposition, precedent score, and every fuzz *result* — is LLM-written, or Python arithmetic over an LLM-typed field.

The mechanical truth is computed and then largely **discarded at the seams**: an anchor's output is laundered through prose `Evidence Tag`, prose `Independent Severity`, prose `Impact:`/`Likelihood:` fields before it reaches the report.

**And this is not deception.** Gates rarely lie about passing; they are honestly, deliberately warning-only, and the driver is documented as "bounded retry, then ship" — the right posture for a haltless recall-oriented pipeline. The problem is that **`CLAUDE.md`, `orchestrator-rules.md` Rule 15, and `report-template.md`'s token tables describe a mechanically-enforced system while the code implements an advisory one.** Either close the gap or state the posture honestly. Right now the docs write cheques the driver doesn't cash.

### Verified additions to the backlog

**P-9 (CONFIRMED) — PoC-fail demotions are computed before any test runs.** ✅ I verified this directly: `sc_verify_aggregate` is defined at `plamen_types.py:1423`, `sc_mechanical_verify` at `:1433`, so aggregate runs **first** — and `_apply_poc_fail_demotions` / `_apply_independent_severity_caps` execute at `plamen_driver.py:15361/15367` under a `phase.name in (…"sc_verify_aggregate") and passed` guard at `:15317`. So `poc_demotions.md` is built **before mechanical verification has executed a single test**, and its trigger is the literal `[POC-FAIL]` string in LLM prose. *Fix: move both applications after `sc_mechanical_verify`. Pure phase-ordering change, makes the ledger mean what its name says.*

**P-10 (CONFIRMED) — Light and Core never fuzz at all.** ✅ Verified at `plamen_driver.py:11267`: the invariant-fuzz builder returns `[]` unless `mode == "thorough"`, and again for `pipeline == "l1"`. Combined with the reported OpenGrep skip in Light, **Light mode may have no mechanical detector pass whatsoever** — meaning its findings rest entirely on LLM judgment with no anchor at all. Decide whether that is intended; if it is, say so in the mode table, because "Light" currently reads as "fewer agents," not "no mechanical evidence."

**P-11 (MECHANISM PLAUSIBLE — VERIFY BEFORE FIXING) — proof-tag substring leakage.** The topology agent reported that `has_mechanical_proof` re-promotes mechanically-disproven findings across 8 call sites. **I could not substantiate it as stated** and am recording it honestly rather than propagating it:

- ❌ The quoted demotion string `"(was [POC-PASS], mechanical integrity=FAIL)"` **does not exist in either tree**, and the cited line (`plamen_driver.py:20111-20115`) is wrong.
- ❌ The two-function split is **deliberate and documented**, not a bug: `plamen_types.py:184-186` and `:200-210` explain that `has_mechanical_proof` stays narrow (test-pass only) while `has_proof_grade_evidence` is the one that "proven-only severity gating must use."
- ✅ **But the underlying mechanism is real.** `has_mechanical_proof` is a naive `any(tag in text)` (`plamen_types.py:195-197`), and `mechanical_verify.py:1341-1343` documents a demotion annotation of the form `"[CODE-TRACE] (was [POC-PASS], integrity downgrade: …)"` and states that the regex **"preserves the line."** So a demoted tag line *can* contain the literal `[POC-PASS]` substring, and any call site passing that raw line to a substring test reads it as proven.

*Action: audit the 19 call sites for which text they pass, then make the check anchored (match the tag at a line/field boundary) rather than a substring scan. Cheap fix, but confirm the exposure first — do not fix on the agent's citation.*

**P-12 — gates that are wired fail-closed but cannot fail.** The agent reported several, of which the pattern matters more than any instance: a validator whose `issues` list is never appended to before return; an SC scan harvesting `[HALT]`/`[GATE FAIL]` tokens that only *L1* prompts emit; and `plamen_contracts.py` — a complete fail-closed typed-contract layer with **zero production imports**, which the first audit independently found and which `CLAUDE.md` still calls "the shared mechanical substrate." Also flagged: two gates carrying comments promising to graduate to fail-closed "after one clean audit cycle" that never did. **Worth a standing sweep for that comment pattern.** A gate that cannot fail is worse than no gate — it reports assurance you don't have.

**P-13 — prompt/parser divergence is a prerequisite, not a follow-up.** The axis-coverage phase previously had a two-part ID regex that silently dropped every three-part heading, **losing 14 findings including a High**; the parser was fixed but `phase4b8-axis-coverage.md:142` still shows the old format. The agent reported **8 unguarded empty-harvest instances** of this shape. This is your own standing memory note — optimistic ID regex → empty harvest → silent pass — and it argues that P-2's mutation gate must ship with the no-zero-count assertion from day one.

**One caveat that applies to this whole section:** neither audit executed the pipeline. Structural claims are measured; frequency claims (how often a branch actually fires in production) are inferred from guard conditions.

## 12.8 The governance point to attach to the handoff

This backlog is ~8 items and should cost on the order of **thousands** of lines, not hundreds of thousands. The audit measured this build at **+370,000 lines added, 0 removed**, with all three god-functions growing and 24 modules / 39,824 LOC unreachable from any entry point.

Attach a budget to the handoff: **each backlog item lands with its legacy counterpart deleted, and the driver's LOC and god-function lengths must not increase.** P-8 exists precisely so there is a live registry to enforce that against. Without it, this list becomes the next 300K lines and the anchor problem remains unsolved underneath a larger apparatus.
