# Changelog

All notable changes to Plamen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **R10 demotion-side gate (external-best-case un-demotion veto) — a new mechanical gate, mirror of the existing assert-side external-assumption cap.** The pipeline already caps a finding whose HARM rides on an assumed *worst-case* external condition (the citation-gated external-assumption brake), but nothing guarded the INVERSE: a finding CONFIRMED-in-scope at depth that a verifier DEMOTED (verdict contested / harm dismissed) purely on an UNCITED *best-case* external assumption — the external question resolved in the safe direction with an empty research ledger behind it. The gate re-detects that shape deterministically from artifacts already on disk (depth verdict via the hypothesis→constituent-inventory join, verifier external-best-case cue, and an absent/stub external-dependency research ledger), floors the report severity back to the depth-claimed value, stamps the finding `[EXTERNAL-ASSUMPTION] + [UNPROVEN-EXTERNAL]`, and keeps it in the report body flagged for human review of the unproven external leg. It is precision-safe by construction — five guards (EXT-CITED grounding present, in-scope-grounded demotion, an executed in-scope PoC of either outcome, depth-REFUTED mechanism, and proof-grade evidence) each independently block a fire — and recall-safe: an absent/unparseable ledger is a strict no-op. Keys only on structural relations; no protocol/token/contract/function names (Part-0). The depth-verdict anchor bridges the queue's hypothesis ids to their constituent inventory findings (including anti-absorption split hypotheses) so the guard engages on real full-pipeline runs rather than silently no-op'ing on an id-scheme mismatch.
- **Post-audit protocol: the RC-AGENT-MECHANIZABLE escape hatch.** A narrow, four-gated exception to "RC-AGENT ⇒ no pipeline change": a recurring (≥3 audits), agent-judgment-free, generic, verify-filtered miss whose correct disposition is fully computable from artifacts the pipeline already produces may route its FIX (not its root cause — RC-AGENT still stands) to a driver-level `mechanical-gate` change instead of no-fix. The prose prohibition is untouched; this only names the driver-code disposition that was already an implicit architecture pattern. The R10 demotion-side gate above is the reference instance.

## [2.2.4] - 2026-07-14

### Added
- **M2 gains a sixth coverage axis: authorization-subject / caller-identity / recipient-consent.** The multi-axis coverage meta-pass now interrogates, for each hot function, whose identity or consent actually authorizes the effect on the target — the recurring miss pattern where a function is examined but "who is acting on whose behalf" is never asked. The detector reads only agent-emitted depth-evidence tags plus one generic prose cue, carries zero ecosystem-specific tokens, and is applicability-gated so it only fires where relevant, routing any gap into inventory-then-verify rather than asserting a body finding directly. The generic "acting on behalf of another party" trigger family used to recognize this shape was also broadened per-ecosystem so a differently-named delegated/managed-for function no longer evades the check.
- **Three recurring recall-miss classes converted from advisory prose into mechanical, graph-grounded gates.** All three are append-only, idempotent, bounded, route low-confidence candidates through the existing verify-the-positives filter and material-harm floor, and are no-ops on absent input. (1) A sibling/variant-coverage gate generalizes the co-referencer enumeration axis into three axes — co-referencer, boundary-input values, and symmetric-operation pairing — emitting variant-gap candidates unconditionally rather than confidence-gated, since the failure mode is a confidently-wrong single-variant analysis rather than low agent confidence. (2) An external-dependency research gate has recon (which has live web-search tools) detect any non-vendored external dependency generically and bake a research ledger to disk; depth phases read the ledger instead of calling unavailable web/MCP tools, and any external-assumption finding must now carry a citation into the ledger or an explicit escalation — an uncited external-assumption tag is capped at code-trace-level evidence. A haltless warning gate flags any still-missing external-assumption research. (3) A promotion-completeness gate does a content-shaped harvest of every intermediate finding artifact (matching on location + mechanism + harm, including malformed/referent-less stub entries) and reconciles it by location against the final consolidated finding inventory, routing any orphaned candidate through the material-harm floor into the report body or an appendix instead of letting it silently vanish.
- **Force-by-default PoC gate closes the self-declared-skip loophole.** A mechanical, label-independent gate now forces any finding with a concrete, stated material harm into an executable PoC attempt unless one of a small closed set of code-grounded blockers applies (fully-trusted-actor design, deploy/transaction-ordering dependency, an external dependency with no available fork, a requirement for a separately-deployed live artifact, or a claim with no on-chain state delta to assert; a refuted verdict also exempts it). Previously the skip decision trusted the verifier's own self-declared PoC-class label, which was empirically unreliable — nearly every observed lazy skip had self-labelled into the class that zeroes the PoC requirement. A forced attempt that still cannot construct a harm-assertion is recorded as a traced-but-unexecuted finding with the specific named blocker, never as a failed/refuted PoC. The same closed taxonomy is now uniform across every supported ecosystem's verification prompt, closing a gap in the ledger-based ecosystem's prompt and adding an infrastructure-blocked-harm carve-out for the node-client audit mode.
- **L1 (infrastructure/node-client) lane rigor, two waves, additive and mode-gated.** Wave 1 wires several previously-unused generic mechanisms into the L1 gate layer: a freshness guard so the code-index bake step is reused rather than always re-indexed on a warm re-run; the four previously-unused scanner agent roles are wired into the L1 depth worker pool; a stale early-return that had disabled sibling-propagation analysis in L1 mode is removed; and a consumer for the existing cross-domain-dependency-tag harvester now feeds low-confidence candidates into the verification queue as the minimal generic replacement for L1's removed chain-analysis phase (L1 bugs are typically point vulnerabilities, not composable chains). Wave 2 extends mechanical verification depth: race/non-determinism/Byzantine-scenario findings are rerouted out of the PoC-exempt "structural" bucket into a testable bucket (this had silently zeroed the mandatory-PoC requirement for exactly the class of bug that most needs an executed proof), while genuinely-untestable classes (timing-dependent, cross-client, eclipse-attack, ordering-dependent) remain deliberately exempt; race/concurrency findings now trigger a race-detector-instrumented re-run with an extended timeout during mechanical verification; two fuzz-engine registry entries and matching skeleton prompt templates are registered for the two supported node-client languages (execution wiring deferred pending a defined crash/no-crash outcome vocabulary); a mechanical dependency-vulnerability scan now runs as a pre-breadth hook, degrading gracefully when the tool isn't installed; and a routing-only fix lets embedded ledger-language source discovered inside an otherwise Go/Rust node-client repo pull in the existing vetted skills for that ledger language.
- **Cross-OS hygiene static gate + full CI matrix.** A new AST-based lint runs as an always-on gate over the driver's own Python source, flagging subprocess/file-open calls missing an explicit text encoding, unguarded platform-only imports on cross-platform code paths, and hardcoded platform-specific interpreter invocations. It ships with an empty allowlist — every violation the gate found in the live tree was fixed in place, not suppressed. A companion CI workflow now runs the full test suite on push/PR across all three supported operating systems (previously only an install-smoke check existed).
- **Fast/integration test-lane split.** The suite now registers unit/integration/slow pytest markers, with the small set of tests that spawn a real subprocess or a real multi-second sleep auto-marked by filename from a single source of truth. A pinned dev-dependencies file adds a parallel test-runner plugin, and CI runs a fast parallel lane (marker-excluded, all cores) alongside a serial integration lane, both across the full OS matrix.
- **Partial DAML language-table entry for the M2 hot-set and identity axis.** The M2 hot-function-set and axis-coverage machinery already ran uniformly across languages (the underlying graph-bake and axis detectors are tag/prose-based, not ecosystem-specific), but had no language-table entry for the ledger-based ecosystem, silently forcing its value-movement/authority-transfer signal to false and over-triggering the not-applicable carve-out. A deliberately partial entry recognizes the language's action-definition and authority-transfer keywords so ledger-based findings join the graph and axis machinery, while a richer field-level parameter-type table is deliberately deferred as unvalidated.
- **Cargo-workspace PoC test discovery** for the ledger-adjacent Rust-based smart-contract ecosystem: the verifier now resolves the correct workspace member via a crate-name-prefix match against source plus a bounded-depth search, threads the matching package-selection flag into the test command, validates that any requested cargo feature is actually declared by that crate before use, captures subprocess output as text explicitly (fixing a hang on non-UTF-8 locales), and warms the build without pinning a feature set.
- **Smaller recall/precision backlog items**: a fail-closed pre-execution supply-chain gate; a second dispatch channel for mechanically-detected skill triggers; two narrow-scope injectable skills (dust-supply divergence in share-based accounting; coupled-cache coherence); a role-gated false-positive guard for a permissionless-setter detector; a blind-first independent-severity cap (assessed before seeing the pre-assigned severity, capping rather than raising); an identifier-existence sanity gate for low-severity findings; an opt-in cross-vendor skeptic backend override; opt-in yield-gated additional breadth passes; report-dedup same-tier candidate hints with a coverage receipt; and improved parsing of one coding-agent backend's daily usage-cap reset time.
- **User-facing documentation of where the recall increase comes from.** The architecture guide's "Mechanical Recall Gates" section now carries a generic, protocol-free worked-example table — one row per recall-miss class (co-referencer, boundary, symmetric-operation, duplicate-element, unbounded-input, stranded-asset, un-asserted-invariant, un-examined-axis, dropped-orphan) showing the kind of miss each mechanism recovers as a candidate — and the internals guide gains an exhaustive per-function inventory (~50 derivers: name, file:line, consumes/produces, purpose) of the deterministic recall-generator / gate / bake / promotion / dedup-recovery layer.

### Fixed
- **M2 hot-function-set selection no longer dominated by generic utility calls.** Calls to built-in/standard-library helper methods (arithmetic wrappers, checked/saturating/wrapping variants, option/result unwrapping, casts, common collection/iterator methods) were being miscounted as contract-state writes, inflating math/utility helpers' rank above real state-changing logic. Fix is isolated to the hot-set scoring function: a builtin-method denylist strips the false "write" signal, and the ranking formula log-dampens raw call-count popularity (which does not equal risk) while keeping security-relevant terms (writes, privilege-elevation, value-movement) and a mild flat bonus for low-fan-in entry points, plus a header-driven fix for the caller-count column that had been misread on non-EVM graph schemas.
- **Long-standing test-suite hang root-caused and fixed.** An interactive artifact-purge confirmation prompt blocked on a keypress-polling loop with no non-interactive escape hatch, so under any non-TTY execution context (agent shell, CI) it hung indefinitely — previously misattributed to resource exhaustion. The same cross-platform environment-variable override and non-interactive-terminal guard already used by two sibling confirmation prompts was added to this one, defaulting safely to "keep artifacts, do not auto-purge" when running non-interactively.
- **Two cross-OS seam bugs found by the new hygiene gate.** A shared function-summary parser now recognizes a caller-count column header variant that had previously been misread as the callee column on several non-EVM ecosystems, corrupting fan-in-based candidate derivation. A delegated/managed-for-another-party trigger pattern used to recognize sensitive multi-step operations was generalized from brittle hardcoded literals to a per-ecosystem naming-family match, mirroring a fix already applied to one ecosystem.
- **Cross-language candidate-collection bug in two derived-candidate checks.** Both indexed language-table fields directly rather than defensively, so adding any language missing certain optional fields (as the new partial DAML entry does) silently discarded already-collected candidates for every other language processed earlier in the same run. Fixed with a defensive lookup.
- **Latent PoC-registry lookup bug that never matched for any non-EVM ecosystem.** A nested lookup shape in the mechanical PoC registry silently missed on every non-EVM PoC dispatch; fixed alongside the cargo-workspace PoC discovery work above.
- **De-overfit: fork-ancestry known-hazard floor tables re-keyed from brand to dependency-type.** Several ecosystems' fork-ancestry methodology files (and one recon-prompt duplicate) had a "known hazard" reference table keyed on specific named protocols/brands — exactly the benchmark-contamination the no-overfit policy prohibits for anything other than genuine detection-trigger recognition. Every such row is re-keyed to a generic dependency-type / vulnerability-class label (e.g. a lending-style receipt-token pattern, a concentrated-liquidity AMM tick model, a liquid-staking pool pattern) while preserving the same underlying hazard knowledge and research keywords. Rows that legitimately need a named primitive to recognize a fork lineage in the first place, and a dependency-CVE-tracking row, were left unchanged as those are detection triggers, not overfit answer keys.
- **report_index false-positive HALT abolished (structured + haltless).** The report-coverage semantic contract hard-halted an already-complete Thorough audit: a negation-blind substring regex matched the `mode-limited` token inside an honest "Not `mode-limited`" disposition and conflated a genuinely-unverifiable `UNRESOLVED_EVIDENCE` deferral (a candidate backfilled after the verify snapshot, carried for human review) with a real skipped-lane mode-limit. The gate now keys on the structured disposition token position (fires only when `mode-limited` is the status compound or the leading reason token), so reason wording can no longer flip it — no negation-lookahead, no false-negative; and even a genuine mode-limit now degrades to a flagged Appendix-B human-review row instead of hard-halting (the contract returns an always-empty blocking set, fully haltless per the repair-then-degrade contract). The advisory failure-diagnosis subprocess timeout was also raised and made env-overridable so failure diagnoses stop falling back to the deterministic local summary.
- **Resume no longer rewinds a completed audit over a stale, already-healed overflow.** The startup overflow-rewind reran a completed phase plus every downstream completed phase whenever an `_overflow/<phase>/` directory merely existed — so a benign, already-reconciled phase-containment quarantine from an earlier attempt could rewind an entire completed pipeline back to inventory on resume. It is now heal-aware by default: a stale overflow is archived and the checkpoint is left intact (the per-phase artifact-gate reconcile remains the precise safety net), with the prior always-rerun behavior preserved as an opt-in for the narrow "I landed a containment fix, rerun the affected phases" case.
- **Phase-containment quarantine move-failure can no longer silently persist a rogue artifact.** When quarantining a foreign later-phase artifact out of a phase's scope, a failed move previously logged a warning and continued, leaving the live rogue file at the scratchpad root with an empty overflow dir that neither the resume rewind nor the reconcile catches. The move is now hardened (rename with a copy+delete fallback) and returns the set that could not be moved; the phase gate fails (and re-runs) rather than completing with a live foreign file in place, riding the same retry-then-degrade cap as any containment failure.

### Docs
- Canonical legend for the mechanical shorthand (the gates/mechanisms/axes and the Source-ID/evidence tags) added to the glossary + internals guides so every mnemonic has one definition site; and a generic, protocol-free worked-example table in the architecture guide showing where the recall increase comes from.

### Testing
- New/extended tests across the M2 identity axis, hot-set denoise/reweight, the three mechanical recall gates, the force-by-default PoC gate's closed blocker taxonomy, L1 Wave 1/Wave 2 wiring, the cross-OS hygiene gate (including its own AST-based checks), the suite-hang fix, the DAML partial language-table entry and its cross-language defensive-lookup fix, and the cargo-workspace PoC discovery path. Suite now splits into a fast parallel lane (pytest-xdist, marker-excluded) and a serial integration lane, both run across the full OS matrix in CI. Full suite green: 4727 passed, 7 skipped, 1 xfailed.

## [2.2.3] - 2026-07-10

### Fixed
- **Report-body inflation from same-location duplicate splitting eliminated (anti-absorption on location, not prose).** The chain-phase anti-absorption gate previously split a hypothesis group whenever it bundled two or more `(file, function)` pairs, and a follow-on repair keyed sub-clusters on severity tier — so a single root-cause bug written up as paraphrase duplicates (or the same bug labelled at adjacent severities across mirror contracts) fragmented into many findings and several spurious Criticals. The gate now splits a group **only** when it bundles constituents at genuinely different locations that are also different bugs; same-location paraphrase duplicates and the same bug at two tiers collapse into one finding (severity inherited as the highest). This removes the prose-similarity trigger that shattered single root-cause findings without merging any genuinely distinct ones — every constituent source id is retained.
- **Report body labels can no longer disagree with the report index.** The assembler now stamps each `### [X-NN] Title [STATUS]` body header from the driver-computed canonical verification-status column (`VERIFIED` = proof-grade evidence / `CONFIRMED` = analytical / `CONTESTED` / `UNVERIFIED`), overriding the tier-writer's own tag. This ends the failure mode where the index recorded a finding as CONFIRMED while the body header rendered it as UNVERIFIED.
- **Cold, dependency-heavy `--via-ir` builds no longer degrade evidence to `[CODE-TRACE]`.** The file-count-scaled recon build timeout had a 30-minute hard ceiling that clamped ~5x below the real cold-build time of a large dependency-heavy Solidity repo (a measured cold `forge build` of a via-ir codebase runs ~48 min). The recon whole-project probe was killed at 30 min, degrading `build_status` to TIMEOUT — which starved Slither to the approximate source-parse graph and, because the verify phase's own build budget was never scaled, capped every PoC at `[CODE-TRACE]` instead of executing to `[POC-PASS]`. The ceiling is raised and made ops-overridable (`PLAMEN_BUILD_TIMEOUT_CEILING_S`, applied to every ecosystem's recon build via the shared `_scale_build_timeout`), and the mechanical-verify phase now warms the build cache once before the per-finding loop (`PLAMEN_MECH_BUILD_TIMEOUT`, wiring the previously-dead build budget) so each subsequent PoC `forge test` is an incremental (seconds) compile that reaches `[POC-PASS]`. Best-effort and non-fatal — a failed/timed-out warm-up leaves the loop exactly as before. Additionally, a one-time console heads-up now fires when a `via-ir` project is detected, warning that a cold whole-project compile can run for tens of minutes with no output (not a hang) — so operators don't kill a healthy run.

### Testing
- New/extended tests: the fresh-generation dedup/label failure modes (same-location paraphrase → no split; mirror contracts → no split; cross-tier same-location → merged; genuinely distinct bugs → still split; body header overwritten from index) and the build-timeout fix (ceiling clamp + env override read per-call; verify pre-warm success/timeout/skip/non-fatal; pre-warm wired into the phase; via-ir "not a hang" heads-up detection + one-time fire). Full test suite green: 4282 passed, 7 skipped, 1 xfailed. Build fix validated end-to-end on a real dependency-heavy via-ir repo: the cold whole-project build completes within the raised ceiling, and the mechanical-verify phase runs its PoCs through to `[POC-PASS]` instead of `[CODE-TRACE]`.

## [2.2.2] - 2026-07-07

### Added
- **M1 — assumption-commitment falsifier (recall generator).** Depth/verify SAFE and REFUTE verdicts now commit the tacit local guard they relied on as a falsifiable `[CI-n]` invariant (six generic shapes), fed through a new `compute_invariant_assertion_candidates` deriver (own budget pool) into the existing invariant-fuzz / PoC / chain paths. A candidate GENERATOR only — the unchanged verify/skeptic/PoC discriminator preserves precision. No new phase, strictly-additive and trivially removable.
- **M2 — multi-axis coverage meta-pass (recall generator).** A driver-owned deterministic hot-function set (capped) is checked across five orthogonal analysis axes, with axis-EXAMINED detected only from the closed depth-evidence-tag vocabulary and ambiguity resolved to GAP (recall-safe). Runs as a soft Thorough-only `axis_coverage` phase (skips when clean).

### Fixed
- **M1/M2 candidate ingestion no longer silently dropped by narrow ID-format regexes** (third recurrence of the ID-format catalog class). The axis-heading and committed-invariant parsers missed multi-segment / namespaced ids (`AXIS-A-1`, `CI-A1`, `CI-ES6-1`), so well-formed candidates parsed as zero and never reached inventory — including High-severity ones. Both regexes are widened to multi-segment ids, a shared receipt-id pattern keeps resume/retry de-dup in sync, and mechanical harvest-vs-emit reconciliation gates make any future ID drift a loud sentinel rather than a silent zero.
- **Attribution provenance + dedup clustering + M1 emission + M2 parity.** Clean `AXISGAP:` / `INVARIANT:` source tokens with a provenance-preserving dedup merge (the survivor keeps an absorbed generator's tag); transitive-closure clustering of co-referent survivors as a report-index consolidation hint (clique requirement + size cap + same-function guard + antonym veto against over-merge); M1 emission moved from the rare skeptic no-gap disposition to the abundant depth/verify verdicts; and non-EVM depth-evidence-tag emission raised to parity to stop false coverage-gap inflation.

### Testing
- New `test_invariant_assertion_deriver.py`, `test_axis_coverage_gate.py`, and extended recall/dedup suites. Full test suite green: 4164 passed, 7 skipped, 1 xfailed.

## [2.2.1] - 2026-07-04

### Fixed
- **Recon pre-pass whole-project build no longer times out on cold, dependency-heavy repos.** The `forge build` / `hardhat compile` timeout is now sized off the full compile-unit tree (including the `lib/` dependency sources the compiler actually builds), not the in-scope production-source count — which under-counted the real solc load ~10x and tree-killed cold-cache builds (e.g. a 652s budget for a 188-file compile), degrading `build_status` to TIMEOUT and starving Slither/Medusa. The scaled value is a ceiling, so healthy builds still return immediately.
- **Recon discovery inventory no longer ingests the project's own test/fuzz/mock harnesses.** `contract_inventory` / `function_list` / `state_variables` (and the derived `slither/*` flat files) now apply the production-source filter, excluding `test/` / `mock/` / `fuzz/` / `script/` (and `.medusa-tests/`) directories. A project's own harnesses — which can encode expected-failure assertions or bug reproductions — no longer leak into the discovery surface and prime analysis.

### Added
- **`--fresh` now archives prior-run answer-key artifacts out of the project root.** Before phase 1, a `--fresh` restart MOVES prior `AUDIT_REPORT*.md`, `*_RCA.md`, hardening notes, and generated fuzz-harness dirs (`.medusa-tests/`) into a dot-prefixed sibling archive (`.plamen_archive_<ts>/`) — moved, never deleted (recall-safe), and dot-prefixed so no build/Slither/recon walk can re-ingest them. Previously `--fresh` wiped only the scratchpad, leaving prior reports and harnesses in the tree where recon could ingest them and prime a supposedly-fresh discovery run.
- **Live heartbeat for long silent mechanical phases.** Long synchronous inter-phase steps (verify recovery/backfill, mechanical PoC verify, cross-tier report dedup) now emit the existing phase heartbeat, so a multi-minute silent window is no longer indistinguishable from a hang. Interval-gated (no pulse for sub-interval steps) and never overlaps a worker-phase heartbeat.

### Testing
- New `test_fresh_archive.py` and `test_mechanical_heartbeat.py`; extended recon build-env tests. Full test suite green: 4117 passed, 7 skipped, 1 xfailed.

## [2.2.0] - 2026-07-03

### Fixed
- **PoC integrity gate no longer spuriously demotes passing revert/error PoCs.** The mechanical harm-assertion integrity check now recognizes revert- and error-expectation assertions as valid harm proofs — `try_*().is_err()` / `is_err()` result checks, `#[should_panic]`, and `expect_err(...)` — so a finding whose harm IS "the call reverts / panics / errors" is scored on its executed assertion instead of being read as a mechanism-only test. Separately, a harness-side failure (`NO_TEST_FILE`, a PoC file that could not be relocated into a build root) no longer severity-caps an otherwise-passing PoC. Net effect: genuine `[POC-PASS]` findings stop being demoted to `[CODE-TRACE]` (and losing severity) because of an assertion shape or a harness-placement artifact rather than a real evidence gap.
- **Executive-Summary counts reconcile with the mechanical summary table.** The assembled report's narrative Executive Summary is derived from the same mechanical severity counts as the summary table, so the prose no longer disagrees with the tabulated Critical/High/Medium/Low/Informational totals.

### Changed
- **R10 anti-burden-inversion enforced at inventory, with a load-bearing `[EXTERNAL-ASSUMPTION]` tag.** A finding whose harm mechanism is CONFIRMED in-scope and whose only path to "safe" runs through an unresearched / out-of-scope / not-inspectable EXTERNAL factor is now held at its worst-realistic-condition severity and tagged `[EXTERNAL-ASSUMPTION: <assumed condition>]`, routing it to verification as an obligation rather than demoting it. This stops the "valid-but-unresearched" fallacy from burying such a finding in the appendix as a quality note; demotion now requires POSITIVE in-scope evidence of the safe condition, not merely its possibility.
- **Body-vs-appendix routing cleaned up.** Findings with a real security consequence stay in the report body at any severity; pure quality/hardening/observability observations route to the appendix. Reduces unverified-severity clutter in the body without dropping any candidate (every finding remains accounted for in the coverage ledger).

### Added
- **Depth recall recovery: table-row and self-exclusion harvesting.** Findings a depth worker buried inside a summary table, or self-dropped on an unverified premise, are now recovered and flow into inventory instead of vanishing before synthesis.
- **Sibling-propagation originate-side authorization check.** Sibling propagation now performs a nested-pull authorization check on the originate side, extending symmetric-pair coverage to the paired originating path.
- **Recon Required=YES niche agents actually spawn.** Fixed the wiring so niche agents recon marks `Required=YES` are instantiated in the depth phase rather than being silently skipped.

### Hardening
- **Internal bug-bounty lane confirmed excluded from the public tree.** Verified the internal-only bug-bounty lane is not present in the published repository.
- **Full test suite green** on this release.

### Measured effect (conservative)
- On a held-out benchmark, **precision held with no recall/precision tradeoff**, and the number of unverified-severity findings surfaced in the report body was reduced.
- The recall recoveries above were measured on the diagnosis benchmark; **further end-to-end recall validation is in progress**.

### Coverage caveat
- This release is **end-to-end verified on Windows across the Soroban and EVM lanes**. macOS/Linux and the remaining ecosystems are **static-verified only**; a **Solana-lane smoketest is in progress**.

## [2.1.4] - 2026-06-23

### Fixed
- **Haltless SC recon on large codebases.** The recon worker pool no longer stalls or halts when a single role worker cannot finish on a large repo. Three coordinated changes: (1) the `inventory_surface` (and light-mode `inventory_templates`) worker now BUILDS ON the mechanical pre-pass enumeration (`contract_inventory.md` / `function_list.md` / `state_variables.md`, added to its readable inputs) and produces only the narrative attack-surface/entry-point/trust layer plus a mandatory `## Enumeration Gaps` subsection (inline assembly, delegatecall/callcode targets, dynamic dispatch, fallback/receive, low-level calls) — instead of unboundedly re-enumerating the whole codebase from source; (2) on worker-pool retry-budget exhaustion the driver runs a PARTIAL merge over whatever shards completed (the merge preserves the mechanical enumeration byte-intact and tolerates empty shards) and continues haltless when the canonical gate passes, instead of falling through to the even-larger monolithic recon; (3) each recon worker now receives the full scaled phase budget (`max(900, timeout)`) rather than a 2400s cap that starved workers below `scale_timeout` on large repos. The mechanical full enumeration stays authoritative throughout — recall-positive (a halted recon yields zero findings).
- **Recon narrative gate softened only when the mechanical inventory is complete.** `_validate_recon_content_structure` routes the three narrative-only checks (design_context Operational Implications, Key Invariants; recon_summary minimum size) to soft/degrade-continue ONLY when all three mechanical inventory files exist, carry no surviving pre-pass marker, and contain a real enumeration body; otherwise they stay hard. All pre-pass-marker-survival checks remain hard unconditionally, so a genuinely-empty recon still halts. Recall-neutral.
- **Rescan plan/execute split (no more monolithic first-pass coordinator).** A new mechanical `rescan_prepare` phase (Thorough only) deterministically writes `rescan_manifest.md` from the contract inventory — mirroring `inventory_prepare` — so the existing rescan worker pool executes the declared rows on the FIRST pass instead of a single coordinator having to plan and execute and dying on large repos. The per-worker rescan methodology and exclusion-list semantics are unchanged.

## [2.1.3] - 2026-06-21

### Fixed
- **Headless PTY workers no longer freeze on `claude`'s first-run interactive gates.** A freshly-installed or never-configured Claude CLI puts up to three first-run **interactive** gates in front of a PTY worker — the onboarding/theme wizard, the per-folder trust dialog, and the one-time `--dangerously-skip-permissions` risk-acceptance prompt. All three are **invisible to `-p`/print-mode probes** but fatal to a headless worker: with no stdin to answer them, the worker produces zero bytes and dies on the phase budget (one observed episode burned ~90 minutes retrying). v2.1.2 pre-cleared the per-folder trust gate; this release pre-clears the two remaining **global** gates at startup in `_ensure_claude_folder_trusted` — it sets `hasCompletedOnboarding` (and a `theme` default **only** when the user has none; an existing choice is never overridden) and best-effort `bypassPermissionsModeAccepted` (the driver already passes `--dangerously-skip-permissions`, so pre-accepting its prompt is consistent; an unknown key is harmless). Idempotent, preserves all other config, never raises; Claude-backend only (Codex has its own sandbox model).

## [2.1.2] - 2026-06-20

### Added
- **EVM build-environment bootstrap in the recon pre-pass.** When a Solidity codebase is analyzed without a Foundry project (no `foundry.toml`), the recon pre-pass now best-effort scaffolds one (`foundry.toml` + `forge-std` + common libraries + `forge build`) so depth/verification have a compilable target. Best-effort and non-fatal — a failed bootstrap degrades cleanly to source-only analysis.

### Changed
- **`sc_semantic_dedup` redesigned cluster-first.** Replaced the O(n²) all-pairs comparison with multi-signal blocking → bounded per-block LLM `MERGE:`/`KEEP:` decisions → union-find transitive closure with a survivor-superset gate. Scales to large inventories without the pair-count explosion, and is zero-loss (every absorbed finding is embedded in its survivor).
- **Proven-only mode preserves structurally-untestable findings.** When `proven_only` is on, a `[CODE-TRACE]` finding whose verifier declined to write a PoC for a genuine structural reason (`STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`, deployment-only, unmockable external) now keeps its verifier-stated severity instead of a blanket Low cap; weak/lazy traces (a harness exists but no PoC was written; spec/docs-only; `NO_BUILD_ENVIRONMENT` contradicted by a SUCCESS build) are still capped. Conservative + additive — relative to the blanket cap this can only RAISE severity — and recorded as `STRUCTURAL-UNTESTABLE(orig_sev)` in the report-index trust-adjustment trail.

### Fixed
- **Proven-only severity no longer caps production-verified findings.** The `proven_only` "cap `[CODE-TRACE]` at Low" rule gated on `has_mechanical_proof`, which recognizes only mechanical-test-pass tags (`[POC-PASS]`/`[MEDUSA-PASS]`/`[FUZZ-PASS]`/…) — not production/on-chain tags. A finding confirmed against forked or live on-chain state (`[PROD-ONCHAIN]`/`[PROD-SOURCE]`/`[PROD-FORK]`, rated 0.9–1.0 by the confidence model) was therefore wrongly capped at Low. Added `EVIDENCE_TAGS_PROD` + `has_proof_grade_evidence()` (mechanical-pass **or** production tag) in `plamen_types.py`; proven-only gating now uses proof-GRADE evidence. `has_mechanical_proof` stays narrow ("a test executed and passed") for its other callers.
- **Chain-derived High/Critical findings are first-class, not obligation telemetry.** A chain hypothesis upgraded to High/Critical with a justified Combined-Impact (`Severity-Upgrade-Justified: YES`) is now force-included into the report coverage seed (mode-agnostic), and per-chain obligation rows are de-duplicated to one row per chain id — previously a justified High could surface only as a multi-row `UNACCOUNTED-OBLIGATION` dump in Appendix B. Chain-severity extraction is format-tolerant: a bare `Chain Severity:` line, a `Chain Severity Matrix: … → HIGH` conclusion line, **or** the summary-table column.
- **Recon degrades instead of looping on a surviving pre-pass marker.** After the worker pool and fallback are exhausted and the only remaining failure is the pre-pass status marker, recon now degrades to the pre-pass content (all backends) rather than re-spawning indefinitely; resume paths strip the stale marker.
- **Driver path resolution: absolute project/scratchpad/scope paths + worker settings.** `project_root`, `scratchpad`, and `scope_file` are normalized to absolute paths (anchored to the config directory) and the subprocess-isolation `--settings` path is absolutized at both construction sites, fixing workers that died at launch when invoked from a different working directory.
- **Driver pre-accepts folder-trust for the worker working directory.** Headless workers spawned in a never-opened directory hung on Claude Code's folder-trust dialog; the driver now writes `hasTrustDialogAccepted` for the project root and home into `~/.claude.json` before spawning (Claude backend only; never clobbers an unreadable or existing config).

## [2.1.1] - 2026-06-17

### Added
- **DAML / Canton as a first-class smart-contract ecosystem (bug-hunting scope).** Plamen now audits DAML codebases end-to-end: ecosystem auto-detection on `.daml` sources; DAML-specific recon, inventory, depth (templates + driver + scanner templates), and verification prompts (`prompts/daml/...`); 12 DAML skills under `agents/skills/daml/` (authorization-model, choice-semantics, contract-key-safety, cid-capability-safety, locking-semantics, privacy-disclosure, ensure-invariants, temporal-parameter-staleness, semi-trusted-roles, share-allocation-fairness, economic-design-audit, verification-protocol); registry entries in `rules/skill-registry.json` and a `daml` toolchain block in `rules/language-toolchain-registry.json` (`daml build` / `daml test`, DAML Script boundary-value fallback, no security SAST); and `DML-` internal finding IDs recognized by the mechanical pipeline.
- **Report-dedup AGENT (Phase 6d, `report_dedup_agent`).** A new, non-halting LLM phase reads the fully assembled `AUDIT_REPORT.md` and PROPOSES consolidations the mechanical signals miss: cross-tier and no-/mismatched-location duplicate MERGES, plus Quality-Observation reclassifications of unambiguously cosmetic Low/Info findings. The agent proposes only — it never edits, renumbers, or deletes; the existing deterministic Python `report_dedup` executes the proposals through the unchanged zero-loss embed + data-loss gate (agent proposes, Python disposes). The phase is `critical=False` (never halts the run), and both `AUDIT_REPORT.pre-dedup.md` and the deduped `AUDIT_REPORT.md` are retained.

### Changed
- **Opus promotion for SC Thorough semantic dedup.** The smart-contract semantic-dedup phase (`sc_semantic_dedup`) now runs on Opus in Thorough mode, where precision-critical per-pair adjudication benefits most from the stronger model.

### Fixed
- **Report-dedup agent decisions were silently dropped (column-mismatch) and one lossy QO retab vetoed every merge.** The `report_dedup_agent` decision parser is now column-agnostic: it reads report IDs by position-in-row (first = survivor, the rest = absorbed) instead of assuming a fixed `Survivor | Absorbed` two-column layout, so it correctly ingests the agent's richer table (`Survivor ID | Title | Absorbed IDs | …`), supports multi-absorb, and loose-matches the QO header. Separately, the Quality-Observation retabulation is now gated **independently** from the merges: previously the single end-of-pass all-or-nothing data-loss gate would revert *every* good consolidation when the QO retab happened to be lossy (e.g. a fee-rounding finding whose impact sub-bullets don't fit the compact QO row). A lossy QO retab is now dropped on its own while the merges still apply. Net effect on a representative report: dedup that had been a silent no-op (proposed merges parsed as zero) now consolidates correctly (81 → 70).
- **Semantic-dedup compaction no-op on large inventories.** The semantic-dedup phase now spends its in-session continuation budget to keep working when live candidate pairs remain, instead of accepting a pre-written `PASSTHROUGH` result unchanged after a context compaction. This closes the large-inventory case where dedup silently did nothing.
- **De-overfit: removed protocol-specific answer-priming from the methodology.** A protocol-specific binding-template primer (and any other protocol-specific answer-priming found in the same sweep) was removed, restoring the HARD no-overfit invariant: the methodology encodes HOW to analyze, never WHAT to find in a specific protocol. (Generic, illustrative-only mentions of cross-chain standards — e.g. LayerZero/Wormhole/Axelar as one example among several, or the documented "never again" case study in the post-audit-improvement protocol — are retained, as permitted by the rule.)

## [2.1.0] - 2026-06-15

### Added
- **PTY-supervised execution + disk-derived completion**: the driver drives each worker through a pseudo-terminal and infers turn completion from on-disk artifact markers (`<!-- PLAMEN_STATUS: COMPLETE -->`) instead of a stdout/JSON envelope, eliminating the 0-byte-stdio silent-hang class. Adds a PTY transport preflight (`preflight_pty_transports.py`).
- **Codex backend (cost-saving BETA)**: OpenAI Codex CLI (`codex exec`) as an alternative worker backend — model/tier/compact configuration, per-job depth fan-out (one `codex exec` per depth job), and natural-language usage-cap detection that auto-waits instead of halting.
- **Deterministic Go SCIP bake** (`_bake_go_scip`) for L1 Go audits, alongside the existing Rust SCIP path.
- **Thorough-only Exploration-Completeness skeptic** (Phase 4b.6) — an independent, recall-positive pass.
- **New mechanical helper modules** (`plamen_contracts.py`, `plamen_markdown.py`) factoring the shared deterministic substrate; `pty_exec.py` + `preflight_pty_transports.py` back PTY execution.
- **Ecosystem auto-detection on the startup banner**: the audited language is detected, auto-corrected, and shown at startup (manifest-priority; suffix never clobbers config; Pinocchio / native-SDK Solana at high confidence).

### Changed
- **Opus tier defaults to `claude-opus-4-8`** across the entire pipeline and all modes; L1 Thorough reasoning roles and verify are pinned to Opus 4.8 (overridable via `PLAMEN_OPUS_MODEL` / `PLAMEN_THOROUGH_OPUS_MODEL`).
- **Haltless by design**: report_index, verify, inventory, and resume paths repair-then-degrade and surface unfinished obligations as flagged Appendix-B items in `AUDIT_REPORT.md` instead of stopping the run. Retry/recovery is unified across backend x mode x pipeline.
- **More deterministic, fewer LLM-prose phases**: mechanical SC `report_index` recovery, mechanical verify backfill / queue manifests, the data-loss-free `report_dedup` builder, and the recon prepass.
- **Zero-data-loss dedup**: dedup runs over the full candidate set rather than a pruned subset.
- **Cross-platform / POSIX execution**: POSIX PTY via `Popen` ownership + SIGCHLD reset on macOS/Linux, nested-session env isolation (strips `CLAUDE_CODE_*` from child workers), and shell-rc PATH persistence.
- **HARD de-overfit rule enforced**: protocol-specific knowledge purged from methodology — the pipeline encodes HOW to analyze, never WHAT to find.

### Fixed
- **Silent-hang / 0-byte-stdio class**: disk-derived completion replaces the stdout/JSON envelope; the context-thrash fast-fail that killed slow-but-completing workers was removed.
- **Audits halting at the finish line**: report_index / verify / inventory obligations degrade-with-flag instead of halting.
- **report_index inflation + coverage-parser bug**: the SC report_index keeps the LLM's consolidated index, accounts coverage-seed-only residuals without halting, and parses the coverage ledger correctly (a "candidate" in reason prose no longer corrupts ID parsing).
- **Resume-rewind loop**: verify queue-completeness backfill stops resume from rewinding a near-complete run; stale/corrupt checkpoints recover instead of stranding the audit.
- **Codex never-cut-stub halt**: per-job depth fan-out; usage-cap exhaustion auto-waits; context-exceeded no longer perma-fails.
- **Ecosystem mis-detection requiring a rerun**: startup auto-correction replaces halt-to-rerun.
- **Regex-fragility silent-drop class**: a tolerant-extraction substrate closes over-strict ID/field parsing drops.
- **Transient API errors**: 5xx server errors (500/502/503/504) now get 529-style backoff-retry instead of stalling a worker.
- **529/overloaded misclassified as a 429 usage cap on worker-pool phases**: the 5xx/529 backoff fix above covered single-subprocess phases but NOT the recon/breadth/rescan/depth worker pools, where a transient 529 set `state.rate_limited` (which matches the overload class) and escalated to the phase-level usage-cap pause — killing the still-internally-retrying worker. The PTY `TurnCompleteState` now tracks `overloaded` separately (the 529-only subset), and the pool runners route a pure 529 to a retriable status so the gate re-spawns just that one worker instead of pausing the whole phase. True 429 account/usage caps still trigger the pause (unchanged).
- **report_dedup over-fragmentation (recall-safe consolidation)**: the final non-halting `report_dedup` phase now (a) retabulates unambiguously-cosmetic Low/Info findings into the Quality Observations table (reusing the existing `classify_quality_observation` classifier; security-relevant findings are never moved), and (b) merges same-root-cause findings within AND across severity tiers into the higher-severity survivor. Candidate generation was widened (including a same-source-file signal) while the strict `_dedup_same_fix_ok` + superset + `_dedup_data_loss_gate` guards are UNCHANGED, so every merge is lossless. Validated on a real audit report: recall held (16/17 ground-truth matches preserved, 0 findings dropped, data-loss gate PASS). Also fixed a latent bug where `_dedup_report_sections` extended the last finding's section to EOF and could swallow a trailing Quality-Observations/appendix block (bounded by the new `_finding_own_block`).
- **Undeclared runtime dependencies**: `pydantic` and `markdown-it-py` (imported by the mechanical substrate `plamen_contracts.py` / `plamen_markdown.py`) are now declared in `requirements.txt`, so a fresh `pip install` no longer leaves the substrate unimportable.
- **Spurious version-mismatch warning on a clean install**: the in-session command prompts hardcoded the prior version, so the mandatory version check fired a false "run git pull && plamen install" warning on a correctly-installed release.
- **Non-existent `--dry-run`**: removed from the wizard's resume guidance (the driver has no such flag and treated it as a missing config path). `resume` and `--fresh` are retained.
- **`cargo install` on stable rustc**: scout / cargo-fuzz / trident / rust-analyzer now install with `--locked`, so a toolchain whose stable rustc predates a dependency's latest MSRV (e.g. rustc 1.92 vs deps requiring 1.94) builds against the tool's tested lockfile instead of failing.
- **`plamen uninstall` on codex-only installs**: read the manifest from every backend (`~/.claude`, `~/.codex`, `PLAMEN_HOME`) instead of only `~/.claude`, so a Codex-only install is no longer a silent no-op. Removes the adapter-owned trees (`~/.codex/{plamen,agents,skills,commands}`) and any plamen-created `python3` shim (now tracked in the manifest), while LEAVING shared `config.toml` / `AGENTS.md` (which may hold user API keys) and noting them for manual review.
- **PATH-persistence hardening**: shell-rc persistence no longer swallows failures silently (warns with the manual command); writes BOTH `~/.zshrc` and `~/.bashrc` for cross-shell coverage (install from one, audit from the other); adds fish support (`config.fish`, only when fish is present); and persists standard toolchain dirs even before they exist so out-of-band tool installs are already on PATH.
- **`plamen compare` clarity**: when the Claude CLI is absent, the error now states compare requires the Claude backend (it is not available on Codex) and points to `plamen core` / `plamen thorough`, which both backends support.
## [2.0.2] - 2026-05-20

Follow-up to v2.0.1 — same surface, error-message copy edit only.

### Fixed
- **Auth error messages** in both `plamen doctor` and the V2 driver's
  `detect_not_logged_in` exit now point at BOTH supported auth paths
  (OAuth `/login` AND `ANTHROPIC_API_KEY` env var) and explicitly state
  that `~/.claude/settings.json` is NOT read as credentials. Previously
  the messages mentioned only OAuth, which misled users who had dropped
  an API key into settings.json expecting it to be picked up.
  (`plamen.py` `run_doctor`, `scripts/plamen_driver.py` `run_phase`)

## [2.0.1] - 2026-05-20

Isolated post-install gap fixes from a live-version user halt diagnosis. No
methodology, agent set, or scratchpad-schema changes — only the install /
doctor / driver edges that produced the failure.

### Fixed
- **`plamen doctor`** now probes `claude` authentication state. An
  unauthenticated `claude -p` returns rc=0 with a "Not logged in" /
  `/login` message that the V2 driver cannot distinguish from a real
  empty response; previously `doctor` only checked that `claude` was on
  PATH. (`plamen.py` `run_doctor`)
- **V2 driver** detects "Not logged in" / `/login` in subprocess stdio
  via the new `detect_not_logged_in` helper (sibling of
  `detect_rate_limit`) and exits `EXIT_DEGRADED` with an actionable
  error message instead of silently re-spawning the same
  unauthenticated CLI until the attempt budget is exhausted.
  (`scripts/plamen_driver.py`)
- **`plamen install`** now emits a loud red `!` and an explicit
  `INSTALL INCOMPLETE` banner when `claude` is not on PATH at install
  time. Previously the install silently skipped both the `~/.claude/`
  symlink and config-merge steps with a gray "skipping" line that was
  easy to miss, leaving the user with an unrunnable setup.
  (`plamen.py` `run_install`)
- **Resume command** in `plamen_display` now quotes `{config_path}`
  in all three emission sites so paths with spaces survive copy/paste.
  (`scripts/plamen_display.py`)

## [2.0.0] - 2026-05-13

### Impact vs v1.1.8 — quality, cost, time

These deltas describe the **structural** changes between v1.1.8 and
v2.0.0. v2.0.0 ships **the same methodology and the same agent set** as
v1.1.8 — no new analytical techniques, no new agent classes. The
practical impact comes from the new driver enforcing what v1 only
described in prose. Numbers below are not from a measured benchmark
comparison; they are the directional expectation. Treat as a
qualitative read, not a contract.

- **Findings**: a slight potential increase over v1.1.8, not from new
  methodology but from gates that stop the pipeline from silently
  skipping mandatory steps under context pressure. In v1, late-Thorough
  context saturation could cause the orchestrator to skip
  Skeptic-Judge, validation sweeps, or niche-agent fan-out without
  reporting it. v2's deterministic driver runs each of those as its
  own subprocess and gates its output. The dynamic-retry gate also
  re-surfaces files that the first breadth pass didn't read.
- **False positives**: at most a slight decrease, again from
  enforcement rather than new logic. The Skeptic-Judge pass on
  HIGH/CRITICAL, the cross-batch consistency check, and the mandatory
  PoC-execution rule with harm-identity enforcement all existed as
  prose directives in v1; v2 turns them into per-phase gates that
  actually run. If you ran v1 Thorough end-to-end without any silent
  skip, you'd see roughly the same precision.
- **Cost**: roughly the same dollar envelope as v1.1.8 at equivalent
  modes. The pipeline spawns more agents than v1, but the model cap is
  **Sonnet for breadth + Opus 4.6 for depth** — Opus 4.7 was tested,
  showed diminishing returns on the audit corpus, and burned tokens
  faster than the recall gain justified. See the cost table in
  `README.md` and `docs/audit-modes.md` for per-mode ranges.
- **Wall-clock time**: slightly shorter than v1.1.8 at equivalent
  modes. Several phases that v1 ran through an LLM (report assembly,
  dedup, severity index) are now mechanical Python steps in v2 —
  milliseconds instead of minutes. The time budget those steps freed
  up was reinvested as longer per-agent timeouts (recon, breadth,
  depth, verify shards all 2× v1.1.8) so the analytical phases have
  more room on large codebases. Net effect is roughly flat to
  slightly faster, depending on codebase size.
- **Surface coverage**: 5 SC chains (added **Soroban/Stellar**) plus
  the new **L1 mode** for Go/Rust node clients — broader than v1.1.8.
- **Backend**: V2 driver runs against **either Claude Code or Codex
  CLI** with the same pipeline and gates.
- **Engineering ergonomics**: the new architecture is markedly easier
  to extend (add a phase = add a `Phase()` entry + a gate spec) and
  test (each phase is a unit-testable subprocess invocation rather
  than a hidden branch in a giant LLM prompt). CI smoke matrix on
  `ubuntu` / `macos` / `windows` × `py3.11` / `py3.12` runs the
  install + non-TTY path on every push.

### Added (release-candidate hardening)
- **ast-grep auto-install**: added to `_INSTALL_RECIPES` under a new `L1 (ast-grep)` group and surfaced in the `check_dependencies` toolchain box. `plamen setup` now installs ast-grep alongside rust-analyzer; previously it was used by the L1 pipeline but never offered to install.
- `plamen doctor` (aliases: `verify`, `check`) — fast install-verification subcommand. Checks Plamen home, PATH for `python`/`git`/`npx`/`claude`/`codex`, Python deps, `~/.claude` manifest items, `~/.codex/plamen` tree, submodule population, CLAUDE.md PLAMEN markers. Exits non-zero on hard failures; no audit run, no paid API calls. Suitable for CI smoke tests.
- `plamen migrate` — atomic v1.x (Plamen-in-`~/.claude`) → v2.x (Plamen-in-`~/.plamen`) migration. Detects v1 markers (broad OR-heuristic across six paths), strips dangling Plamen hook entries from `settings.json`, renames or backs up, runs the non-interactive install, verifies CLAUDE.md markers.
- `docs/glossary.md` — quick reference for pipeline / phase / breadth / depth / niche / skill / skeptic-judge / PoC / scratchpad / MCP / RAG vocabulary.
- `.gitattributes` — forces LF on `*.sh`/`*.py`/`*.toml`/`*.md`/`*.json`/`*.yml`, CRLF on `*.bat`/`*.cmd`/`*.ps1`. Prevents `^M` interpreter errors when cloning Windows-developed working trees on Linux/macOS.
- `.github/workflows/install-smoke.yml` — CI matrix (ubuntu / macos / windows × Python 3.11 / 3.12) running non-TTY `plamen install`, `plamen install --codex`, idempotent re-install, and `codex-adapter` rename verification on every push.

### Changed (release-candidate hardening)
- **`plamen install` split from `plamen setup`**: `install` is now pure and non-interactive (symlinks, settings merge, CLAUDE.md inject, submodules, Python deps). Safe in any context — Claude Code Bash, Codex shell, CI, headless. `setup` runs the install then the interactive toolchain wizard. In a non-TTY context, `setup` exits cleanly after the install instead of crashing on `inquirer.checkbox`.
- **`codex/` repo dir renamed to `codex-adapter/`**: stops shadowing the Codex CLI binary when `~/.plamen` is on PATH. All references updated in `plamen.py`, `scripts/codex_adapter.py`, `.gitignore`, README, SETUP, CONTRIBUTING, and `docs/`.
- **README**: Codex CLI prerequisite block with `~/.npm-global` user-local install snippet (avoids `sudo npm` EACCES on Homebrew). PEP 668 `--break-system-packages` callout with opt-out via `PIP_BREAK_SYSTEM_PACKAGES=0`. `--recurse-submodules` in every clone command. `install` vs `setup` vs `migrate` vs `doctor` distinction up front. Codex-vs-Claude-first guidance.
- **SETUP.md rewritten** as a real AI-assistant install script with Step 0–5 structure, error-handling cues, expected-output anchors, and explicit "do not run `plamen setup` or `plamen rag` from this session" guards.
- Vendored MCP servers (`custom-mcp/solana-fender/`, `custom-mcp/unified-vuln-db/`) ship MIT LICENSE files and original-authorship setup.py headers.

### Fixed (release-candidate hardening)
- `plamen` (no args), `plamen uninstall`, and the wizard path all crashed in non-TTY contexts with `OSError: [Errno 22]` from `prompt_toolkit`. All three now TTY-guard at the entry point and exit cleanly with an actionable message. `plamen uninstall` honors `PLAMEN_UNINSTALL_YES=1` for scripted environments.
- `scripts/codex_adapter.py` generated SKILL.md with a bare `{PROJECT_ROOT}` inside an f-string, causing `NameError` on every `plamen install --codex`. Now escaped as `{{PROJECT_ROOT}}`.
- `pip install -e custom-mcp/slither-mcp` failure on empty submodules was reported as `exit 0` ("non-critical (failed)"). Now detects empty submodules (no `setup.py` or `pyproject.toml`), emits a clear "run `git submodule update`" message, and surfaces critical failures at the end of the install loop.
- `plamen install --codex` succeeded with no `codex` binary on PATH. Now calls `_find_codex_bin()` and warns loud with the install snippet if missing.
- `--break-system-packages` was added silently. Now prints a one-time stderr notice; opt out with `PIP_BREAK_SYSTEM_PACKAGES=0`.
- Dangling Plamen-owned hook entries in `~/.claude/settings.json` (from a moved/removed previous install) blocked every PreToolUse Bash invocation. `_heal_dangling_hooks()` runs as a pre-flight in `run_install()` and `run_migrate()`, strips Plamen-owned entries whose targets don't resolve, and preserves all non-Plamen hooks.
- `docs/l1-mode/design.md` referenced a private staging branch in its header; `commands/plamen-l1.md` carried a stale "Do NOT run on production" disclaimer. Both rewritten with stable framing.
- UTF-8/CP-1252 mojibake (`â€"`, `â€™`, `â€œ`, `âœ"`, `â—‹`) cleaned across 20+ prompt/rule/command files.
- `scripts/write_helper.py` (0-byte stub) removed; `docs/repository-structure.md` updated to reflect the rename `codex/` → `codex-adapter/` and the removed stub.
- **rust-analyzer install on Homebrew Rust (macOS)**: previously `rustup component add rust-analyzer` ran unconditionally and failed when Rust came from `brew install rust` (no rustup multiplexer). `_rust_analyzer_cmds()` now detects rustup vs brew and routes to `brew install rust-analyzer` when rustup is absent. The recipe's prereq flag drops `rust` on macOS+brew so the prereq check doesn't force-reinstall rustup. `docs/dependencies.md` documents the brew-vs-rustup distinction.

### Added
- **V2 Resumable Pipeline**: Python driver (`plamen_driver.py`) runs one `claude -p` subprocess per phase with automatic checkpointing. Resumes from last successful phase on crash or usage exhaustion. Launched via `/plamen-wizard` or `plamen_driver.py`.
- **L1 Infrastructure Audit Mode**: `/plamen l1 [light|core|thorough]` for auditing blockchain node clients (consensus engines, p2p networking, mempool, RPC, validator lifecycle) in Go and Rust. 22+ injectable L1 skills, 2 new depth agents (`depth-consensus-invariant`, `depth-network-surface`), L1-specific severity matrix aligned with Immunefi v2.3, Phase 0.5 "Bake" (scip-go / rust-analyzer SCIP batch indexing), Opengrep cross-ecosystem static analysis.
- **Soroban/Stellar Chain Support**: 19 skills (13 cross-language + 6 Soroban-specific: auth_validation, storage_lifecycle, overflow_safety, contract_upgradeability, sep41_token_safety, custom_type_safety). Full pipeline coverage: recon, breadth, depth, verification, report.
- **OpenAI Codex CLI Backend**: V2 driver supports `codex exec` as alternative to `claude -p`. Tool translation, sandbox adaptation, path rewriting (`~/.claude/` → `~/.codex/plamen/`), model mapping. Codex config at `~/.codex/plamen/`.
- **Semantic Dedup Agent (Phase 4e)**: Pre-chain dedup pass with location-overlap, source-ID subset, PERT lineage, and same-fix-pattern merging signals.
- **PoC Execution Classifier**: Mechanical Python gates for coverage/integrity/demotion plus LLM Assertion Retry Protocol with harm-identity enforcement.
- **Report Assembly**: Deterministic Python-native report assembler replaces LLM-based concatenation (49ms vs 1+ hour on large reports).
- **Subprocess Isolation**: Plugin/hook/MCP isolation via `--settings` overlay prevents cold-start hangs from user plugins.
- **Phase Isolation**: Each V2 subprocess receives ONLY its own prompt section with forward-reference sanitization.
- **Pipeline Watchdog Hooks**: Claude Code Stop + PostToolUse hooks enforce artifact existence at phase transitions with two-strike stall model.
- **Confidence Scoring Model**: Scoring model upgraded haiku → sonnet for per-finding differentiation on large audits.
- **STABLESWAP_COMPLIANCE Niche Agent**: Curve/StableSwap fork compliance (Newton-Raphson convergence, A parameter encoding, reserve decimals).
- **Graph Artifact Pre-Computation**: Recon produces caller_map, callee_map, state_write_map, function_summary across all 5 SC languages.

### Changed
- **5 Smart Contract Chains**: EVM/Solidity, Solana/Anchor, Aptos Move, Sui Move, Soroban/Stellar (was 4)
- **Cross-platform path abstraction**: `plamen_home()` replaces all hardcoded `~/.claude` Python paths. Supports PLAMEN_HOME env, script-relative, and ~/.claude fallback.
- **Version normalized to v2.0.0**: All internal version references unified (was mixed v1.1.8 / v9.9.x / v2.2.0 A.x dev tags)
- **Light mode added**: 3 audit modes (Light/Core/Thorough) for Pro plan users (was 2: Core/Thorough)

### Fixed
- 200+ driver fixes across v2.0.0-v2.8.7 development cycle (see MEMORY.md pipeline entries for per-version details)
- Subprocess stdin pipe deadlock on all platforms
- MCP cold-start hang from plugin/hook interference
- Report assembly truncation on large reports (>25 findings)
- Gate-vs-gate collision between step-trace and coverage-fill agents
- False recon retry from determiner articles in placeholder detection

## [1.1.8] - 2026-04-08

### Added
- **Pipeline Watchdog Hooks**: Claude Code Stop + PostToolUse hooks (`phase_gate.py`) that mechanically enforce artifact existence at phase transitions. Prevents the orchestrator from skipping mandatory steps. Key features:
  - Two-strike stall model (warn then block)
  - Forward leak detection (blocks if later-phase artifacts appear before current phase completes)
  - Mode-aware conditional checking (perturbation/DST only in thorough, confidence scores only in core+thorough)
  - Niche agent enforcement (parses both bullet and table formats from template_recommendations.md)
  - Actionable recovery hints (block messages include specific agent types and template file references)
  - Anti-loop protection (block then free pass then fresh warn cycle)
  - Dormant for non-audit sessions (zero overhead)
  - Auto-installed via `plamen install` with platform-aware python resolution
- **hooks/ directory symlinked** by `plamen install` (auto-updates on `git pull`)
- **settings.json hooks merge** during `plamen install` (additive, platform-aware python command)
- **Step 0.9 watchdog init** in pipeline startup (activates enforcement before recon agents)

### Fixed
- **Perturbation and Skill Execution Checklist sections missing from 4 language trees**: EVM, Solana, Aptos, and Sui phase4b-loop.md files were missing the Finding Perturbation Agent and Depth Skill Execution Checklist sections that existed only in Soroban. The watchdog enforced these artifacts but the templates that agents follow to produce them were absent, breaking the completeness chain in Thorough mode. Now propagated to all 5 language trees with language-specific skill mappings.
- SETUP.md paste no longer triggers automatic RAG build (10GB RAM issue)
- RAG positioned as optional across all documentation with resource warnings
- Niche agent file naming aligned across SKILL.md, phase4b-required-artifacts.md, and watchdog
- Scanner artifact naming made flexible (accepts blind_spot_*, scanner_*, validation_sweep_*)
- Anti-loop stall state properly cleared after free pass
- settings.json.example hook nesting corrected (statusMessage/async inside hook entries)
- Python command resolution platform-agnostic (python3 on macOS/Linux, python on Windows)

## [1.1.6] - 2026-03-29

### Fixed
- **MCP path resolution**: All MCP server commands (`slither-mcp`, `npx`, `python`) now resolve to absolute platform-correct paths during install — not just `python`/`python3`. Searches pip script directories (`~/Library/Python/X.Y/bin/`, `~/.local/bin/`, `%APPDATA%/Python/Scripts/`) via `sysconfig` when `shutil.which` fails.
- **Cross-platform migration**: Installer detects wrong-OS paths in existing `mcp.json` (e.g., `C:/` paths on macOS) and auto-fixes them to resolved local paths while preserving user env vars and API keys.

## [1.1.7] - 2026-04-07

### Added
- **Pipeline Watchdog Hooks**: Stop + PostToolUse hooks (`phase_gate.py`) enforce artifact existence at phase transitions. Two-strike stall model, forward leak detection, mode-aware conditional checking. Dormant for non-audit sessions. Auto-installed via `plamen install`.
- **Perturbation Agent** (Thorough only): Post-depth agent that applies structured mutation operators (DIRECTION_FLIP, BOUNDARY_SHIFT, ACTOR_SWAP, ORDERING_REVERSE, AGGREGATION_SPLIT) to existing findings, testing adjacent vulnerability space. Targets single-hit satisfaction pattern where agents find one variant but miss symmetric counterparts.
- **Skill Execution Checklist** (Thorough only): Haiku agent that mechanically verifies depth agents executed all steps of their assigned skills. Execution gaps feed Devil's Advocate iteration 2 input.
- **Symmetric Operation Pairing** (Thorough only): Pre-computed pairs table (deposit/withdraw, borrow/repay, mint/burn, approve/revoke, pause/unpause) injected into depth prompts with mandatory both-sides coverage gate.
- **Static Artifact Manifest**: `phase4b-required-artifacts.md` per language tree — READ-ONLY manifest checked by orchestrator post-depth. Missing artifacts trigger agent spawns, not silent passes. Prevents orchestrator from skipping committed mechanisms.
- **Soroban Rule SB17**: Transaction resource budget exhaustion detection. Computes `max_reads = reserves_in_position × reads_per_reserve` and compares against Stellar's ~40 read ledger entry limit.
- **External data ordering check**: Sub-check added to `external-precondition-audit/SKILL.md` across all 5 language trees: "For each external data structure received: what ordering/uniqueness does the consuming code assume? Does the spec guarantee it?"

### Changed
- **Lending injectable sharpened**: Replaced 5 vague reasoning questions with mechanical grep-and-compare actions. Produces named output tags (NO_MINIMUM_POSITION, LIQUIDATION_RESOURCE_DOS, NO_UNPAUSE_GRACE, NO_FALLBACK_ORACLE). Net -4 lines.
- **MCP package management**: Pinned npm MCP server versions, added schema sanitizer proxy for unified-vuln-db, gated MCP install for legacy/existing configs only.

### Fixed
- 5 regressions in static artifact manifest (generic title, niche file names, EVM-specific fuzz artifacts, MODE gate, non-EVM fuzz requirement).
- MCP config now correctly targets `~/.claude/mcp.json` (not `~/.claude.json`).

## [1.1.5] - 2026-03-28

### Added
- **NEW injectable skill: INTEGRATION_HAZARD_RESEARCH** — researches known footguns of external protocols the audited code integrates with. Solodit + Tavily queries per target, hardcoded hazard floor (30 protocols across EVM/Solana/Sui/Aptos), third-party race conditions, integration state TOCTOU. Triggered by `NAMED_EXTERNAL_PROTOCOL` flag. All 4 chain recon prompts updated.
- **Oracle hardening (all chains)**: EVM oracle skill new Section 2d (pull-based checks — timestamp monotonicity, Pyth confidence intervals), Section 5c item 5 (chained feed deviation stacking), Section 1 (hardcoded stablecoin pricing). Sui/Aptos oracle skills: chained deviation + stablecoin check. Solana/EVM R16: new rows for timestamp monotonicity, confidence interval, chained feed deviation, hardcoded stablecoin price.
- **Calldata smuggling detection (EVM)**: storage-layout-safety new Step 4d — hardcoded offset into ABI-encoded data. 4 impact tiers (dual-read divergence, single-read assumption, revert injection, hash divergence). Covers calldataload, mload, byte-slicing, nested bytes. Memory vs calldata decoding asymmetry note.
- **Anchor IDL hidden instructions (Solana)**: account-validation skill IdlBuffer cosplay amplification note. Scanner C new CHECK 8b — 7 hidden IDL instructions, IDL authority claim, IdlCreateBuffer as cosplay primitive.
- **Silent misconfiguration (all chains)**: Scanner CHECK 2 extended with R14 bounds enforcement + silent misconfiguration sub-check (setter with no bounds that silently produces wrong math).
- **Immunefi Competitions RAG indexer**: new `immunefi_competitions.py` (984 lines) — 4th indexer alongside Solodit, DeFiHackLabs, Immunefi writeups. Indexes 879 competition-validated findings from 25 audit competitions. Windows-safe, 3 filename formats, 0.2s raw fetch delay. `plamen rag` now runs all 4 indexers. CLI: `--source immunefi-competitions`, `--competitions`, `--max-findings`, `--local-repo`.
- **Immunefi competition methodology analysis**: 14 agents analyzed 879 findings across 25 competitions — 0 methodology gaps found. Confirms pipeline coverage of all competition-validated vulnerability classes.

### Changed
- All new skills/checks follow v1.1.2 patterns (processing protocol, coverage assertions) where applicable.
- unified-vuln-db README rewritten — removed stale HuggingFace source, updated MCP tools table to 16 actual tools, corrected query examples and schema.
- Documentation updated across 13 files: 4k+ finding count, 8 injectable skills, 4 RAG sources.
- Raw content fetch delay reduced from 1.0s to 0.2s for raw.githubusercontent.com (no rate limit).

## [1.1.4] - 2026-03-27

### Fixed
- **EVM recon: STORAGE_LAYOUT flag detection** — added grep pattern for `proxy|upgradeable|delegatecall|sstore|sload|assembly` and BINDING MANIFEST entry. STORAGE_LAYOUT_SAFETY skill was previously unreachable.
- **EVM recon: CROSS_CHAIN_MSG flag detection** — added grep pattern for `lzReceive|ccipReceive|receiveWormholeMessages|setPeer|setTrustedRemote` and BINDING MANIFEST entry. CROSS_CHAIN_MESSAGE_INTEGRITY skill was previously unreachable.
- **EVM recon: SPEC_COMPLIANCE_AUDIT niche agent** — added to niche agent binding rules and table. Was present in Solana/Aptos/Sui but missing from EVM.
- **EVM recon: ZERO_STATE_RETURN binding rule** — added `ERC4626 flag → ZERO_STATE_RETURN REQUIRED`. Flag was grepped but no binding rule enforced skill loading.
- **EVM/Solana recon: Injectable Skills section** — added full Injectable Skills section listing all 7 (EVM) / 6 (Solana) protocol-type-specific injectables. Previously missing entirely.
- **Aptos/Sui recon: Injectable Skills section** — expanded from VAULT_ACCOUNTING-only to full injectable list (6 injectables per language) plus ZERO_STATE_RETURN binding for vault protocols.
- **Uninstall crash** — `plamen uninstall` no longer crashes with KeyError if `settings.json` lacks a `permissions` key.
- **Stale doc references** — removed deprecated `solodit-scraper` and `defihacklabs-rag` from README, mcp-servers.md, dependencies.md, and repository-structure.md.

### Changed
- **Skill counts** — Aptos and Sui skill counts updated from 21 to 22 (21 standard + 1 core directive) in skill-index.md, internals.md, and repository-structure.md. Added MOVE_SAFETY_CORE_DIRECTIVES to skill-index.md.
- **Solana prompt count** — repository-structure.md corrected from 9 to 10 files (includes phase4b-invariant-fuzz.md).
- **Python version** — docs/setup.md corrected from "3.11+" to "3.11-3.12" (3.13+ has known issues).
- **Rust scope** — docs/dependencies.md corrected from "Required (All Platforms)" to "Solana only".
- **Audit modes table** — docs/audit-modes.md added missing "Orchestrator model" row.

## [1.1.3] - 2026-03-27

### Added
- **EVM Compilation Weight Check (Step 3c)**: Recon TASK 1 now counts `.sol` files and checks `via-ir`/`auto_detect_solc` settings before `forge build`. Heavy projects (>500 files, via-ir + >200 files, or multi-version pragmas) get `threads = 2` in foundry.toml and solc version pinning. Prevents parallel solc instances from exhausting system RAM and crashing Claude Code.
- **Solana Compilation Weight Check (Step 1e)**: Recon TASK 1 now counts `.rs` files and workspace members before `anchor build`/`cargo build-sbf`. Heavy projects (>300 files, >3 workspace members) get `CARGO_BUILD_JOBS=2` prefix. Prevents parallel rustc instances from causing OOM.

### Why
Observed repeated crashes on large projects (e.g., a Solidity monorepo with 5,000+ .sol files with `via-ir = true`). Foundry spawns 5-6 solc instances at 4-8GB each, exhausting RAM. Cargo does the same with rustc. Aptos/Sui Move compilers are single-threaded and lightweight — no mitigation needed.

## [1.1.2] - 2026-03-27

### Added
- **Scanner CHECK 5 extension**: Untrusted call target validation — when code decodes an address from calldata and calls interface functions on it, the return values are untrusted unless the address is verified against a registry or factory. Fills a gap between "untrusted parameters in calls to known contracts" (existing) and "calls to untrusted contracts whose return values are trusted" (new). RC-METHOD fix from dHEDGE post-mortem (2 High misses).
- **Niche agent Processing Protocol**: All 8 niche agents now enforce enumerate-first processing — ENUMERATE targets → PROCESS exhaustively → COVERAGE GATE. Based on CheckEval (EMNLP 2025) and Plan-and-Act (ICML 2025) research showing binary per-item decomposition and plan/execute separation improve checklist adherence. ~100 extra tokens per agent, zero additional API calls. Applies to Core and Thorough modes.
- **Niche agent Coverage Assertion**: Pre-return reminder in all 8 niche agents requiring explicit verification that every enumerated item was processed. Based on Lost-in-the-Middle research — repeating key instructions at prompt end provides recency attention boost.
- **Niche Agent Coverage Judge (Thorough only)**: Post-iteration-1 haiku agent that mechanically cross-references niche output files against function_list.md to detect skipped entities. If gaps found, spawns targeted sonnet gap-fillers for missed items only. Added to all 4 language trees (EVM, Solana, Aptos, Sui).

## [1.1.0] - 2026-03-27

### Added
- **EVM CHECK 2g**: Missing native ETH receiver detection — flags payable functions/contracts that lack a `receive()` or `fallback()` function
- **DIMENSIONAL_ANALYSIS injectable skill**: Unit/dimension mismatch analysis for protocols using mixed fixed-point arithmetic (MIXED_DECIMALS flag)
- **Move-Safety Agent architecture (Aptos/Sui)**: New `move-safety-core-directives` skill split from the 4 always-required skills (~950 lines total). Core directives (~130 lines) load into every breadth agent; a dedicated Move-Safety Agent gets full skills. Prevents attention saturation on dense methodology.
- **Phase 5 batched verifier spawning**: When >8 verifiers needed, splits into severity-tier batches (A: Chain+High opus, B/C: Medium sonnet, D: Low+Info single agent). Crash-resume support — skips already-verified hypotheses on restart. Short return messages (~50 tokens/agent) prevent orchestrator context bloat.
- **New niche skills**: `callback-receiver-safety` (EVM callback handler access control, state inflation), `multi-step-operation-safety` (authorization conflicts, on-behalf-of targeting)
- **New injectable skill**: `lending-protocol-security` for lending protocol audits
- **Depth template improvements**: ANCHORING REJECTION LIST (7-row table of insufficient REFUTED/CONTESTED justifications), File Coverage Map task in inventory prompt, MIXED_DECIMALS flag in recon

### Fixed
- **`nice -n 10` on Unix**: Indexer processes now run at reduced CPU priority on macOS/Linux — keeps machine responsive during RAG build (~10-20% throughput cost on idle machine; none on loaded machine)
- **Adaptive RAG timeouts**: Fanless Macs (MacBook Air) get extended timeouts (1800s Solodit, 900s embedding) and reduced Solodit page count (5 vs 10) to prevent thermal-throttle timeouts
- **Resource warning banner**: `plamen rag` now warns before indexing: "RAG indexing is CPU and RAM intensive. Your machine may feel sluggish — do not close this terminal."
- **Status box RAG hint**: "not built" now shows "run 'plamen rag' (~10 min, CPU intensive)" hint
- **`sys.executable` MCP injection**: `_merge_mcp_json` replaces `"python"`/`"python3"` with `sys.executable` at install time — eliminates "spawn python ENOENT" on macOS/Linux without manual sed
- **Malformed JSON handling**: `_merge_settings_json` and `_merge_mcp_json` now show friendly errors (not raw tracebacks) when existing config files have trailing commas or syntax errors
- **Removed dead package installs**: `solodit-scraper` and `defihacklabs-rag` removed from `_setup_python_deps` — `unified-vuln-db` handles all RAG indexing internally; `defihacklabs-rag` had `openai>=1.0.0` as unnecessary hard dep
- **`plamen rag` dep-guard**: `_build_rag_db` auto-installs missing RAG deps before indexing — `plamen rag` is now self-healing after a fresh clone or partial install
- **Sentence-transformers quick-check**: `_setup_python_deps` quick-check now uses `import sentence_transformers, chromadb` instead of `import torch` — avoids 2-3s torch cold-start on every `plamen setup`
- **Pip `--user` args fix**: Corrected `[3:]` → `[4:]` slice bug that produced `--user --user` args
- **Always MiniLM embeddings**: Removed Nomic/Voyage model selection — always uses `all-MiniLM-L6-v2` (384-dim, ~90MB). Eliminates RAM crashes on 16GB M1 Macs.
- **`_python_bin()` space-quoting**: Uses `sys.executable` with double-quote wrapping for paths containing spaces

## [1.0.13] - 2026-03-26

### Changed
- **RAG separated from `plamen setup`**: The `setup` command no longer installs PyTorch (~2GB), chromadb, sentence-transformers, or builds the RAG database. These are now installed and built exclusively via `plamen rag`. This prevents 1+ hour install times and crashes on memory-constrained machines (M1 Macs with 16GB RAM, fanless MacBook Airs). Setup now completes in ~30 seconds.
- **New `_install_rag_deps()` function**: `plamen rag` auto-installs RAG Python dependencies before building the index. Users no longer need to manually pip install anything — just run `plamen rag` when ready.
- **Fixed `_RAG_MIN_ENTRIES` undefined**: Added missing constant (500) that would crash `check_dependencies()` at runtime.

## [1.0.12] - 2026-03-25

### Added
- **RAG indexing resource warning**: `_build_rag_db()` now prints a caution banner before indexing starts — warns that the process is CPU/RAM intensive, the machine may feel sluggish, and the terminal should not be closed.
- **`nice -n 10` on Unix indexer commands**: On macOS/Linux, all indexer subprocesses run at reduced CPU priority (`nice -n 10`), yielding CPU to other applications. No effect on indexing quality, ~10-20% slower on idle machines. Silently skipped on Windows.
- **First-time RAG hint in status box**: When RAG DB is not yet built (`-1`), the status box now shows `run 'plamen rag' (5-20 min, CPU intensive)` instead of bare `not built`, guiding new users.

## [1.0.11] - 2026-03-25

### Fixed
- **RAG build wipes wrong ChromaDB path**: `_build_rag_db()` wiped `custom-mcp/unified-vuln-db/data/chroma_db` instead of the actual database location `unified-vuln-db/data/chroma_db` (per `database.py` `parents[3]` resolution). The nuke was a silent no-op, leaving stale DBs from crashed builds untouched and causing rebuilds to fail with partial data.
- **Per-source RAG timeouts**: Replace flat 600s timeout with per-source limits — Solodit 1200s (20 min) / 1800s on fanless Macs (30 min), indexing 600s / 900s. Solodit retries removed (hanging API call doesn't improve on retry). Immunefi retry uses `--skip-fetch` to reuse cached HTTP responses instead of re-fetching 139 URLs.
- **`--skip-fetch` CLI flag**: Expose existing `skip_fetch` parameter in `index_immunefi()` as a `--skip-fetch` CLI flag in the indexer, enabling cache-only retry after a timeout without re-fetching all Immunefi URLs.
- **Solodit page count on constrained machines**: Reduce `--max-pages` from 10 to 5 on fanless Macs / low-RAM machines (29 tags × 10 pages × 3.5s delay exceeds timeout on slow networks).

## [1.0.10] - 2026-03-24

### Fixed
- **RAG build hang on fanless Macs**: Stale ChromaDB with Nomic 768-dim HNSW index caused `get_or_create_collection()` to hang indefinitely when MiniLM 384-dim embeddings were used. Added `_wipe_if_dimension_mismatch()` to detect and clear dimension-mismatched databases before opening.

## [1.0.9] - 2026-03-23

### Added
- **Thermal constraint auto-detection**: `_is_fanless_mac()` detects MacBook Air and other fanless Macs via IORegistry. `_should_use_fast_rag()` switches to MiniLM (`all-MiniLM-L6-v2`, 384-dim, ~90MB) instead of Nomic Embed v1.5 (768-dim, ~500MB) on fanless Macs or machines with <16GB RAM, preventing thermal throttling during RAG indexing. Override with `VULN_DB_FAST_MODE=0/1`.

## [1.0.8] - 2026-03-22

### Added
- **Cross-batch verification consistency check (Phase 5.2)**: Haiku agent checks for contradictions between verification batches before final report assembly.

### Fixed
- **Slither/Hardhat dependency failure**: Resolved installation conflict between slither-analyzer and hardhat dev dependencies.

## [1.0.7] - 2026-03-21

### Fixed
- **Invariant generation bypass**: Agents could shortcut Phase 4b-invariant-fuzz template by summarizing properties inline rather than reading the full methodology file. Enforced agent-read requirement for fuzz templates (Rule 3 hardening).

## [1.0.6] - 2026-03-19

### Changed
- **Non-destructive install**: Plamen now clones to `~/.plamen` instead of `~/.claude`, preserving existing Claude Code configuration. The installer creates symlinks into `~/.claude/` and merges configs additively (settings.json, mcp.json, CLAUDE.md with markers). Closes #3.
- **macOS/Linux support**: All commands use `python3` (not `python`). PATH setup targets `~/.zshrc` on macOS and `~/.bashrc` on Linux.
- **Windows support**: Clone to `$HOME\.plamen` (PowerShell). Directory junctions (no admin needed) for dirs, Developer Mode required for file symlinks. Documented in all setup guides.

### Added
- **Bootstrap auto-install**: `plamen.py` detects missing `rich`/`InquirerPy` on first run and installs them automatically before importing. No more `ModuleNotFoundError` on fresh installs.
- **`plamen rag` command**: Rebuild the RAG database without running full setup. Setup wizard now always shows RAG rebuild option even when database has entries.
- **`plamen help` / `plamen --help`**: Shows all available commands and options.
- **`plamen uninstall` confirmation**: Interactive prompt before removing symlinks and config entries.
- **`plamen` extensionless launcher**: Unix shells find `plamen` on PATH (previously only `plamen.sh` existed, which required typing the extension).
- **Install manifest**: `.plamen-manifest.json` tracks all installed symlinks for clean uninstall with `.pre-plamen` backup restoration.

### Fixed
- **einops missing from requirements**: `nomic-embed-text-v1.5` silently fell back to `all-MiniLM-L6-v2` (384 dims vs 768). Added `einops>=0.7.0` to unified-vuln-db requirements.
- **unified-vuln-db not globally importable**: `pip install -e` was missing, so `python3 -m unified_vuln.indexer` only worked from inside the package directory. Now installed as editable package during setup.
- **Solodit API key ordering**: Setup docs now set `SOLODIT_API_KEY` before running the installer, preventing silent Solodit indexing failure on first install.
- **3x `os.path.abspath` → `PLAMEN_HOME`**: Setup helper scripts (_solana_installer.py, _avm_installer.py, _sui_installer.py) failed when run through symlinks.
- **Solana skill count**: skill-index.md said 19, actual count is 20 (stale from v1.0.3 Trident addition).
- **"Info" vs "Informational"**: finding-output-format.md now matches report-template.md label.
- **CLAUDE.md marker guard**: Missing `<!-- PLAMEN:END -->` no longer crashes install/uninstall.

## [1.0.5] - 2026-03-19

### Changed
- **Skill file architecture**: All 92 skill files restructured from `SKILL_NAME.md` to `skill-name/SKILL.md` named-folder format with YAML frontmatter (`name`, `description`). Enables Claude Code skill registry compliance and reference file splitting for large skills.
- **Verification protocol split**: 4 large verification-protocol files (700-1097 lines) split into `SKILL.md` + `references/` subdirectory (advanced.md, templates.md) for better context management.
- **Orchestrator path resolution**: `commands/plamen.md` updated to construct `skill-name/SKILL.md` paths for standard skills, injectable skills, and niche agents (lines 467, 474, 724).
- **Em-dash normalization**: All em dashes (--) replaced with regular dashes (-) across modified files for consistent formatting.

### Fixed
- **Blocker from PR #1**: `commands/plamen.md` skill path references were not updated in the original PR -- would have caused silent skill loading failures. Fixed before merge.

## [1.0.4] - 2026-03-19

### Fixed
- **Scope file estimation**: Parser now handles markdown tables (`| File.sol | 300 |`), bullet lists (`- contracts/File.sol`), and bare paths (`File.sol`) — previously only bare paths worked, causing "~0 lines, 0 files" for markdown-formatted scope files
- **Cost estimate consistency**: `/plamen` command now calls `plamen.py --estimate` instead of calculating inline — single source of truth, no more divergent numbers between wrapper and command
- **Double confirmation prompt**: Wrapper now passes `wrapper-launch` flag; `/plamen` skips Step 0d (cost estimate + confirmation) when launched from the wrapper since the user already confirmed

### Added
- `plamen.py --estimate` CLI flag: outputs JSON cost estimate for use by `/plamen` command

## [1.0.3] - 2026-03-19

### Added
- **Solana invariant fuzz campaign**: New `phase4b-invariant-fuzz.md` for Solana/Anchor — mirrors EVM v1.1.0 structure with protocol-derived invariants, finding-derived fuzz targets, lifecycle handlers, and 5 mandatory categories. Fills the EVM/Solana parity gap (was explicitly skipped in `phase4b-loop.md`)
- **Trident API reference**: New `TRIDENT_API_REFERENCE.md` (v0.12.0) — prevents method signature hallucination with correct CLI commands, types, and patterns
- **Lending/Liquidation injectable skill**: 247-line methodology covering health factor boundaries, interest accrual, liquidation mechanism safety, DoS vectors, bad debt socialization, collateral factor manipulation, asymmetric pause analysis
- **DEX/Slippage injectable skill**: 134-line methodology covering slippage parameters, deadline enforcement, return value handling, fee tier assumptions, router approval safety
- **Self-transfer accounting check**: Added to TOKEN_FLOW_TRACING in all 4 language trees — detects `sender == recipient` manipulating fees/rewards/snapshots
- **Timestamp unit confusion check**: Added to TEMPORAL_PARAMETER_STALENESS for Sui (`clock::timestamp_ms` vs seconds) and Aptos (`now_seconds` vs `now_microseconds`)
- **Denylist enforcement lag check**: Added to CROSS_CHAIN_TIMING for Sui and Aptos
- **Invariant quality self-check**: Tautological/sensitivity/testability filter before generating fuzz code
- **Scope selector**: Foundation/Integration/Temporal campaign scope based on protocol characteristics
- **Non-triviality guards**: Prevents false confidence from broken fuzz setups (0% success rate detection)
- **Platform dependencies guide**: New `docs/dependencies.md` with per-platform installation, troubleshooting, and Trident version compatibility matrix
- **Windows Developer Mode check**: `plamen.py` auto-detects and warns if Developer Mode is OFF (required for Solana symlinks)
- **OpenSSL auto-detection**: Fuzz templates inline-detect OpenSSL on Windows for Trident compilation
- **Cost estimation in `/plamen`**: Launch confirmation with codebase size, agent count, token estimate, API cost, and plan usage % with color-coded warnings

### Fixed
- **Trident v0.12 commands**: Replaced all `run-hfuzz`/`debug-hfuzz`/`HFUZZ_RUN_ARGS` references with v0.11+ commands (`trident fuzz run fuzz_0`). Trident v0.11+ uses TridentSVM — no honggfuzz/AFL required
- **Cross-platform Trident**: Documented and verified working on Windows (with Developer Mode + OpenSSL), macOS, and Linux
- **Recon probe**: No longer checks for `honggfuzz --version` — checks `trident --version` only

### Changed
- Solana skills: 19 → 20 (added TRIDENT_API_REFERENCE)
- Injectable skills: 5 → 7 (added LENDING_PROTOCOL_SECURITY, DEX_INTEGRATION_SECURITY)

## [1.0.2] - 2026-03-19

### Improved
- **EVM fuzzing**: Invariant fuzz and Medusa campaigns now derive invariants from `design_context.md` (protocol economics) and `findings_inventory.md` (bug targets), not just structural write-site analysis
- **No artificial caps**: Removed max 8/5 invariant limits and max 15 handler limit -- fuzz execution is zero token cost regardless of count
- **Lifecycle sequence handlers**: Mandatory multi-step handlers (create->repay->close) that construct realistic state random individual calls cannot reach
- **Realistic value bounds**: Handlers use protocol-actual decimals and parameter ranges from `constraint_variables.md`
- **Campaign config**: 256 runs x depth 25 (was 64x15), 5 mandatory invariant categories with coverage table in output
- **README restructured**: 865 lines -> 134 lines. Follows Ruff/Foundry landing page pattern
- **Documentation**: New `docs/` directory with 7 focused guides (setup, architecture, audit modes, MCP servers, usage, internals, repository structure)

## [1.0.1] - 2026-03-19

### Added
- **Rule 12**: THOROUGH MODE COMPLETENESS -- mandatory checklist of 13 non-negotiable Thorough steps with violation logging
- **Rule 13**: NO SPEED OPTIMIZATION IN THOROUGH MODE -- blocks weasel phrases that skip steps
- **Pre-Depth checkpoint**: Assertions for invariant fuzz and Medusa campaign completion
- **Post-Depth checkpoint**: Assertions for confidence scores, adaptive loop log, manifest, iteration 2 enforcement
- **Phase 4b.5 inline**: RAG Validation Sweep explicitly marked MANDATORY for Core/Thorough
- **Skeptic-Judge enforcement**: Positive statement that Thorough HIGH/CRIT must run skeptic

### Fixed
- Design Stress Testing now unconditional (1 reserved slot, not budget-conditional)
- AUDIT MODES table updated to match Rule 12 (DST: "1 reserved slot, UNCONDITIONAL")
- `violations.md` and `checkpoint_postdepth.md` registered as scratchpad artifacts
- Removed internal planning document (`RAG_OVERHAUL_STATUS.md`) from public repo

### Changed
- GitHub repo topics added: web3-security, smart-contract-audit, claude-code, solidity, solana, aptos, sui, ai-agent, security-audit, ethereum

## [1.0.0] - 2026-03-14

### Initial public release

Plamen is an autonomous Web3 security auditing agent for Claude Code. This is the first open-source release.

### Core Pipeline
- 8-phase audit pipeline: Recon → Instantiation → Breadth Analysis → Re-Scan → Inventory → Depth Loop → Chain Analysis → Verification → Report
- Two audit modes: **Core** (22-40 agents, HIGH/CRIT focus) and **Thorough** (32-90 agents, all severities)
- **Compare** mode for post-audit improvement against ground truth reports
- Adaptive depth loop with 4-axis confidence scoring and Devil's Advocate iteration
- Iterative chain analysis with enabler enumeration and postcondition-precondition matching
- Mandatory PoC execution with fuzz variants for Medium+ findings
- Tiered report generation (Opus for Critical+High, Sonnet for Medium, Sonnet for Low+Info)

### Language Support
- **EVM/Solidity** — 18 skills, Foundry/Hardhat build, Slither integration, fork testing
- **Solana/Anchor** — 19 skills, LiteSVM tests, Trident fuzzing, Helius on-chain data
- **Aptos Move** — 21 skills, Move test framework, resource/capability analysis
- **Sui Move** — 21 skills, test_scenario framework, object ownership analysis

### Skills System
- 79 language-specific skills across 4 trees
- 5 injectable skills (Vault Accounting, Account Abstraction, NFT Protocol, Governance, Outcome Determinism)
- 5 niche agents (Event Completeness, Semantic Gap Investigator, Spec Compliance, Signature Verification, Semantic Consistency)
- Flag-triggered loading to prevent context dilution

### Scanner Templates
- Blind Spot Scanner A: Tokens & Parameters (+ msg.value loops, returnbomb, gas griefing)
- Blind Spot Scanner B: Guards, Visibility & Inheritance + Override Safety
- Blind Spot Scanner C: Role Lifecycle, Capability Exposure & Reachability
- Validation Sweep Agent with write-completeness checks
- Design Stress Testing Agent (Thorough mode, budget redirect)

### Verification Protocol
- Pre-PoC feasibility gates (Reachability + Math Bounds)
- Evidence source tracking with mandatory audit tables
- Mock rejection rule (CONTESTED, not REFUTED, on mock evidence)
- RAG confidence override (historical precedent protection)
- Chain hypothesis protection with full-sequence PoC requirements
- Bidirectional role analysis for semi-trusted actor findings

### MCP Server Integration
- unified-vuln-db: RAG vulnerability database with Solodit API, DeFiHackLabs, Immunefi
- slither-mcp: Slither static analyzer (Trail of Bits)
- farofino-mcp: Solidity analysis fallback
- foundry-suite: Anvil fork testing, Forge scripts, Heimdall bytecode analysis
- evm-chain-data: On-chain contract ABI/state queries
- helius: Solana on-chain data
- tavily-search: Web search for fork ancestry and documentation

### Python Wrapper (plamen.py)
- Terminal UI with Rich + InquirerPy
- Mode selection, target detection, docs/scope/network configuration
- Auto-detection of project type (Foundry, Hardhat, Anchor, Move)
- Dependency checking, Ctrl+C handling, terminal width adaptation
- CLI fast path for scripted usage

### Security Rules
- 16 rules (R1-R16) covering adversarial assumptions, combinatorial impact, bidirectional roles, cached parameters, worst-state severity, unsolicited tokens, exhaustive enablers, anti-normalization, cross-variable invariants, flash loan preconditions, oracle integrity
- Finding output format with step execution tracking and depth evidence tags
- Severity matrix (Impact x Likelihood) with downgrade modifiers
