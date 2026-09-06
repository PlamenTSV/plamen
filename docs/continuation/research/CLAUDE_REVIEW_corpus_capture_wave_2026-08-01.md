# CLAUDE_REVIEW — Corpus Capture Wave

**Date:** 2026-08-01 · **Question:** can Plamen's methodology, agent spawns, counts and wiring actually capture bugs like the ones found in the wild?
**Corpus:** `https://0xsimao.com/findings` — 778 real contest findings (Sherlock / Code4rena / CodeHawks / Immunefi)
**Method:** 4 parallel slices — 2 corpus partitions (84 findings fetched and read in full, mapped finding-by-finding onto the methodology inventory), 1 spawn/budget/wiring audit against a complete real Thorough run, 1 testing/topology synthesis. Load-bearing claims re-verified by me.

**Companions:** `CLAUDE_REVIEW_codex_architecture_audit_2026-07-31.md` · `CLAUDE_RESEARCH_recall_architecture_2026-08-01.md` · `CLAUDE_REVIEW_consolidated_verdicts_and_backlog_2026-08-01.md`

---

## 1. The number that reframes the programme

From a complete Thorough EVM run (`scripts/bounty_targets/decentraland/.scratchpad/_plamen.log`, 8h34m):

> **One Python deriver produced 74 candidate findings.**
> **All ~30 LLM discovery agents combined produced 93.**

`recon_prepass.py:495 compute_interface_parity_findings` — a single regex-level mechanical deriver, no AST — accounted for **44% of the entire raw candidate set at ~zero cost and ~zero wall-clock.**

In the same run, **chain analysis produced 3 hypotheses, every one stamped `Severity-Upgrade-Justified: NO` / `Combined-Impact: NONE` — zero upgrades, zero new findings.**

Everything below follows from that asymmetry.

---

## 2. Four measured findings

### F-1. LLM sweep agents under-produce by 3–12×, and caps are not the reason
Measured against their own ceilings in that run:

| Lane | Cap | Produced |
|---|---|---|
| Blind Spot A | 5 | **2** |
| Blind Spot B | 5 | **1** |
| Blind Spot C | 8 | 2 |
| **Validation Sweep** | **12** | **1** |
| Design Stress | 8 | 3 |
| Per-contract (×7) | 5 each | 0,2,3,3,3,4,0 |
| Sibling propagation | 8 | **file never produced** |
| **Python interface-parity deriver** | *uncapped* | **74** |

**This inverts my earlier P-1 recommendation, and I'm correcting it.** I previously called removing output caps "the highest recall-per-hour fix," on the strength of Trail of Bits' measured over-filtering effect. The caps are real and the severity-prioritization language should still go — but **they are not the binding constraint.** An LLM told to "sweep every division / every guard / every sibling" returns 1–3 exemplars regardless of how many exist. Raising the caps would change nothing.

The failure is also **silent**: an agent that swept 3 of 40 division sites reports success identically to one that swept all 40. That is the same silent-pass class already in your memory as the optimistic-ID-regex lesson.

### F-2. Chain analysis is aimed at ~5% of real findings
Two independent corpus samples agree:

| | Slice 1 (40 findings) | Slice 2 (44 findings) |
|---|---|---|
| Chain shape ("A's postcondition enables B") | **0 / 40** | **2–3 / 44** |
| Single finding requiring N facts held at once | 40 / 40 | 41–42 / 44 |
| 1-fact local defects | 0 | 7 (16%) |
| 3+ facts composed | 70% | 41% |

**93–95% of real findings are a single defect whose discovery required holding 2–4 code facts about one path simultaneously.** They do not decompose into "Finding A enables Finding B." They decompose into "you had to look at four things before you could see one thing."

**But the allocation is only wrong in Light.** Measured: chain is 5.1% of discovery agents and 4.7% of wall-clock in Thorough — roughly proportionate to its 5–7% corpus share. In **Light** it is **~22% of all discovery agents**, because `Phase("chain")` carries no `modes=` restriction while scanners, niche agents and sweeps are all gated off. Light gets 4 depth agents, zero scanners, zero niche — and still pays for 2 chain agents. (The L1 pipeline already removed chain entirely, on exactly this reasoning.)

### F-3. The dominant shortfall is "wrong enumeration target"
Across 84 mapped findings: **OWNED 30–48%, PARTIAL 32–60%, UNOWNED 10–20%.** PARTIAL dominates — the check exists and asks a sensible question, but never sees the entity.

The clearest instance: a check enumerates functions that **trigger** accrual, when the bug is in functions that **write accrual inputs without triggering it** — the exact inverse. Others: Design Stress enumerates *bounded* parameters, so an attacker-appendable *unbounded* collection has no row; a capability-reachability check enumerates *inherited base internals*, so a capability held via ownership of a separate deployed contract is invisible; a token-identity check enumerates *external calls returning tokens*, so a hardcoded chain-keyed address constant is invisible.

**And critically — gaps concentrate at LOW compositional depth, not high.** Slice 2's 1-fact findings (nested-loop index reuse, missing distinctness check on two same-type params, validating the wrong one of two similar fields) were *all* UNOWNED or PARTIAL. Plamen is not failing at hard compositional reasoning. It is failing at mechanical enumerations nobody wrote.

### F-4. EVM has zero narrowing-cast coverage — and every other ecosystem has it
✅ **VERIFIED BY ME.** Grep across `prompts/` per ecosystem:

| Ecosystem | `UNSAFE_CAST` | `TRUNCATION` | cast-grep pattern |
|---|---|---|---|
| solana | 2 | 0 | 3 |
| sui | 4 | 2 | 2 |
| soroban | 2 | 0 | 4 |
| aptos | 2 | 0 | 2 |
| **evm** | **0** | **0** | **0** |

Zero hits for `downcast`, `SafeCast`, `uint128(`, `uint96(`, or `narrowing` anywhere in the entire EVM prompt tree. The non-EVM trees have the check because **their recon prompts grep for `as uN`**; the EVM recon prompt has no `uint\d+\(` pattern. Worse, the EVM tree frames integer risk entirely around `unchecked {}` — and lists `unchecked` under **"Safe Patterns — Do Not Flag"** — while explicit `uintN(x)` downcasts truncate *silently in ≥0.8 regardless of `unchecked`*.

This is the strongest single gap found: **a port, not an invention.** It is proven in four ecosystems and it cost the corpus a Crit/High (a value downcast before hashing, leaving the discarded high bits as a free forgery channel).

---

## 3. The organising principle: Enumerate ≠ Decide

Every check decomposes into an **enumeration** step (find all N sites) and a **decision** step (at each site, is this a bug?). F-1 and the 74-vs-93 number are the same fact from two sides: **Python enumerates completely and decides nothing; LLMs decide well and enumerate at 1–3 exemplars regardless of N.**

> **Rule 0 (hard): enumeration always goes to Python. Never to an LLM.**

Then route the *decision* to the cheapest tier that can actually settle it:

| What settles the question | Tier | Failure if misassigned here |
|---|---|---|
| Syntax / type / symbol-graph facts alone | Python decides and emits | FP flood. **This is what interface-parity is today** — 74 rows straight to an Informational file, bypassing every decider. Perfect enumeration, zero decision, near-zero delivered value |
| A bounded arithmetic claim over one function | Symbolic, refutation-only | A solver timeout read as a pass |
| Reachability over multi-call state | Stateful fuzz | Green forever on rare-constant bugs |
| **Protocol intent** — is this divergence wrong *given what the protocol is for*? | LLM, on a bounded pre-computed worklist | The only tier that can answer it |

**Rule 1:** a check may live in an LLM prompt only if its decision step requires *intent*. If the decision is structural, the LLM's presence is a bug.
**Rule 2:** a PASS from fuzz or symbolic never raises confidence. Only counterexamples are evidence.
**Rule 3:** every mechanical tier emits `sites_scanned` alongside `candidates_emitted`. A tier that scanned 0 sites is **dead, not clean**.

---

## 4. Mutation testing: verdict revised

I previously rejected mutation testing on the grounds that mutants are "local anomalies that contradict surrounding code" while real bugs are "bugs the developer believed correct," and that only 3.9% of mutants mimic a vulnerability. **That reasoning was correct for the question it answered — and answers the wrong question here.**

The 3.9% figure is `P(mutant is a real vuln)` — a **precision** statistic. A positive control needs the converse: `P(deriver fires | mutant is a syntactic instance of the deriver's class)`, which is **1.0 by construction or the deriver is broken**. Realism is irrelevant: a deriver that fails to fire on an *unrealistic* instance of its own class is broken regardless of how the instance arose. Likewise the zero-transfer result concerns transfer of *recall estimates*, not of *fires/doesn't-fire*, which is a mechanical property with no organic/synthetic distinction at all.

| Use | Verdict |
|---|---|
| Recall benchmark | **REFUTED** — unchanged |
| Invariant vacuity gate (`[SPEC-KILL]`) | **RECOMMENDED** — and cheaper than assumed; `forge test --mutate` is now native |
| **Deriver positive control** | **NEWLY RECOMMENDED** — this is what changed |

Coverage of the unowned families by stock operators: **3/7 direct** (guard-omission and operator-substitution families), 5/7 with partials, **7/7 with two ~50-line custom operators** (scope-aware identifier swap; narrowing-cast introduction).

**One operational trap to design around:** on a real project with `via_ir = true`, `forge test --mutate` produced 123 mutants, **111 timed out, reported score 0%** — because every mutant triggers a full recompile. With a fast profile: same 123 mutants, **100% killed in 12.3 seconds**. A confidently-wrong 0% is exactly the silent-failure class this document is about, and you have prior history with cold `via_ir` builds. Any mutation lane must force a fast compile profile and refuse to report a score when timeouts dominate. `mechanical_verify.py:703 _resolve_foundry_profile` already knows how to reason about profiles.

---

## 5. An integrity hole in the highest-weight evidence tag

✅ **VERIFIED BY ME.** `[MEDUSA-PASS]` is in `EVIDENCE_TAGS_PROOF` (`plamen_types.py:177`) and weighted **1.0** (`plamen_driver.py:1599`) — identical to `[POC-PASS]` and `[PROD-ONCHAIN]`.

But the only mechanical acceptance test for a fuzz worker is **"markdown file ≥500 bytes and ends with the COMPLETE marker."** Nothing verifies a corpus directory exists, that a harness was written or compiled, or that any campaign ran; no exit code or run log is captured. The prompt's mandatory `## Result Status:` line is **never parsed by any Python**. And `mechanical_verify.py` only ever reads `verify_*.md`, so fuzz sidecars never meet the one layer that could catch this.

**Net: an agent that writes a plausible `medusa_fuzz_findings.md` without ever invoking medusa is indistinguishable from one that ran a real campaign — and its output carries the highest evidence weight in the system.** This is the exact inverse of the discipline `mechanical_verify.py` enforces for PoCs, where `INFLATED_PROSE` forcibly rewrites `CONFIRMED` → `CONTESTED [INTEGRITY-DOWNGRADE]`. The asymmetry is unjustified.

Also worth fixing: the tag *means* "counterexample found." The name reads as the opposite and invites Rule 2 violations at every downstream reader.

---

## 6. Topology: shard, don't fan out

The "hold N facts simultaneously" problem is a **context/enumeration** problem, not a topology problem — **but "one agent + a complete worklist" is also wrong.**

Hand a single agent a 74-row worklist and it will return ~3 dispositions, reproducing F-1 inside the fix for F-1. Multi-instance studies find **instance count, not context length**, is the primary driver of degradation, with decline beginning around 4–8 instances — and you have the same thing measured in production at cap 12 → produced 1.

**The correct shape: Python enumerates completely → shard into bounded batches of ~5 obligations → one worker per shard → mechanical reconciliation of dispositions against the full list.** This is not refuted by the compute-matched multi-agent literature: those studies hold instance count fixed and vary architecture; sharding doesn't add workers for *perspective*, it adds them to keep each worker's instance count inside the reliable regime. That is scope partition, which was never refuted.

**The pattern already exists in-repo** — `phase6-report-prompts.md` shards the report index into per-tier seeds with a "PROCESS ONE TIER-BATCH PER TURN (MANDATORY)" contract and reconciles the merged output against the full seed, emitting a retry hint naming any dropped ID. Apply it verbatim to `enumgap_exploration`.

**And that phase already exists and is starved.** `prompts/shared/v2/phase4b7-enumgap-exploration.md` is precisely the simultaneous-hold architecture — a Python-computed worklist handed to an agent whose sole job is to trace every row to a conclusion. Its own prompt states the thesis: *"An obligation handed straight to a verifier gets dismissed, because a verifier refutes a STATED claim with a PoC — it does not investigate a hint."* **It ran 0 times** in the measured audit, because only 4 derivers feed it and none fired. Meanwhile the highest-yielding deriver in the system bypasses it entirely.

Saturation is bounded by decider throughput, not deriver count: at shard size ~5, **10–12 derivers × ~15 rows ≈ 150–180 obligations ≈ 30–36 shards** is the ceiling. Beyond that you add queue, not recall. Order derivers by *survival rate* (rows surviving the decider ÷ rows emitted) and demote low-survival ones rather than deleting them.

---

## 7. New backlog items

Ranked by recall-per-cost. These extend `CLAUDE_REVIEW_consolidated_verdicts_and_backlog_2026-08-01.md` §3.

| ID | Item | Cost | Why |
|---|---|---|---|
| **P-14** | **Port `UNSAFE_CAST` to EVM** — recon regex trigger + narrowing-cast deriver + inventory hypothesis | XS | A port, not an invention: proven in 4 ecosystems, **verified totally absent in EVM**. Closes one whole unowned family |
| **P-15** | **Deriver liveness telemetry** — every deriver emits `sites_scanned` / `candidates_emitted`; `DERIVER_DEAD: <name>` when zero | XS | Today a deriver whose regex silently stops matching is indistinguishable from a clean codebase. Recall *insurance* for every current and future deriver, ~20 lines |
| **P-16** | **Route interface-parity-class derivers through `enumgap_exploration`** instead of straight to an Informational file | XS | Converts 74 already-computed dead rows into 74 decided obligations. Pure rewiring |
| **P-17** | **Shard the enumgap worklist (k≈5) + mechanical disposition reconciliation** | S | Unlocks the starved phase *and* immunises it against F-1. Multiplies the value of every deriver added after. Pattern already exists in the report-index seeds |
| **P-18** | **Fuzz evidence gate** — parse `Result Status`, require a corpus dir or counterexample artifact before honouring `[MEDUSA-PASS]`; extend `mechanical_verify`'s `INFLATED_PROSE` to fuzz sidecars; rename the tag | S | Integrity, not recall — but it protects the measurement everything else is judged by |
| **P-19** | **Three structural derivers** — nested-loop index reuse, same-type-param distinctness, in-band error sentinel | M | Three genuinely unowned families. Use **SlithIR**, which is verified unused today (`recon_prepass.py` touches only `state_variables_written`; `.irs`/`TypeConversion` appear nowhere) — the richest substrate available is idle behind a working Slither handle |
| **P-20** | **Mechanize the Validation Sweep's enumeration step**, feed sharded deciders | M | Converts a measured 12→1 into ~12. Classifies as `mechanical-gate` under your RC-AGENT-MECHANIZABLE hatch — **not** a new prose rule |
| **P-21** | **Positive-control mechanism** — CI meta-test requiring every `compute_*` deriver to have a matched fires/near-miss pair; plus in-memory inverse mutation at runtime | S–M | Makes P-14/P-19/P-20 trustworthy. The convention already exists (`test_permissionless_setters.py` has 1 positive + 5 near-miss negatives); the gap is enforcement |
| **P-22** | **Gate `Phase("chain")`/`chain_agent2` to Thorough**; single pass over pre-filtered pairs; delete iteration 2 | S | Light spends ~22% of discovery agents on a 5% shape. Shrink, don't delete — 5–7% is real, and `chain_prep.py` already does the expensive part in Python for free |
| **P-23** | **Fix the injectable trigger vocabulary** — `staking`, `dex`, `bridge` classify to zero injectables; 7 of 9 injectables have no `skill-registry.json` entry; protocol type is single-label so at most one can ever fire | S | Pure routing repair, ~2 lines each, no new methodology. Passes Part 0 |

**Do NOT do:** raise output caps (measured non-binding); add prose to scanner templates (Scanner A has 9 CHECKs and returned 2 findings — the 10th won't help); fan out over fact-pairs; mutation as a recall benchmark.

---

## 7b. P-14 prototyped and measured (not just proposed)

I built the narrowing-cast deriver and ran it against three real codebases in `scripts/bounty_targets/`. Regex tier, no compiler, runs in seconds.

**v1 — enumerate every narrowing cast.** Result: dominated by noise. decentraland's audited scope has **35** cast sites, essentially all benign ASCII/string formatting (`uint8(48 + i % 10)`, `bytes1(uint8(bStr[i]) + 0x20)`, `address(uint160(account))`). A naive deriver emitting all 35 would reproduce the interface-parity failure mode exactly — perfect enumeration, zero decision, 35 Informational rows.

**v2 — add the corpus-specified boundary condition** (the narrowed value is *persisted* to storage/struct or enters a *hash/signature preimage*, with a benign-formatting filter):

| Codebase | .sol scanned | casts | benign | **at boundary** |
|---|---|---|---|---|
| decentraland (audited scope) | 158 | 35 | 35 | **0** |
| sparklend | 48 | 33 | 2 | **5** |
| yearnfinance | 115 | 91 | 2 | **81** |

**The decentraland zero is the important number.** Its completed 57-finding Thorough report contains **no** narrowing-cast finding — and the deriver agrees there was nothing to find. The report *does* contain several division-truncation findings (`* rate / 1_000_000`, truncation-to-zero), which are a different and already-owned family. So the pipeline's silence on casts there was **correct**, and the deriver produces **no false-alarm flood on a clean codebase** — the failure mode that matters most given Rule 0.

Where the class exists, it surfaces the right shape: `uint96(pot.dsr())` / `uint120(pot.chi())` / `uint40(pot.rho())` packing **external oracle return values** into a struct (sparklend); `uint16(_targetRatio)`, `uint128(_minimumChange)`, `uint96(_newRoles)` — admin-supplied values and a **roles bitmap** narrowed on the way into storage (yearnfinance).

**What this does and does not establish.**
- ✅ The deriver is cheap, needs no compiler, and discriminates: 0/35 on benign, 5/33 and 81/91 where the class is real.
- ✅ It does not fire on a codebase with nothing to find — validated against a completed audit whose silence was correct.
- ❌ It has **not** been shown to catch a real bug the pipeline missed. decentraland had none of this class to catch. Proving recall value needs a codebase with a *known* cast finding — that is the next experiment, not a claim I can make now.
- ⚠️ **yearnfinance's 81 obligations exceed `_MAX_PER_DERIVER = 15`** (`enumeration_gate.py:1373`). Either the cap rises for this deriver, or obligations need ranking (prefer: narrowed value originates from an *external call* or a *caller-supplied parameter*, over an internally-bounded value). Un-ranked truncation at 15 would silently drop the interesting ones.

Prototype lives at `scratchpad/cast_deriver2.py`; it is a throwaway reference for the real implementation, not production code.

## 8. Corrections and limits

**Corrections to my own earlier claims, recorded so they aren't re-propagated:**

1. **"Removing output caps is the highest recall-per-hour fix"** — wrong. Caps don't bind; LLM under-production does. The severity-prioritization language should still go, but expect little from it. The real fix is Rule 0.
2. **"Off-by-one is an unowned family"** — wrong. `phase4b-scanner-templates.md:339-355` is a dedicated Boundary Operator Precision check with an enumerate→process→coverage-gate protocol *and* a mechanical backstop. It lives inside the Validation Sweep, the agent measured at 12→1. **It is a delivery failure on methodology that already exists**, which makes it `mechanical-gate`, not a new rule.
3. **"`downcast`/`SafeCast` coverage is globally zero"** — wrong as stated; it exists in Soroban, Sui, Solana and the (unreachable) L1 tree. **The gap is EVM-shaped and total**, which is a stronger and more actionable finding.

**Limits of this wave:**
- **Corpus coverage is 84 of 778 findings (~11%)**, drawn from the two most recent partitions. The oldest third was not sampled; older contests may carry different protocol types and different families. Two slices converged strongly, but this is not full coverage and I am not claiming it is.
- **All realized-behavior numbers come from ONE Thorough run** on a low-yield NFT/marketplace codebase (final report: 0 Critical / 1 High / 3 Medium / 18 Low / **84 Informational**). Cap-binding and lane-yield conclusions should be re-measured on a high-yield repo before being treated as general — your own "never sample-of-one" rule applies, and this is the main weakness of the wave.
- Ownership verdicts are inference over methodology text; fact-counts per finding are reconstructions from each writeup's argument, not the auditor's stated process.
- One inherited external figure (the Certora 23–28% mutant-kill calibration) could not be re-confirmed this session and should be re-sourced before external citation.
