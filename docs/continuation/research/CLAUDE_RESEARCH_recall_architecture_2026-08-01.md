# CLAUDE_RESEARCH — Recall Architecture Research Round

**Date:** 2026-08-01
**Scope:** Foundry symbolic testing · mutation testing (Gambit et al.) · Certora Prover/AutoProver · Trail of Bits July 2026 Tribune + ML corpus · the composition/ordering vulnerability class · multi-agent graph topology
**Method:** six parallel research agents, web-grounded with primary sources; load-bearing claims re-verified against the Plamen repo directly
**Companion:** `CLAUDE_REVIEW_codex_architecture_audit_2026-07-31.md` (the architecture audit this builds on)

---

## 1. The one thesis

Six independent research threads, given six different questions, converged on the same conclusion. That convergence is the most important output of this round.

**Plamen's problem is not that it lacks analysis power. It is that it has almost no anchors — nodes whose verdict is true independent of LLM judgment.** The architecture audit found this from the inside (gates that report success while structurally disabled; fixtures that assert output shapes production never produces; a `[CODE-TRACE]` ceiling on most findings). The research found it from the outside, three separate times:

- The formal-verification thread concluded that **the anchor you need is mutation testing, not a prover** — and arrived there while researching provers.
- The Trail of Bits thread independently named mutation testing as the only technique in their corpus that "answers how do we measure our own recall without asking an LLM," because *mutants are generated, so ground truth exists by construction and contamination is impossible*.
- The symbolic-testing thread concluded that a symbolic PASS must **never** be consumed (no vacuity check exists in the Foundry lane), and that the only safe consumption is a **concretely replayed counterexample** — i.e. symbolic execution earns its place as a *PoC generator*, not a new evidence class.

Three different starting points, one answer: **stop trying to make the LLM layer more confident; add mechanical nodes it cannot argue with.**

The second, unwelcome finding: **Plamen's own prompts contain a measured recall-destroying anti-pattern, and it is institutionalized as a virtue.** See §4.

---

## 2. Adopt — ranked, with the first experiment for each

### A-1. Mutation-gate the invariants Plamen already produces — `[SPEC-KILL: n/m]`
**Effort: ~2–3 days. Cost: near zero. This is the highest-value item in the round.**

Plamen's Phase 4a.5 semantic-invariants output is currently *believed because an agent said it*. Gambit (Certora's mutation generator, free, standalone, 34 mutants in 0.69s) generates mutants; an invariant that kills zero mutants is **vacuous** and supports nothing.

The empirical anchor that makes this urgent — **Certora's own contest data**: across two Rust FV contests (47 participants, 40,000 USDC in prizes), participants wrote **2,623 formal rules**; only **23–28% killed a single mutant**. Roughly three-quarters of rules written by motivated humans competing for money proved nothing and passed anyway.

**First experiment (one engineer, one day, no vendor):** take one completed EVM audit, hand-translate its N semantic invariants into Foundry assertions, run Gambit, and measure what fraction kill ≥1 mutant.
- **Below ~25%** → Phase 4a.5 is producing decorative output, which is a bigger and more actionable finding than anything a prover would give you.
- **At or above ~25%** → you have just built the pipeline's first mechanically-true quality metric.

Either outcome is worth more than the experiment costs.

### A-2. Fix the over-filtering recall leak
**Effort: hours. Highest recall-per-hour in the round.** See §4 — this is verified in the repo, not hypothetical.

### A-3. Mechanical read-coverage (aicov pattern) — replace the self-attested coverage gate
**Effort: 1–2 weeks. The data is already on disk.**

Trail of Bits hit the identical failure ("Codex tends to skip reading the entire codebase even when explicitly asked") and solved it mechanically — they built coverage of which lines the agent actually *opened*, explicitly "so the model can't cheat," then set a follow-up goal to close the gaps.

Plamen's `rules/phase3b-rescan-prompt.md:259-261` asks the agent to self-report a `| File | Lines | Opened? | Functions Analyzed |` table. **That is a gate that validates itself** — exactly the class the architecture audit indicted. Plamen already writes `tool_calls.jsonl`; the driver can compute true read-coverage per worker and auto-spawn follow-ups for under-covered in-scope files. This converts a self-certifying gate into a real anchor using data you already collect.

### A-4. Symbolic testing as a PoC *generator*, EVM only, refutation-only
**Effort: ~1 week pilot. Gated on a vacuity guard.**

Foundry is the one actively-developed symbolic option — and the category is **consolidating into it**, not declining: Manticore and Optik are archived (Trail of Bits exited symbolic execution entirely — all 43 `crytic` repos enumerated, both symbolic tools archived, nothing replaced them), Halmos is dormant since 2025-08-06, greed/ityfuzz/Pyrometer are dead. Foundry documents its symbolic flags as "Halmos-compatible" and is absorbing the use case. Had Plamen adopted Halmos a year ago it would now own a dormant dependency.

**The design constraint, from four independent directions:** never consume a symbolic PASS. Foundry's own docs say *"treat [Incomplete] as 'not established', not as a proof"*; there is **no vacuity check** in the lane; every prover surveyed has a documented path where green ≠ proven; and LLM-generated invariants compile at 96.7% but block a real exploit at **20.4%**.

So: for Medium+ findings that terminate at `[CODE-TRACE]`, restate the existing harm assertion, run `forge test --symbolic --json`, and on FAIL feed the emitted concrete regression test through the PoC path Plamen already has. A wrong property simply fails to reproduce and is discarded by existing machinery. **Blocking prerequisite:** an `assert(false)` vacuity guard — not an invention, it is Certora's default-on `rule_sanity` check imported into a lane that ships without one.

Expect near-zero conversion on AMM math, lending accounting, and economic findings (nonlinear arithmetic). If the pilot shows that, it is the expected result — keep the lane narrow rather than tuning it.

### A-5. Cross-model skeptic + the seven brocards as a pre-PoC triage gate
**Effort: routing change + a small gate.**

Trail of Bits' false-positive pipeline is explicitly *"a two-pass false-positive gauntlet using different models."* Plamen's skeptic/judge currently shares a model family with the verifier it checks, so its disagreement signal is correlated with the thing it is checking.

Their seven "brocards" are a cheap ACCEPT / DISMISS / NEEDS-MORE-INFO filter applied *before* PoC investment. Brocard #2 — **"no exploit from the heavens": dismiss if the attacker's existing capabilities already encompass the claimed impact** — is a principled replacement for Plamen's ad-hoc trusted-actor severity modifier. All seven are generic and Part-0 clean.

### A-6. Narrow-then-widen variant analysis
**Targets Plamen's own recorded dominant miss class (RC-ATTENTION, "found one variant, missed the siblings").**

Trail of Bits' algorithm: write a pattern matching **only** the confirmed bug exactly → generalize **one element at a time** → validate each widening mechanically (must fire on the known-vulnerable site, must stay silent on a known-correct sibling). That validation criterion is the valuable part: it makes variant coverage checkable *without* LLM judgment. Measured yield: 11 variant hits across projects.

### A-7. The composition class — one injectable skill + a 3-line always-on extend
**Effort: ~150 lines in an already-loaded agent. Zero budget slots.**

The Secret Network finding generalizes to a real, decidable, cross-ecosystem class: **Unowned Validation Obligation at a composition seam** — a shared-fate consumer of untrusted input imposes a precondition that *no layer on some reachable path enforces*. Fourteen verified instances across ten ecosystems and thirteen years (Bitcoin Core CVE-2018-17144 → supply inflation; ruby-saml CVE-2025-25291 → auth bypass, and its CVE record literally cites CWE-436; Next.js GHSA-f82v-jwr5-mffw at CVSS 9.1; Nomad Bridge at $190M; PostgreSQL, Exim, CUPS, Spring Security, Java deserialization).

The decisive design point: **frame it as ownership, not ordering.** The same researchers found *two* Critical halts in the same codebase eight days apart — one was an ordering bug, the other had no ordering defect at all (seven layers each treated a field as optional). An ordering-framed methodology finds one of two.

Detection is a **matrix, not a judgment**: rows = obligations, columns = every layer on the path, cells ∈ {ENFORCES(file:line), PARTIAL, DECLINES(reason), DEFAULT-PERMISSIVE, ABSENT}. An obligation with no ENFORCES cell on some reachable path is a finding. Every ABSENT claim requires a dispositioned three-synonym grep — which converts "I found no owner" from a memory claim into a mechanical one, the specific countermeasure for LLMs being bad at proving negatives.

The false-positive control is a **shared-fate gate**: keep only obligations whose violation crosses the isolation boundary (halt, abort, gossip amplification, privilege grant, irreversible write). Drop anything whose failure mode is "returns an error." Without this gate the skill's entire output would land in Appendix C via Plamen's existing Material-Harm floor.

The full drafted skill, its Part-0 self-audit (five violations caught and fixed during drafting), and the five registration touchpoints are in the agent report — it is ready to ship largely as written.

**If only one line of it ships**, make it the always-on extend to the existing pre-auth panic directive: *"...or before the generic decoder/validator whose guarantees the consumer assumes. Name the file:line that owns the check on this path. 'The framework validates it' without a file:line is not an owner."* That is the whole class compressed to one sentence.

---

## 3. Do NOT adopt — and why (this section saves the most money)

**Certora AutoProver — defer entirely.** Announced 2026-07-15, Solidity-only beta, **6 GitHub stars** three weeks post-launch, requires five PostgreSQL databases plus a populated RAG index, and publishes **zero** benchmarks, bug counts, or success rates. Critically: its phases 1, 5 and 6 (system analysis, parallel property extraction, parallel spec generation) **duplicate what Plamen already does**. What Plamen lacks is the discharge engine — obtainable from the Certora Prover directly, on a genuinely free 2,000 prover-minutes/month tier covering EVM + Solana + Soroban + Sui, without the agent layer. And its documented "failed specs are revised" loop has **no documented vacuity gate**, which is the exact reward-hacking shape: an LLM told to revise until the prover stops complaining has a trivially available winning move — weaken the spec.

**The tweet that prompted this: real workflow, zero evidence the fan-out was causal.** Verified as a real post (2026-07-30, 68 likes). But: no artifact, no repo, no protocol, no counterfactual; the author is promoting a tool he tags; and AutoProver's own README already describes parallel property extraction *inside the product*, so the novel step is only fanning out the design doc.

**Do not build a mutation-based recall benchmark.** The hypothesis is falsified, twice, and directly:
- **Vulnerability-mimicking mutants:** only **3.9%** of generic mutants semantically mimic a vulnerability, and those cover only **55.6%** of real vulnerabilities.
- **The killer experiment** (ASIA CCS 2021, by LAVA's own authors, 80+ CPU-years): **no fuzzer discovered any organic bug, despite 50 being available — while finding synthetic bugs in the same binaries routinely.** Same binaries, same tools, same run, zero transfer.
- **The structural reason:** a mutant is a bug that *contradicts its own surrounding code* — a local anomaly, which is what LLMs are good at. A real audit finding is a bug the developer *believed was correct*, where the whole codebase consistently embodies the flawed assumption and there is no local inconsistency to notice.
- **The ceiling:** Web3Bugs (516 real exploitable vulns, ICSE 2023) shows most real findings need a *high-level semantic oracle*. Every mutation operator is expressible as a syntactic pattern, so the benchmark **structurally over-samples the class tools are already good at and cannot sample the class that dominates real findings**.

A pipeline could score 100% on mutants with zero capability on the bugs that actually hurt. Optimizing toward it would push Plamen back toward flagging every suspicious comparison — the low-precision behavior you spent releases removing.

**Do not adopt fan-out-then-debate as an architecture.** Six compute-matched studies (2024–2026) find single-agent matches or beats multi-agent topologies at equal token budget; debate induces sycophancy up to **85.5%**, with ~70% of agents abandoning correct reasoning after peer exposure. **Keep the distinction sharp:** this refutes *fan-out-then-debate on one question*. It does **not** refute *parallel scope partition* — different agents reading different code — which is what Plamen actually does and which its sibling-miss problem argues for.

**Do not adopt any standalone symbolic tool** (category consolidating into Foundry) and **do not migrate SMTChecker** — verified, Plamen doesn't use it, so its BMC-engine deprecation is a non-issue.

---

## 4. Verified in the repo: three recall leaks

### 4.1 Output caps + severity prioritization — the measured anti-pattern, institutionalized

Trail of Bits' skill-authoring guide names this explicitly:

> **"Over-Filtering in Delegation"** — asking an agent to report only high-severity issues upfront "causes the agent to investigate thoroughly, then suppress output, making **precision rise while recall collapses** — appearing as a capability loss when it's a prompt problem. Request everything with severity attached, then filter separately."

**Plamen does this pervasively.** Verified by grep across every language tree:

| Location | Instruction |
|---|---|
| `prompts/*/phase4b-scanner-templates.md` | `Maximum 5 findings [BLIND-A1] through [BLIND-A5]` (also B: 5, C: 8–9) |
| `prompts/*/phase4b-scanner-templates.md` | `Maximum 12 findings (prioritize by impact)` |
| `prompts/*/phase4b-scanner-templates.md` | `Maximum 8 findings - prioritize by severity` (sibling propagation, DST) |
| `prompts/*/phase4b-loop.md` | `Max 5 findings total across all re-examined functions` |
| `rules/phase3b-rescan-prompt.md` | `Maximum 5 findings per agent - prioritize by severity` |
| `prompts/*/self-check-checklists.md:92` | `- [ ] Anti-dilution: max 5 findings per agent per iteration?` |

That last row is the deepest instance: the anti-pattern is **codified as a virtue the agent is asked to self-certify.**

**An important distinction I want to preserve, because not all caps are equal.** Plamen's *input* caps (AD-3's "max 15 findings into a depth agent," domain-filtered views) are context management and are defensible. The problem is *output* caps and "prioritize by severity" instructions — those tell an agent that has already done the analysis to throw work away. On a pipeline whose binding constraint is recall, that is the wrong side of the trade. **Recommended change: remove output caps and severity-prioritization from producer prompts; keep every finding with severity attached; filter downstream where the driver can ledger what was dropped.** Plamen already has the dedup, consolidation and Material-Harm-floor machinery to do the filtering properly — and unlike a suppressing agent, that machinery leaves a record.

### 4.2 Self-attested coverage gate
`rules/phase3b-rescan-prompt.md:259-261` — the `Opened? YES/NO` checkpoint. See A-3.

### 4.3 Clean bills of health (checked, no action needed)
- **No verification scaffolding** in any prompt — zero hits for "double-check" / "verify your answer" / "check your work". Trail of Bits reports these *reduce* output quality on current models; Plamen is already clean.
- **SMTChecker** is not used anywhere, so the BMC deprecation (Solidity PR #16877, merged 2026-07-23, removal possible in 0.9.0) does not affect you.
- **Model diversity** already exists for depth agents (opus for token-flow/state-trace, sonnet for others) — the gap is specifically skeptic-vs-verifier separation (A-5).

---

## 5. Calibration: what the best-resourced shop in the industry actually achieves

Useful for setting expectations, from Trail of Bits' own AI-native writeup (94 plugins, 201 skills, 84 agents):

- **"On the right engagements, AI-augmented auditors finding 200 bugs a week"** — up from ~15 — but only where "the codebase and scope allow it," and **"An auditor validates every one."**
- **"About 20% of all bugs we report to clients are now initially discovered by AI in some form."** That 20% is a realistic ceiling for AI-*originated* findings today.
- They publish **no false-positive rate, no precision/recall by skill, no cost-per-finding**, and name "no feedback-signal loop yet" as an open problem.

**Plamen's "no mechanical ground truth" gap is an industry-wide gap, not a local deficiency.** Nobody has solved self-measurement. That is precisely why A-1 is worth doing — it is a genuinely differentiating capability, not catch-up work.

Cost anchor from AIxCC: Trail of Bits' Buttercup placed 2nd with **28 vulnerabilities, >90% accuracy, at $39.6k total ($181/point) over 100,000+ LLM requests — using exclusively cheaper, non-reasoning models.** The winning architecture used LLMs to *steer mechanical tools*, not to *be* the oracle. That is the same conclusion as §1, reached in a different domain.

---

## 6. Two more things worth knowing

**A negative-result warning that applies directly to Plamen's improvement protocol.** Trail of Bits' Toucan post-mortem: *"when we tried slight permutations of the original small tests, we could usually get the prompt to fail given relatively minor changes in input,"* and *"It is extremely difficult to get a prompt that generalizes very well across multiple, diverse inputs"* — with no stopping rule: **"you never know when you are done."** For a project tuning ~330 methodology files against audit post-mortems, this is the strongest available argument for the existing RC-AGENT exclusion test and the multi-repo bench discipline. Keep both.

**Class-level beats root-cause-level targeting — measured.** Given the *exact root cause* of a known bug, Trail of Bits reports Codex **"found nothing."** Given *class-level* descriptions, it "surfaced numerous bugs. We reported 9 of them, with 3 already fixed." This is independent empirical support for Plamen's Part 0 rule, arrived at from a completely different direction — and it suggests auditing the iteration-2 finding cards in `phase4-confidence-scoring.md`, whose "Investigate:" prompts are arguably too specific.

---

## 7. Recommended sequence

**This week (days, not weeks):**
1. Remove output caps + severity-prioritization from producer prompts (§4.1).
2. Run the Gambit invariant-vacuity experiment on one completed audit (A-1). One engineer, one day, no vendor, and the result is decision-grade either way.

**This month:**
3. Mechanical read-coverage from `tool_calls.jsonl` (A-3).
4. Cross-model skeptic routing + brocard pre-PoC gate (A-5).
5. The composition-class always-on extend (three lines, A-7).

**Next quarter, gated on the A-1 result:**
6. `[SPEC-KILL: n/m]` as a real gate, with a frozen holdout and a precision counter-metric.
7. Foundry symbolic refutation lane, EVM only, behind the vacuity guard (A-4).
8. Narrow-then-widen variant analysis (A-6) and the full composition skill (A-7).

**Explicitly not scheduled:** Certora adoption, AutoProver, standalone symbolic tools, a mutation recall benchmark, fan-out-then-debate.

---

## 8. Open threads

- **Multi-agent topology analysis of Plamen's own phase graph** (false edges, verifier independence, anchor inventory, write-isolation races) — still in flight; will be appended.
- **Certora's Balancer-hack analysis (Nov 2025)** — Balancer was a Certora client and was exploited; the post body is JS-rendered and could not be fetched. Worth closing before any procurement conversation.
- **AI-auditor precision has no independent published benchmark.** EVMBench measures recall only; SCABench's precision leaderboard is still empty. Any 2026 precision claim is vendor-sourced.
- **A contamination probe you could run nearly free:** apply semantic-preserving mutations (rename variables/functions, reorder independent statements) to your existing human-report benchmarks. If recall drops on a semantically identical codebase, you have measured memorization rather than analysis. Relevant because ~36 of 40 EVMbench repos predate the training cutoff, and on genuinely post-cutoff incidents model rankings *invert*.
