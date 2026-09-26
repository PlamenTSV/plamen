# Prompt trends & discovery reality check — September 2026

Written while run43 ran. Question asked: is Plamen still good enough on prompts
and thoroughness, given how many failures were "LLM -> artifact format ->
validator"? Reality-checked against the public skill registries and the 2026
benchmark/academic record. Sources at the end.

## 1. What the registries actually are (corrected — first draft undercounted both)

**Forefy's AI Security Registry (ASR, forefy.com/asr)** is not Forefy's three
blockchain skills; it is a curated cross-vendor registry. Measured from
`GET /api/asr` (paged, 20/page): **236 indexed entries** (skills, 7 workflows,
4 goals; sitemap lists 389 skill URLs, 25 plugins, 11 workflows, 7 MCPs), of
which **131 are blockchain/audit-relevant**. Every entry is git-pinned to a
`commit_sha`, carries an `audited_by` (68 of the 131) and an **`ai_slop_score`**
(0–100; 19 of the 131 score ≤20, 59 score >50). It mirrors the ecosystem under
one author field: Trail of Bits' chain scanners (solana/ton/algorand/cairo/
cosmos, `dimensional-analysis`, `entry-point-analyzer`, `property-based-testing`),
Pashov's `solidity-auditor` / `fizz` / `x-ray`, QuillShield's ten
(`semantic-guard-analysis`, `behavioral-state-analysis`, `state-invariant-
detection`, `proxy-upgrade-safety`, `signature-replay-analysis`, …),
kadenzipfel `scv-scan`, Archethect `security-auditor` (Map-Hunt-Attack,
Scope→Hunt→Judge→Coverage→Report), and community skills that matter for
Plamen's comparison:

| ASR skill | what it is | Plamen analogue |
|---|---|---|
| `krait` | 4-phase pipeline recon → detection → state analysis → verification | the phase DAG |
| `judge` | multi-step adversarial FP filter for AI-generated findings | skeptic + typed adjudication |
| `bug-validator` | validates findings against Code4rena judging criteria, predicts acceptance | severity ledger / disposition authority (no contest-criteria lens) |
| `web3-triage-report` | Immunefi report format + 20 real paid bounty examples | report template |
| `feynman-auditor` | language-agnostic business-logic bug finder via the Feynman technique | first-principles (missing — see §3) |
| `client-auditor` | audits node / execution / consensus clients in Go/Rust | L1 mode |
| `code-sleuth` | EVM storage-safety: lost / overwritten / mis-scoped persistent state | storage-layout skill + R14 |
| `spec-compliance`, `scoping-bee`, `protocol-breakdown`, `audit-prep`, `rust-audit-prep` | pre-audit scoping, spec extraction, maturity | recon + SPEC_COMPLIANCE_AUDIT niche |
| `audit-lending`, `audit-liquidation` (×3), `audit-auction`, `audit-clm`, `audit-staking`, `audit-oracle`, `audit-slippage`, `audit-signature`, `audit-state-validation`, `audit-math-precision`, `audit-reentrancy` | **protocol-type / class micro-checklists**, one skill each | injectable skills (LENDING_PROTOCOL_SECURITY, DEX_INTEGRATION_SECURITY…) — Plamen's are broader, the ASR's are more numerous and finer-grained |
| `veerskills` | "300+ attack vectors, 50+ agents, Skeptic-Judge, 6-check FP gate, Nemesis convergence loop, 21-protocol context engine (10,600 findings)" — 1★, slop 70 | a claims list, not evidence; note the registry still scores it |

**pashov/skills (1.16k★, 86 files)** is three top-level skills with real depth
inside:
- `solidity-auditor`: **12 parallel hacking agents**, each bundled with ALL
  in-scope source + `senior-auditor-sop.md` (Socratic questioning; **Inversion**
  — "every clean path gets a backward pass: three concrete attacker moves") +
  `shared-rules.md` (mandatory `[Socratic: …]` / `[Inversion: …]` markers the
  orchestrator greps after the run; `FINDING` needs `proof:`, **"No proof =
  LEAD, no exceptions… default to LEAD over dropping"**; 6-line structured
  output). Nine single-lens agents (math-precision, access-control,
  economic-security, execution-trace, invariant, periphery, first-principles,
  asymmetry, boundary) plus **three "gap" agents that hunt only the SEAMS
  between lenses** (`flow-gap` = trace × periphery × intent, `trust-gap` =
  access × economics × asymmetry, `numerical-gap` = precision × invariant ×
  boundary), each forbidden to report anything a single lens would catch.
  `judging.md`: **four sequential gates** (attack execution → reachability →
  unprivileged trigger → material harm to an identifiable victim), REJECT /
  DEMOTE / CONFIRM, confidence starts at 100 with fixed deductions, "safe
  patterns (do not flag)" list.
- `fizz`: six **invariant-discovery agents** (adversarial-profit-maximizer,
  conservation-auditor, protocol-type-specialist, roundtrip-rounding-analyst,
  state-transition-mapper, synthesizer) + implementers, a full Echidna/Medusa
  template suite, and a provenance tag per property: **SHOULD-HOLD only with
  citable evidence, otherwise EXPLORATORY** ("a HIGH-priority guess is still
  EXPLORATORY").
- `x-ray`: 41 KB pre-audit skill with 48 KB `threats.md`, 47 KB `templates.md`,
  a 49 KB git-security analyser; <500 lines output, "no fabrication — say
  could not determine".
- README: "target 2–5 hot contracts"; "**run more than once** — LLM output is
  non-deterministic; 2–3 passes catch what one misses."

Also in the ecosystem: quillai `quillshield_skills` (10 plugins, "a contract is
its own specification"), trailofbits/skills (3.3k★, 58, runs real tools),
auditmos (14), Cyfrin, OpenZeppelin, and `tradingstrategy-ai/openaudit`, a
meta-runner that runs all of them ("different tools collectively found the 4
issues humans missed — each covers a different subset"). pashov's
`ai-web3-security` list files `PlamenTSV/plamen` under autonomous agents.

Everything above is a **single-session prompt bundle** or a registry of them.
None has a typed phase DAG, content-addressed receipts, PoC ledgers with harm
assertions, model attestation, candidate-negative proposals, or a recall-safe
report floor. On architecture Plamen is not in the same category — but the
registry ecosystem is far broader and finer-grained on **discovery lenses,
protocol-type checklists, and judging criteria** than the first draft of this
note admitted.

## 1b. What the community skills actually do (read at their pinned commits, not from descriptions)

- **`krait`** (Zealynx): Phase 0 recon with *deterministic file risk scoring*;
  Phase 1 detection = 3 passes × **4 lenses × 4 mindsets, 101 heuristics**,
  detection modules activated by protocol type; Phase 2 state analysis =
  **coupled state-pair analysis, mutation matrix, masking-code detection**;
  Phase 3 critic = **8 automatic kill gates**, concrete exploit trace required
  for every H/M; **Phase 3b = a REVIEWER that second-opinions the critic's
  killed findings ("catches over-filtering")**. Claims "100% precision across
  50 blind shadow audits, 0 FP" — precision only; recall is not reported,
  which is the number that matters. Treat as a design reference, not evidence.
- **`feynman-auditor`** (nemesis): seven question categories applied to EVERY
  function ("do not skip simple functions"): purpose, ordering, **consistency
  ("why does A have it but B doesn't" — the inverse operation must validate at
  least as strictly)**, assumption, boundary, return/error path, and
  **external-call reordering: swap the external call and the state update
  and see which direction reverts — the one that reverts is the ordering the
  code depends on; the one that doesn't is the ordering an attacker can
  exploit.** That last one is a concrete, mechanical depth heuristic.
- **`judge`** (The-Judge): a validation pipeline, not a scanner. Step 2
  privileged-role determination with an explicit default trust table
  (owner/admin/governance/timelock/multisig/dao/council = TRUSTED;
  operator/keeper/guardian/manager/deployer = SEMI-TRUSTED, "flag but don't
  auto-downgrade"); Step 3 a **generic invalidation library** (a selector
  picks the 3 most applicable reasons, 3 checkers test them); Step 4 an
  issue-specific adversarial generator told to go BEYOND the library + 3
  checkers + a judge; external-protocol research with a claim cache; verdict
  VALID / INVALID / DOWNGRADED with the exit step recorded. Plamen's skeptic +
  typed adjudication + `FULLY_TRUSTED_ACTOR` cover the same ground; the typed
  *invalidation library* is the reusable artifact.
- **`semantic-guard-analysis`** (QuillShield): the algorithm is explicit and
  deterministic — for each writable state variable S: M = functions that
  write S; G = guards common across M; **V = M \ G is the candidate set**;
  ≥80% guard frequency = strong invariant (H/C), 50–79% = weak (M), <50% =
  ignore; then a privilege overlay (public = highest scrutiny; admin = must be
  consistent with each other; emergency = still guarded). Plus a
  "rationalizations to reject" list. This is a Rule-0 pre-pass specification
  as written.
- **`audit-liquidation` / `audit-*`** (auditmos): each protocol-type micro-
  skill has a "**False Positives — Do NOT Flag**" section (trusted
  liquidators, documented minimum sizes, admin-only setters with timelock…).
- **`bug-validator`**: 13 automatic invalidators (C4 criteria), severity
  ALIGNED / INFLATED / DEFLATED with inflation heavily penalised.
- **`client-auditor`** (DarkNavy): node/execution/consensus clients in Go/Rust;
  explicit **context-management rules — the orchestrator must never read
  pattern files or source directly** (compaction is named as the failure
  mode); cross-subsystem agent; adversarial review of every H/C in DEEP mode.
  Closest external peer to Plamen's L1 mode.

## 2. The 2026 record on discovery (what actually moves recall)

- **Hypothesis-validation is the paradigm** (VulAgent, Findings of ACL 2026):
  "relax discovery from vulnerability adjudication to **high-recall
  sensitive-code spotting**, defer correctness to hypothesis construction +
  validation." +6.6–8.2 pts accuracy, −36–42% FP. Plamen already IS this
  (breadth proposes; verify adjudicates; producers cannot close candidates).
- **Generator/critic doubles effectiveness** (GPTLens: 76.9% vs 38.5%
  single-stage). Plamen: skeptic + adjudicator. ✔
- **Mythos pipeline** (Anthropic, Firefox: 271 vulns): file priority scoring →
  parallel isolated VMs → hypothesis → **execution verification with
  sanitizers + reproducible PoC** → **separate adversarial self-review agent**.
  Plamen: PoC-mandatory with a HARM assertion (not mechanism), skeptic. ✔
- **OpenAnt**: closed-loop **attacker simulation under realistic constraints**
  → exploit evidence, not "suspicious pattern". Plamen's verify phase. ✔
- **Benchmarks, independently verified numbers** (Odd Sequence, 84 tools /
  60 papers): EVMBench (OpenAI+Paradigm, Feb 2026: 120 vulns / 40 real
  audits; Detect/Patch/Exploit) — Claude Opus 4.6 **45.6% detect**,
  GPT-5.3-Codex 72.2% exploit. SCONE-bench 65% post-cutoff exploit.
  ScaBench: Hound **31.2% recall**. Nethermind AuditAgent **40% recall /
  4.1% precision** on independent eval; Savant Chat **35% / 17.9%** (self-
  reported VDR 0.952). "FP rates on real-world DeFi often exceed 97%."
  Plain GPT-5, no tools: 25.5% of high-sev.

**Reality check:** the honest external frontier for single-tool recall on
real audits is ~30–45%, with precision in single digits to teens. Calibrate
DODO expectations against EVMBench/ScaBench-style scoring, not vendor claims.

## 3. Where Plamen's DISCOVERY prompts are behind the best registries (honest)

1. **Inversion is not a pass-1 discipline.** Pashov applies "backward pass
   with three concrete attacker moves" to EVERY path judged clean in the FIRST
   pass, and greps the marker afterwards. Plamen's Devil's-Advocate role only
   arrives in depth iteration 2, and only for UNCERTAIN findings. Clean-looking
   code in pass 1 gets no adversarial second look.
2. **No assumption-violation lane.** Pashov's `first-principles-agent`:
   "ignore named classes; extract every assumption (value freshness, ordering,
   identity, arithmetic, state); violate it; exploit the break." Plamen's
   breadth roster is class-specialised; DST and DA cover fragments of this.
3. **Asymmetry is a directive, not an agent.** Pashov runs a full 6-step
   asymmetry agent (operation pairs, branch pairs, writer/reader pairs, admin-
   variant vs user-variant, and "bad symmetry" — over-restrictive duplicate
   checks causing permanent DoS). Plamen has the Symmetric Pairs Directive and
   rescan's "asymmetric operations" bullet.
4. **No per-skill False-Positives section.** Forefy's case files pair every
   detection heuristic with the FP shapes for that class. Plamen's inventory
   churn is partly noise arriving from breadth; FP notes at the source are a
   precision lever Plamen's ~150 skills do not have.
5. **No reviewer of the critic.** Krait's Phase 3b second-opinions every
   finding the critic killed, explicitly to catch over-filtering. Plamen's
   skeptic is proposal-only and adjudication preserves body placement, which
   is stronger on paper — but nothing re-examines a candidate the verifier
   REFUTED. A cheap "refutation review" lane is the recall-safe complement.
6. **No mechanical "consistency principle" pre-pass.** QuillShield's semantic
   guard analysis is exactly a Rule-0 candidate: Python enumerates, per
   function, the guards the contract applies (modifiers, `require` shapes,
   caller checks, pause/reentrancy guards) and flags the OUTLIERS as candidates
   for breadth. High recall, deterministic, no LLM in the loop.

## 4. Where Plamen should NOT follow the registries

- **"Always prefer lower severity"** (Forefy). Plamen's R10 worst-state +
  recall-safe body floor is the correct inverse for an audit whose unacceptable
  error is a missed real bug. Keep it.
- **"Findings in minutes"** framing. Registries optimise for a fast single
  session; Plamen optimises for exhaustive coverage with evidence. Different
  product; do not trade thoroughness for speed.

## 5. On the premise "a ton of our failures are LLM -> artifact format -> validator"

Today's measured ledger disagrees on the cause and agrees on the remedy:
- Runs 41–43: zero malformed model outputs; every retry/halt was a recogniser
  narrower than its own producers' language, or a provider refusal.
- But the registries' output contracts are **tiny** (Pashov: a 6-line
  `FINDING` block) and everything else is assembled by the orchestrator.
  Plamen's inventory chunk asks the model to transcribe ~50 multi-paragraph
  blocks verbatim — the largest format-risk surface in the pipeline, and the
  one place retries were ever observed to make things worse.
- Multi-pass discovery (breadth → rescan → per-contract → depth iterations) is
  the right answer to discovery non-determinism; Pashov says so outright.
  Format non-determinism is answered by shrinking the surface, not by prompting.

## 6. Recommendations, ranked

1. **Inventory chunk emits decisions, not transcriptions.** Model outputs
   mapping / severity / merge decisions in a compact block; Python assembles
   every facet from source bytes (the facet-restoration splice already does
   half of this). Biggest reliability win available; removes the data-bus use.
2. **Deterministic consistency-principle pre-pass** (Rule 0), using the
   semantic-guard algorithm verbatim: per writable state variable, writers M,
   common guards G at ≥80% / 50–79% thresholds, candidates V = M \ G, then
   the privilege overlay. Feed V to breadth as named candidates. Cheap,
   deterministic, high recall.
3. **Inversion in pass 1**: every function a breadth worker judges clean gets a
   required `[Inversion: <3 concrete attacker moves>]` marker; the driver counts
   them like `Step Execution`. Prompt + validator, small.
4. **First-Principles and Asymmetry as always-on Thorough breadth lanes**
   (adapt Pashov's two agent prompts; genericise — no protocol names).
5. **Per-skill "False Positives" sections** for the noisiest classes first.
6. **Two depth heuristics worth lifting verbatim**: Feynman Q7 ("swap the
   external call and the state update; whichever direction reverts is the
   dependency, the other is the exploit") for depth-state-trace, and Krait's
   coupled-state-pair mutation matrix for the semantic-invariants phase.
7. **Refutation review lane**: a bounded second opinion on verifier-REFUTED
   candidates before Appendix A, mirroring Krait 3b. Recall-safe by
   construction (can only re-open, never close).
8. **Typed invalidation library for the skeptic** (from `judge`): a closed
   list of generic invalidation reasons the skeptic must select from and a
   separate "beyond the library" generator; both remain proposal-only.
9. **Benchmark against EVMBench / ScaBench scoring**, publish recall AND
   precision, expect 30–45% single-pass recall as the external frontier.

## Sources
- pashov/skills — https://github.com/pashov/skills (x-ray, solidity-auditor:
  senior-auditor-sop.md, hacking-agents/{shared-rules,asymmetry-agent,first-principles-agent}.md)
- forefy/.context — https://github.com/forefy/.context (smart-contract-audit/SKILL.md, multi-expert.md, reference/solidity/fv-sol-*)
- Forefy AI Security Registry, security-auditor — https://forefy.com/skills/55d1c321-5b93-4581-a188-d70480f5e07a
- quillai-network/quillshield_skills — https://github.com/quillai-network/quillshield_skills
- tradingstrategy-ai/openaudit — https://github.com/tradingstrategy-ai/openaudit
- pashov/ai-web3-security — https://github.com/pashov/ai-web3-security
- Odd Sequence, "84 Tools, 60 Papers, One Question: Is AI Auditing Ready?" — https://oddsequence.com/research/ai-auditing-ready
- VulAgent (Findings of ACL 2026) — https://aclanthology.org/2026.findings-acl.928.pdf ; arXiv 2509.11523
- OpenAnt — https://arxiv.org/html/2606.19149v2
- Mythos / LLM agent vuln discovery write-up — https://www.mrlatte.net/en/research/2026/05/08/llm-agent-vuln-discovery
- Augment, AI smart contract vulnerability detection guide (FP >97% figure) — https://www.augmentcode.com/guides/ai-smart-contract-vulnerability-detection
- Forefy ASR API — https://forefy.com/api/asr (paged) and /api/asr/<id> (per-skill: github_url, skill_path, commit_sha, audited_by, ai_slop_score)
- krait — https://github.com/ZealynxSecurity/krait @2e82023
- The-Judge — https://github.com/heavyw8t/The-Judge @710e06a
- feynman-auditor — https://github.com/0xiehnnkta/nemesis-auditor @83c28b7
- bug-validator — https://github.com/santiagoib/bug-validator @04b5b6e
- client-auditor — https://github.com/DarkNavySecurity/web3-skills @f5ee98f
- auditmos audit-liquidation — https://github.com/auditmos/skills @c958b3a
- QuillShield semantic-guard-analysis — https://github.com/quillai-network/qs_skills @75d48a8
