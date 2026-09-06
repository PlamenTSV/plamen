# Plamen Pipeline — Methodology & Architecture Review

**Author:** Claude (Anthropic) — Claude Code review pass
**Model:** Fable 5 / Opus 4.8
**Date:** 2026-07-15
**Nature:** Adversarial design/methodology critique of the Plamen defensive smart-contract audit pipeline. Grounded in the repo (`github.com/PlamenTSV/plamen`): driver structure, CHANGELOG, and the actual gate/assembler code (`enumeration_gate.py`, `mechanical_verify.py`, `report_index_machinery.py`, `plamen_mechanical.py`), plus the loaded methodology rules.

> NOTE: This is the **Claude** review. A separate **Codex** review exists and should be compared against this one. Where the two agree, treat the point as high-confidence; where they diverge, that divergence is itself signal worth resolving.

---

## 1. Methodology soundness

The discover → verify → report spine is sound and matches both human practice and a generate/verify architecture. Its structural limit is ontological, and the code makes it sharper: **not only the LLM phases but the entire mechanical layer are committed to a local, witness-based notion of a finding** — a `(file, function, symbol, line)` anchor plus a directly-assertable harm.

Every recall generator in `enumeration_gate.py` gates on local objects: co-referencing *functions* of a *symbol* (Axis 1), *boundary values* of a numeric *parameter* (Axis 2), *symmetric operation* pairs (Axis 3), a hot-*function* × risk-axis matrix (M2). There is no generator, and no report ontology, for a vulnerability that is an emergent property of the system rather than a property of a location. Classes this shape systematically under-serves — the same ones top-firm ground-truth weights most heavily:

- **Design / economic / mechanism-level flaws** (insolvency under adversarial market composition, incentive misalignment, governance capture over time, liquidation cascades). No `(file, function)` anchor and no unit-test harm assertion. The rules route them out: mechanism-only harm caps at Informational; `[CODE-TRACE]` caps at CONTESTED.
- **Cross-agent seams.** Breadth is role-scoped and per-contract analysis forbids tracing into other contracts. Composition analysis runs on summaries and on postcondition/precondition *tags the agents chose to emit* — downstream of exactly the "methodology existed but wasn't applied" failure.
- **Absence-of-mechanism bugs**, which have no anchor at all.

The closest thing to whole-system reasoning is **M1 (committed-invariant → fuzz)** — the right instinct. But its vocabulary is a fixed `_CI_SHAPES` frozenset (`CONSERVATION`, `REQUESTED_EQ_DELIVERED`, …). A closed catalog of invariant shapes can only express economic invariants someone pre-enumerated, so protocol-specific conservation laws — the ones that matter — fall outside it and are never committed or fuzzed.

Precision-side structural issue, confirmed in code: a finding's *identity* is re-derived at nearly every phase (agent IDs → `INV-NNN` → hypothesis → queue `canonical_id` → report `C-01`/`CID-…`). Each re-derivation is a lossy prose transform, which is precisely why a promotion-completeness gate is needed to detect drops.

## 2. Architecture correctness

The **deterministic driver + disk-marker completion** (`<!-- PLAMEN_STATUS: COMPLETE -->`, v2.1.0) is the strongest decision and retired a whole silent-hang bug class. Keep it.

The core weakness is confirmed by the assembler: **finding identity is reconstructed downstream instead of assigned at the source.** `report_index_machinery.py` computes a real structural identity — `_canonical_finding_hash()` → `sha256` → `CID-…` over normalized `{artifact, local_id, title, location, root_cause, source_ids}`. That is exactly the stable structural key to want. But it is computed **at report assembly, by re-fingerprinting markdown blocks** — "no single authoritative upstream source exists; identity is reconciled across multiple markdown files." So the infrastructure for the right fix exists and is applied at the wrong end of the pipeline: after every lossy transform, instead of before any of them.

Consequence: a large recovery apparatus — promotion harvest, coverage audit, `_synth_report_section_from_verify()` re-synthesizing dropped sections, referent-less re-emit — exists to repair information the architecture loses because state is serialized as markdown and re-parsed by a *different* LLM at each boundary. The changelog is the evidence: recurring regex/ID parsing drops (v2.2.4 namespaced-ID `AXIS-A-1`/`CI-A1` parsed as zero; v2.2.3 caller/callee column misread on non-EVM; v1.1.4). These are the predictable failure signature of prose-artifact-as-API.

**Cleaner architecture:** assign the `CID` hash **at first emission**, persist findings in one append-only typed store (JSONL/SQLite), and have every later phase *annotate* the record rather than re-emit and re-parse it. Dedup becomes a set operation on `CID` at write time; coverage becomes set difference; most of `report_index_machinery.py`'s reconciliation and the promotion-harvest become unnecessary because a record with a permanent key and a mandatory disposition field cannot be lost. The hash function already exists — move it upstream.

## 3. Prior-art comparison

- **Human firms** work top-down: threat-model from intent, *specify* invariants, then read code against them, with heavy economic-design emphasis and one shared mental model. Plamen discovers invariants bottom-up per agent and fragments context. Borrow: a front-loaded, protocol-specific invariant/threat-model spec as the spine — which would also give M1 an *open* invariant vocabulary instead of the closed `_CI_SHAPES` catalog.
- **Static analysis** gives exhaustive, fatigue-free coverage — the weak axis. The enumeration gate is SAST-flavored but bounded by silent caps (§4) where real SAST is exhaustive. Borrow "no cap, close every cell."
- **Symbolic execution / formal verification** prove *absence* over all inputs; the PoC finds one witness on one path. `mechanical_verify` treats subprocess PASS as authoritative truth, but a passing PoC is a witness, not a proof — the architecture has no representation of input-space coverage. For the arithmetic/invariant subset, let the LLM write a spec and a real prover (Halmos/Certora/BMC) discharge it. M1 → fuzz is a partial step; formal discharge is the categorical one.
- **Stateful fuzzing** is high-recall for the cross-function state-machine bugs under-served here, and the Medusa/invariant-fuzz plumbing already exists — but only as a Thorough-mode per-finding *variant* check, post hoc. Promote it to a *discovery* phase seeded by the invariants.
- **Other LLM-agent audit systems** trend to fewer, deeper passes with economic-feasibility reasoning. Plamen's engineering (determinism, resumability, gates) is ahead; per-finding reasoning *depth* may be behind because budget is spread across many shallow role-scoped agents, and the dominant discovery miss (sibling/variant) is a depth failure.

## 4. The mechanical deriver/gate layer

Sound strategy, and in the code better than advisory prose: candidates use **structural composite keys** (`ENUMGAP-KEY:{finding_id}:{symbol}:{missing_fn}`, `VARGAP-B:{fid}:{fbare}:{member}`), idempotent receipt files prevent re-emission, and GAP is **recall-safe by default** (M2: "ambiguous ⇒ GAP"). Generator-only-adds / verify-disposes is respected. Promotion-completeness (found-then-dropped is the dominant loss mode, 100% mechanizable) and the integrity gate (fabricated-proof downgrade) are the two highest-value pieces.

Where it is theater or actively harmful, grounded in the code:

- **Silent recall ceilings.** `_MAX_ENUMGAP_PER_RUN = 40`, `_MAX_PER_DERIVER = 15`, `_MAX_HOT_FUNCTIONS = 40`, `_MAX_COREFS_PER_VAR = 6`. When a cap truncates, the run *looks* fully covered — the "silent truncation reads as covered everything" trap. Dropping obligation #41 silently has the same effect as the non-application it was built to fix.
- **The popularity skip is risk-inverted.** `_SKIP_VAR_REF_THRESHOLD = 25` omits symbols referenced by >25 functions as "too common to gate on." But the variable touched by 30 functions is typically the *global accounting variable* — the highest-value target for a cross-function invariant break. The deriver turns itself off exactly where risk is highest. Structural blind spot, not a tuning nit.
- **Prose-substring reconciliation.** Axis 1 decides a co-referencer is covered when "the function name appears in the block's prose (case-insensitive substring)." That both false-confirms (incidental mention suppresses a real gap) and false-gaps (a covered function under a different name re-emits). Same prose-parsing fragility that produced the recurring ID-parse bugs.
- **Graph-absence → silent no-op** (`if graph is None: return 0`). If the per-ecosystem bake under-resolves the call graph, the gate emits zero, indistinguishable from "nothing to find." Silent under-generation is the dangerous failure. Needs a resolution-ratio self-check that fails loud.
- **Integrity gate fidelity is build-layout-dependent and two-sided.** `mechanical_verify` correctly makes subprocess outcome authoritative, but `_find_build_root()` / `_resolve_foundry_profile()` are best-effort; a profile miss reads `NO_TEST_FILE` and wrongly demotes a *genuine* passing exploit to `INFLATED_PROSE` (the FOUNDRY_PROFILE regression). And `flip_verdict_on_integrity_downgrade()` matches an exact `Verdict: CONFIRMED` regex — a differently-phrased verdict escapes the downgrade. The gate that fights fabrication can both miss fabrications (format escape) and suppress true positives (toolchain miss).

Other mechanizable miss classes (enumerate/diff/reconcile): in-scope function in *no* agent output (entry-point set − analyzed set); every external call site → return-value/reentrancy/staleness disposition; every value-receiving path → accounting-reconciliation obligation; every role → abuse-path disposition; a **severity-monotonicity diff** flagging any non-monotone drop lacking a canonical reason token (audits the loss pipeline itself). Genuinely needs model judgment — route, never decide: shared-root-cause equivalence, whether a boundary value causes *harm*, external-assumption realism, impact magnitude, novel vectors.

## 5. Recall improvements, ranked

Pipeline-loss levers (finding already exists — cheapest, most certain):
1. **Assign the `CID` structural hash at emission, append-only store, phases annotate** (HIGH gain, MEDIUM complexity — hash already exists). Eliminates found-then-re-derived-then-lost by construction; deletes most recovery machinery. Top change overall.
2. **Make every silent cap loud.** When `_MAX_ENUMGAP_PER_RUN` / `_MAX_PER_DERIVER` / graph-absence truncates, emit a `COVERAGE-SHORTFALL` obligation into the Appendix-B human-review lane (LOW complexity — converts invisible recall loss into a visible flag).
3. **Structured agent outputs as the only parsed surface** (HIGH gain, MEDIUM complexity; partly done). Removes the regex substrate under every gate and under Axis-1 reconciliation.
4. **Severity computed once from typed evidence** (MEDIUM-HIGH gain), collapsing the ~6 lossy re-narrations; kills silent under-severity demotion.

Discovery-side levers (never found):
5. **Top-down protocol-specific invariant spec as the spine**, fed into M1 to replace the closed `_CI_SHAPES` catalog (HIGH gain, MEDIUM complexity). Attacks non-application on the design/economic class.
6. **Fix the risk-inverted popularity skip** — invert it: highest-fan-in state variables get *more* co-reference gating (LOW complexity, targeted gain on the highest-value bug class).
7. **Promote stateful invariant fuzzing to a discovery phase** seeded by #5 (HIGH gain on state-machine bugs; tooling present).
8. **Symbolic/BMC discharge for the arithmetic-invariant subset** (MEDIUM gain, higher complexity) — the only categorical win over PoC-sampling.

## 6. Precision / anti-bloat

FP is already low; the real problems are fragmentation, severity mis-calibration, Info clutter.

- **Same-root-cause fragmentation** is structural: overlapping-scope parallel agents re-find the same bug; dedup deferred to late prose consolidation. `_canonical_finding_hash` already gives the merge key — apply it **at write time** so the second finder annotates the first record. Direct payoff of lever #1.
- **Severity mis-calibration** → the single deterministic severity function; keep enforcing CONFIRMED-vs-VERIFIED mechanically (integrity gate does this well) so unverified code-trace can't ship as VERIFIED.
- **Info clutter** → keep the material-harm body floor mechanical and aggressive: pure-quality → Appendix C row, never a body section.
- **Gate bloat is the new anti-bloat frontier.** The enumeration gate's caps/denylists are legitimate precision tools; the risk is every post-mortem tempting a new gate. Apply the RC-AGENT presumption test to *gates*: a gate for a miss that was actually agent reasoning-error adds surface with no recall. Gates need a budget cap like skills do.

## 7. Blind spots and the single highest-leverage change

Assumptions I think are wrong:

- **"A finding is a `(file, function)` anchor + a harm PoC."** Baked all the way down into the mechanical generators, so the system is blind to the design/economic/emergent category as architecture, not effort — and that category is often the highest-severity real finding. Recall can look healthy while missing the category that matters, especially if benchmark ground-truth is code-bug-heavy (bench selection is load-bearing).
- **"Subprocess PASS = verification."** It's witness-finding. Two-sided error, confirmed in `mechanical_verify`: believes it *proved* what it only *sampled*, and *demotes* genuine exploits on a toolchain miss.
- **"More parallel role-scoped agents = more recall."** Fan-out buys coverage at the cost of depth; the dominant discovery miss (sibling/variant) is a depth failure.
- **Prose-artifact-as-API** is the accidental-complexity engine behind the entire loss/recovery apparatus and the recurring regex/ID bug class.

**Single highest-leverage change:** take the `_canonical_finding_hash` / `CID` already computed at report assembly and **move it to first emission**, backing a typed append-only finding store that every phase annotates rather than re-emits. This eliminates the dominant found-then-lost failure by construction, turns dedup and coverage into set operations, gives every mechanical gate and reconciliation a stable structured surface (retiring most of `report_index_machinery.py`'s repair logic and the promotion-harvest), and lets severity be computed once. The hard part — the structural fingerprint — is already built and is being spent at the wrong end of the pipeline to *detect* loss that assigning it at the source would *prevent*.

**Runner-up** (the discovery-side counterpart it doesn't fix): the top-down invariant spec spine feeding an open-vocabulary M1, to attack the non-application misses on the design/economic class no location-anchored generator can reach.
