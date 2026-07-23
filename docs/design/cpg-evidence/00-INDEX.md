# CPG dataflow producer — research trail & evidence

This folder is the full investigation behind the RFC in
[`../cpg-dataflow-producer.md`](../cpg-dataflow-producer.md). It is the handoff
record: what was proposed (an external "CPG oracle" pitched as "an improved
Slither"), what we found, and the ground-truth evidence for the recommendation.

**Bottom line:** reject the *product* (a hosted, proprietary, DODO-only query
service with no ingestion path and an eval license that bars our use), adopt the
*capability* locally — surface Slither's already-installed-but-unused SSA
data-dependency + dominator analyses into `_mechanical_graph.json` as additive
`taint_edges` / `guards` / `typed_sinks` / `reachability` keys, grounding the
existing M1/M2/G1–G2/chain_prep derivers with graph ground-truth instead of
LLM+grep. EVM-first; Go-L1 next; Rust/Move staged; DAML out.

## Reading order

| File | What it is |
|------|-----------|
| [`10-assessment.md`](10-assessment.md) | Decision-grade assessment: product-vs-capability, the reject-product/adopt-idea call. |
| [`20-cpg-oracle-profile.md`](20-cpg-oracle-profile.md) | Factual profile of `mishoko/cpg-oracle`: what actually ships (an access kit, no builder), the CPG schema, the 7 read-only tools, license/hosting model, maturity. |
| [`21-cpg-oracle-handson-probe.md`](21-cpg-oracle-handson-probe.md) | Access-reality probe of the hosted service (auth model, what's inspectable without a key, no public footprint). |
| [`22-live-oracle-probe.md`](22-live-oracle-probe.md) | **Live probe with an eval key (key redacted):** full MCP handshake succeeded, real Cypher rows from the loaded graph (ZetaChain gateway + DODO route-proxy, 59 contracts). Confirms the schema is real. |
| [`30-slither-reproduction.md`](30-slither-reproduction.md) | **The decisive evidence:** running code (`../cpg-spike/`) that regenerates `validationDominates`, taint→typed-sink, and typed-sink classification from open Slither 0.11.5, deterministically. |
| [`40-plamen-integration-map.md`](40-plamen-integration-map.md) | Exact file:line producer/consumer seams in `recon_prepass.py` / `enumeration_gate.py` / `chain_prep.py`. |
| [`41-plamen-static-stack.md`](41-plamen-static-stack.md) | Inventory of Plamen's current static/structural stack (Slither via CLI bake, Opengrep, SCIP for L1) — no taint/dominance/CPG today. |
| [`42-plamen-integration-points.md`](42-plamen-integration-points.md) | Where structural analysis is consumed across the pipeline. |
| [`43-plamen-capability-gaps.md`](43-plamen-capability-gaps.md) | Methodology gaps a CPG mechanizes (enabler enumeration, chain matching, guard-coverage, taint enumeration). |
| [`50-generalization-and-tradeoffs.md`](50-generalization-and-tradeoffs.md) | Per-ecosystem frontend readiness (EVM/Go/Rust/Move/DAML), security-research payoff, honest pros/cons/risks. |

## Provenance & guardrails

- The live-oracle rows were captured for **internal evaluation only** (what the
  eval license permits). The raw API key is **redacted** from every file here.
- The RFC's schema is designed from the **open Joern CPG spec + LLMxCPG**, never
  copied from the proprietary oracle — see the license guardrail in the RFC §7.
- This is a **design RFC + evidence appendix for review**, not a merge-ready code
  change. The only runnable code is the reproduction spike in `../cpg-spike/`.
