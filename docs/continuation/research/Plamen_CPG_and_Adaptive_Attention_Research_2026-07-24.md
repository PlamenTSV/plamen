# Plamen CPG/Dataflow and Adaptive-Attention Research

Date: 2026-07-24  
Status: research verdict and implementation input; not a completion claim  
PR reviewed: `PlamenTSV/plamen#21` at
`4bb9e3387fc4ff26b5e59cff498468629bb7f52c`

## 1. Executive verdict

Build the CPG/dataflow capability, but do not implement PR #21 as written.

The useful capability is deterministic occurrence-level structural evidence:
CFG dominance, may-dependency, typed operations/sinks, resolved and unresolved
calls, and bounded program slices. This can improve recall and methodology
application by enumerating work the model would otherwise skip and by giving
agents smaller, source-bound evidence slices.

The unsafe part of the RFC is treating those facts as graph ground truth that
can replace existing recall sets or support safe conclusions. Dominance is not
authorization adequacy; dependency is not feasible exploit flow; a sink is not
harm; zero facts are not absence proof.

The correct architecture is a driver-owned, snapshot/build/tool-bound typed
program-facts sidecar committed through PhaseIO. The legacy mechanical graph
contains only a versioned digest/capability reference. Graph facts may add
obligations, rank work, create disagreements, and produce bounded context
slices. They may never suppress, demote, refute, or certify a clean negative.

Blanket agent-count increases are also rejected. Agent expansion should be
driven by exact uncovered obligations and genuinely different evidence
channels. Sequential joins and judgments stay centralized.

## 2. PR #21 claims that require correction

1. The current graph loader reconstructs only legacy fields and drops unknown
   top-level keys. The RFC's proposed keys would not automatically pass through.
2. The current graph is already a versioned schema with typed signatures and
   state symbols. Four unversioned flattened arrays would conflict with that
   evolution.
3. `_mechanical_graph.json` is consumed as a PhaseIO input but is not currently
   an owned semantic-provider output. Adding authoritative data there would
   preserve an ownership hole.
4. Current representation policy correctly treats scratchpad-local provider
   claims as nonterminal. A filename or self-hash does not create independent
   BAKE authority.
5. Chain preparation does not currently consume the Access Guard column as the
   RFC's integration map assumes.
6. M1 is a committed-invariant re-emitter; CFG dominance does not match its
   semantics.
7. M2 already carries typed axes; an unqualified taint axis would double-count.
8. G1 is finding-anchored co-reference enumeration. Replacing its denominator
   with static-analysis taint would lose recall on analyzer false negatives.
9. Existing freshness checks include mtime-based behavior. Semantic providers
   require exact source/build/provider/config binding, not mtimes.
10. Two identical same-host hashes and a four-function fixture do not establish
    cross-platform determinism or full coverage.

## 3. False-ground-truth hazards

- A dominating predicate can be irrelevant to actor authorization or value
  validity.
- A non-dominating check may still protect a sink through branch structure.
- Slither dependency is a may/context dependency relation, not a path-sensitive
  proof.
- Ordinary user input reaching an ordinary transfer may be intended behavior.
- Library, internal, interface, high-level external, low-level, delegate, create,
  and host calls are not one sink class.
- Visibility and modifier names cannot mechanically classify semantic actors
  under proxies, callbacks, registries, dynamic dispatch, account privileges,
  or custom authorization.
- Zero rows can mean unsupported constructs, excluded build variants, partial
  compilation, analyzer failure, truncation, or genuine absence.
- Static analysis cannot decide protocol intent, economic harm, temporal or
  multi-transaction behavior, governance, external-system behavior, by-design
  tradeoffs, exploitability, or severity.

## 4. Recommended program-facts architecture

### 4.1 Dedicated work unit

Add a deterministic `model_invoked=false` PhaseIO work unit such as:

`recon/program_facts_bake`

Owned artifacts:

- `mechanical_program_facts.v1.json`, or provider shards under
  `program_facts/<provider>.json`
- `mechanical_program_facts_receipt.v1.json`
- `mechanical_program_facts_debt.v1.json`

The work unit runs after audit-snapshot binding and before recon workers. It
uses the PhaseIO sequence:

`bind exact inputs/output prestate -> EXECUTION_STARTED -> bake -> validate -> atomic commit`

Failure, staleness, truncation, unsupported features, or partial builds preserve
explicit debt and legacy behavior.

### 4.2 Receipt

The receipt binds:

- audit snapshot and source-scope digests;
- provider, version, executable/module digest, compiler/toolchain, OS/arch;
- command/config and allowlisted environment;
- build roots, profiles, features, tags, remappings, generated sources, and
  dependency closure;
- exact compiled-file denominator and hashes;
- excluded and unresolved constructs;
- timeout, truncation, and resource caps;
- status: `WRITTEN|REUSED|UNAVAILABLE|FAILED|STALE|DEGRADED`.

Use separate hashes for the portable canonical fact payload and the
environment-specific execution receipt. Reuse requires exact compatibility.

### 4.3 Fact shape

Facts use existing canonical function/occurrence identities and include:

- compilation unit and build variant;
- case-aware relative path, source digest, span, statement hash;
- source and target IDs;
- relation kind;
- provider/version/receipt;
- capability and precision scope;
- unresolved or degraded reason.

Prefer honest structural relation names:

- `EXACT_CFG_DOMINATES`
- `EXACT_CFG_POST_DOMINATES`
- `MAY_DEPENDENCY_FUNCTION`
- `MAY_DEPENDENCY_CONTRACT`
- `RESOLVED_STATIC_CALL`
- `MAY_REACH_CHA|RTA|VTA`
- `UNRESOLVED_DYNAMIC_CALL`
- `SYNTACTIC_SINK`
- `HOST_SEMANTIC_SINK`

Use `dominating_predicates`, not `guards`. Never emit `FULL` without an exact
denominator and zero unresolved debt.

### 4.4 Graph envelope

Keep the legacy graph small. Add only a versioned reference:

```json
{
  "program_facts": {
    "artifact": "scratchpad:mechanical_program_facts.v1.json",
    "sha256": "...",
    "schema_version": "plamen.program_facts.v1",
    "provider_set": ["..."],
    "capabilities": ["..."]
  }
}
```

Consumers load the sidecar through a typed, bounded provider. Models receive
deterministic slices with fact IDs, not the raw graph.

## 5. Consumer authority

- G1: `legacy_required UNION graph_extra`; graph facts cannot remove a legacy
  obligation.
- G2: annotate, prioritize, or slice candidates; never classify safe.
- M1: unchanged in the first release. A later predicate-asymmetry generator must
  be separately named and retain may-semantics.
- M2: program facts are a separate axis family deduped by canonical obligation
  ID. Fact presence alone cannot mark methodology `EXAMINED`.
- Chain/composition: add pairs and source-bound slices. Semantic actor/enabler
  reasoning remains model plus independent verification.
- Static/model disagreement creates a mandatory review obligation.
- No path, zero facts, a dominating predicate, or successful tool exit may
  demote or refute a candidate.

## 6. Ecosystem rollout

### P0 — contract only

Define schema, receipt, trust, PhaseIO, snapshot, failure/debt, packaging, and
cross-platform determinism fixtures. No consumer behavior changes.

### P1 — EVM emit-only

Use pinned Slither APIs for:

- CFG and dominator facts;
- context-labelled may-dependencies;
- typed SlithIR operations;
- resolved/unresolved calls and sinks.

Label inheritance, modifier, alias, proxy, dynamic call, assembly, remapping,
via-IR, profile, and partial-build limitations.

### P2 — EVM additive consumers

Enable one consumer per measured release:

1. G2 fact-backed projection;
2. G1 union;
3. chain candidate slices;
4. M2 separate fact axis.

Leave M1 out or last.

### P3 — Go

Use a small custom `go/ssa` helper. Explicitly choose and label CHA, RTA, or VTA
with their roots and limitations. Do not make deprecated `go/pointer` or a
heavyweight Joern installation the initial dependency.

### P4 — Rust, Solana, Soroban

- Keep rust-analyzer/SCIP for references.
- Treat pinned MIR facts as experimental because rustc internals are unstable.
- Keep CodeQL Rust optional and license-aware.
- Solana needs account/PDA/signer/writable/owner/CPI/remaining-account semantics.
- Soroban needs authorization-tree, cross-contract client, storage-class,
  TTL/archive, SAC, and custom-auth semantics.

### P5 — Aptos and Sui

Use separate adapters and license review. Aptos and Sui stackless bytecode and
toolchains are not interchangeable. Preserve source maps, compiler/opcode
versions, resource/object ownership, signer/TxContext, abilities, generics,
native calls, upgrades, and unresolved debt. DAML remains no-op until a genuine
provider exists.

## 7. Required CPG fixtures

Cross-cutting:

- stale source/build/provider/config;
- partial compilation and multiple build profiles;
- malformed, duplicate, conflicting, and truncated facts;
- overload/same-name/case/path collisions;
- moved source at the same line;
- provider unknown/unavailable/failed;
- model tamper;
- unordered set and cross-process/platform normalization;
- zero rows versus no coverage;
- dependency/generated-source mismatch;
- exact resume and graph-on/graph-off incompatibility.

EVM:

- irrelevant dominating predicate;
- branch-local authorization;
- modifier and inherited predicates;
- sanitizer transforms;
- struct/field/storage aliases;
- internal/library/interface/high-level/low-level/delegate/create distinctions;
- ordinary parameter transfer;
- proxy and dynamic dispatch;
- assembly, remappings, via-IR, and profile variants.

Go:

- interface dispatch, reflection, unsafe, cgo/assembly, build tags, roots,
  generics, init, goroutines, and channels.

Rust/Solana/Soroban:

- proc macros, build scripts, cfg features, trait/dyn dispatch, unsafe/FFI,
  async, generated account constraints, PDA rules, account aliasing, CPI
  privileges, dynamic program IDs, nested auth, custom auth, storage/TTL.

Move:

- Aptos signer/global resources/multi-agent versus Sui owned/shared objects,
  TxContext and dynamic fields; abilities, visibility, generics, native calls,
  upgrades, source-map absence, and compiler/opcode versions.

## 8. Agent-count research verdict

Do not increase counts globally.

Controlled research reports:

- large gains on decomposable work but losses on sequential planning;
- substantial error amplification in independent-agent architectures;
- diminishing returns from homogeneous agents;
- benefits from different models, prompts, tools, and evidence channels;
- stronger frontier agents often saturating with fewer collaborators;
- communication and tool-coordination costs consuming fixed reasoning budgets.

For Plamen:

- recon, breadth lenses, component/seam sweeps, and independent chain pairs are
  decomposable;
- phase progression, inventory authority, dedup, disposition, verification
  judgments, severity, and report assembly are sequential or centrally joined;
- more report or judge agents are likely to increase fragmentation;
- verification scales by exact queue capacity, not voting.

## 9. Current count-policy gaps

- Recon concurrency is fixed at four.
- Breadth, rescan, and depth concurrency are fixed at three.
- Smart-contract breadth count originates in an LLM-written Markdown manifest.
- L1 breadth has hard-coded mode targets.
- Attention repair is one call capped at 32 items.
- Several exact worklists remain single-agent when denominators grow.
- Codex fanout and Claude fanout do not have proven identical scheduling
  semantics.
- The optional breadth-wave feature is off by default, SC-Thorough-only,
  hard-coded to two jobs and two waves, and stops on raw above-Info finding
  count. It rewards duplicates/false positives and is not an adaptive
  application controller.

## 10. Adaptive evidence-channel controller

Agent count becomes a consequence of an exact work denominator.

The versioned plan binds:

- source snapshot, methodology, backend, model, tools, graph treatment, phase,
  round, and predecessor digests;
- exact obligations: method steps, axis cells, components, relations, provider
  debt, candidate challenges, chain pairs, verifier items;
- state: uncovered, assigned, evidenced, disputed, explicit debt, or closed by
  independently authorized disposition;
- role and distinct evidence slice;
- stable channel ID derived from obligation set, evidence slice, role, source,
  methodology, graph treatment, and runtime policy;
- separate total-agent cap and maximum concurrency;
- minimum context/token floor;
- exact worker and deterministic join receipts;
- stop receipt retaining every uncovered/failed item as debt.

Candidate union remains monotonic. Worker `SAFE` never closes work. Negative
closure remains an independent-provider responsibility.

## 11. Phase policy

- Bake: parallel tools only.
- Recon: expand only for unresolved components or external dependencies.
- Instantiate: one compiler/authority.
- Breadth: primary adaptive target; assign uncovered component × evidence-lens
  cells.
- Rescan/per-contract: uncovered components, seams, siblings, and variants.
- Inventory: capacity-shard candidate IDs; deterministic merge.
- Semantic invariants: shard pass 1 by state/write clusters; pass 2 follows the
  exact pass-1 join.
- Depth: add channels only for unresolved obligations with different evidence
  slices.
- Attention repair: replace the 32-item call with stable small shards and exact
  tail reconciliation.
- Enumeration/axis/exploration/application skeptic: shard exact worklists and
  centrally join.
- Dedup: one central authority; agents propose relations only.
- RAG/external research: shard exact dependencies/candidates with cited join.
- Chain: parallel within a generation; generations remain sequential.
- Verification: dynamic queue roster; add premise-specific challenges only.
- Skeptic/severity: independent per-finding adjudication, not voting swarms.
- Report: body capacity shards only; index/disposition/dedup/assembly central.

## 12. Neutral experiment

Keep graph and attention factors separate:

| Arm | Program facts | Attention |
|---|---|---|
| G0A0 | Off/legacy | Current fixed roster |
| G1A0 | Typed sidecar | Current fixed roster |
| G0A1 | Off/legacy | Adaptive evidence channels |
| G1A1 | Typed sidecar | Adaptive evidence channels |

An increased homogeneous static count may be included as a diagnostic arm, not
as a preferred cutover.

Run two budget regimes:

1. matched total model/tool/token/time budget;
2. matched per-agent budget.

Ground truth remains grader-only. Control source snapshot, backend, model, tools,
prompts, and ordering.

Measure:

- methodology application completeness;
- unique confirmed root causes;
- found-then-lost and false-safe rates;
- verifier confirmation yield;
- fragmentation and duplicates;
- unsupported-negative reopen rate;
- severity and report signal;
- tokens/time/tool calls per unique confirmed root cause;
- channel overlap and evidence diversity.

Raw finding count is not a yield metric.

## 13. Adaptive-controller fixtures

- exact denominator = assignments + receipts + debt;
- stable IDs under reorder and resume;
- dependency-scoped invalidation;
- concurrency changes do not change total planned work;
- budget exhaustion emits exact visible debt;
- an uncovered high-priority item triggers expansion after zero findings;
- correlated duplicate channels do not count as diversity;
- worker `SAFE` cannot close;
- candidate union and aliases remain monotonic;
- duplicate finding volume cannot extend a run;
- missing graph providers emit debt, not clean coverage;
- more than 32 attention items shard without tail loss;
- crashes, retries, cancellation, and late writes cannot mint authority;
- no ground-truth identity/path reaches a worker.

## 14. Cutover

Cut over only if:

- no legacy obligation disappears;
- no graph-derived terminal negative/demotion exists;
- exact lifecycle identities reconcile;
- held-out root-cause recall is non-decreasing with uncertainty;
- verifier workload and false-positive costs remain bounded;
- adaptive expansion improves application/unique evidence rather than raw count;
- at least one graph-eligible held-out root cause is gained across a
  multi-ecosystem set;
- full fault/resume/backend/ecosystem evidence is green.

## 15. Primary sources

- [PR #21](https://github.com/PlamenTSV/plamen/pull/21)
- [Slither](https://github.com/crytic/slither)
- [SlithIR](https://github.com/crytic/slither/wiki/SlithIR)
- [Open CPG specification](https://cpg.joern.io/)
- [Joern frontends](https://docs.joern.io/frontends/)
- [LLMxCPG, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays)
- [Go SSA](https://pkg.go.dev/golang.org/x/tools/go/ssa)
- [Go CHA](https://pkg.go.dev/golang.org/x/tools/go/callgraph/cha)
- [Go RTA](https://pkg.go.dev/golang.org/x/tools/go/callgraph/rta)
- [Go VTA](https://pkg.go.dev/golang.org/x/tools/go/callgraph/vta)
- [Rust MIR](https://rustc-dev-guide.rust-lang.org/mir/index.html)
- [CodeQL Rust dataflow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-rust/)
- [Solana programs](https://solana.com/docs/core/programs)
- [Solana CPI](https://solana.com/docs/core/cpi)
- [Anchor account constraints](https://www.anchor-lang.com/docs/references/account-constraints)
- [Soroban authorization](https://developers.stellar.org/docs/build/guides/auth/contract-authorization)
- [Soroban storage](https://developers.stellar.org/docs/build/guides/storage/choosing-the-right-storage)
- [Agent-system scaling, Nature Machine Intelligence 2026](https://www.nature.com/articles/s42256-026-01268-y)
- [Google Research scaling summary](https://research.google/blog/towards-a-science-of-scaling-agent-systems-when-and-why-agent-systems-work/)
- [Agent scaling via diversity](https://arxiv.org/abs/2602.03794)
- [Multi-agent debate study, ICML 2024](https://proceedings.mlr.press/v235/smit24a.html)
- [Self-consistency](https://arxiv.org/abs/2203.11171)
