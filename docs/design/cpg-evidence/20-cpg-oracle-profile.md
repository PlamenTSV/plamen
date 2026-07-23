# CPG Query Oracle — Factual Profile

**Source:** `git clone https://github.com/mishoko/cpg-oracle` (succeeded; commit `2881ecb`, cloned 2026-07-23).
**Method:** Read every file in the repo; did NOT rely on the landing-page pitch. GitHub API queried for maturity signals.

> **One-line verdict:** This is NOT a tool you install or run. It is a ~90 KB **access kit** (one skill + four reference docs + a proprietary license) that teaches an AI agent to send Cypher to a **hosted, read-only, API-key-gated** graph that contains **exactly one pre-baked codebase — the redacted "dodo" cross-chain DEX**. There is no graph-building code, no server, and no way to point it at your own code. It answers *structural* graph questions and explicitly disclaims finding bugs or asserting exploitability.

---

## 0. Full file tree

```
.gitignore                                   (just .DS_Store)
LICENSE                                       ← proprietary evaluation license
README.md                                     ← connect + install kit
skills/cpg-query-oracle/
  SKILL.md                                    ← how the agent drives the oracle
  references/
    schema-key.md                             ← labels, edges, properties, enums, gotchas
    query-cookbook.md                         ← 30 verified queries
    demo-queries.md                            ← 7 worked questions
    dodo-findings.md                          ← structural evidence + flow diagrams
```
That is the **entire** repository. **No server code, no CPG file, no graph-building / ingestion / parser code ships.** README §"What you received" confirms: *"No server code and no CPG file ship here — you query a hosted endpoint."*

---

## 1. What it actually is (hosting & access model)

- **Hosted-only remote MCP server.** Endpoint: `https://solq.dev/api/v1/cpg/dodo/mcp`, Streamable HTTP transport.
- **API-key gated.** Access is a single `X-API-Key` header, issued out-of-band. Per README: *"An API key... is the whole of your access — it identifies you, scopes you to read-only, and can be revoked."*
- **Read-only by construction.** SKILL.md: *"There are no write, load, or admin tools... Writes, schema changes, procedure calls, and unbounded variable-length paths are rejected."*
- Install = point your MCP client at the endpoint:
  ```bash
  claude mcp add --transport http cpg-query-oracle \
    https://solq.dev/api/v1/cpg/dodo/mcp --header "X-API-Key: <your-key>"
  ```
- The kit's skill is optional convenience (teaches the agent the introspect→validate→run→cite loop).

### Can it analyze YOUR OWN code? — **NO.**
The graph is fixed and hosted. There is no upload, load, or build path in the kit or the tool set (the only tools are read/query). The endpoint path literally hardcodes `.../cpg/dodo/mcp`. The cookbook shows a generic `.../cpg/<graph>/mcp` URL shape, hinting the *provider* could host other graphs, but **you, the licensee, receive access to the dodo graph only.** To analyze your own codebase you would need the (proprietary, non-shipped) analysis pipeline that builds the CPG — which the license explicitly forbids reverse-engineering.

---

## 2. Coverage — baked for ONE codebase (DODO), not general-purpose

- Loaded graph = the **redacted "dodo" cross-chain DEX gateway suite**: `GatewayCrossChain`, `GatewayTransferNative`, `GatewaySend`, `GatewayEVM`, `GatewayZEVM`, plus the Zeta / Uniswap / OZ libraries they build on.
- Size: **12,694 nodes / 39,811 edges**, **59 contracts** in scope (gateway contracts carry the app logic; the rest are libraries/upgradeable scaffolding).
- The "security enrichment" (typed sinks, taint edges, guard dominance, storage flow) is **pre-computed and frozen** for this one graph. Counts are fixed (e.g. 763 CALL nodes, 488 FUNCTION nodes, 164 STATE_WRITE sinks, 140 EXTERNAL_CALL sinks).
- Every example query in all four docs targets dodo contract/function/variable names. The queries are reusable *patterns* ("swap the names"), but there is no other codebase to point them at.

---

## 3. The 7 read-only MCP tools

| Tool | What it does |
|---|---|
| `cpg_status` | Confirms a graph is loaded and reports its identity (contract count + names). **Call first, every session.** Every answer is scoped to this one graph. |
| `get_schema_catalog` | The live vocabulary: every node label, edge type, property key, and real enum value present in the graph. Declared single source of truth (trust it over any static doc). |
| `list_label_counts` | Node counts by label — what the graph is made of. |
| `describe_node {label}` | Real property keys (+ a sample) for one node label. |
| `describe_edge {type}` | Real property keys (+ a sample) for one edge type. |
| `validate_cypher {stmt}` | Dry-run lint: flags unknown label/edge/property (with nearest valid token) and confirms the statement is read-only. Kills the "mistyped filter silently returns zero" class before you run. |
| `cypher {stmt}` | Runs a read-only Cypher query and returns grounded rows. Rejects writes, procedure calls (`CALL`), schema changes, and unbounded variable-length paths (`[:TYPE*]` must be bounded, e.g. `[:CALLS*1..3]`). |

---

## 4. THE CPG SCHEMA (the substance)

A Code Property Graph fusing AST + control-flow + call graph + data-flow + a security-enrichment layer. Every node also carries a generic `:CPG` label and a `type` property mirroring its specific label, so `(n:CPG:FUNCTION)` ≡ `(n:CPG {type:'FUNCTION'})`.

### 4.1 Node labels (34 types) — verbatim from schema-key §2.1

| Type | Represents | Key properties |
|---|---|---|
| `EXPRESSION` | generic expression | `operator`, `expressionType` |
| `IDENTIFIER` | variable/function reference | `name`, `identifierName` |
| `VARIABLE` | declared variable | `name`, `scope`, `isStateVariable`, `typeName`, `storageLocation`, `isParameter`, `isImmutable`, `isConstant` |
| `CFG_BLOCK` | control-flow basic block | `blockType`, `functionId` |
| `STATEMENT` | statement (incl. `revert`/`emit`) | `contractName`, `statementType` |
| `CALL` | call expression | see §4.4 |
| `PARAMETER` | function parameter | flagged on VARIABLE via `isParameter=true` |
| `FUNCTION` | function definition | `name`, `signature`, `visibility`, `stateMutability`, `isConstructor`, `isReceive`, `isFallback`, `isCallbackFunction`, `callbackType` |
| `ASSIGNMENT` | assignment expression | `operator` |
| `LITERAL` | literal value | `literalValue`, `literalType` |
| `RETURN_PARAMETER` | return parameter | flagged on VARIABLE via `isReturnParameter=true` |
| `IMPORT` | import directive | `importPath` |
| `EVENT` | event definition | `eventName`, `eventArgCount`, `anonymous` |
| `ERROR` | custom error definition | `name` |
| `CONTRACT` | contract / interface / library | `name`, `isAbstract`, `isInterface`, `isLibrary`, `contractType`, `baseContractNames` |
| `YUL_BLOCK` | Yul (inline-assembly) block | `dialect`, `isYulBlock` |
| `PRAGMA` | pragma directive | `pragmaType`, `version` |
| `ASSEMBLY_BLOCK` | inline-assembly block | `isAssembly` |
| `STRUCT` | struct definition | `name`, `members` |
| `PHI_NODE` | SSA phi node | `ssaVariable` |
| `MODIFIER` | function modifier | `name`, `contractName`, `isAccessControl`, `isContractGated`, `isReentrancyGuard` |
| `FUNCTION_CALL_OPTIONS` | `{value:,gas:,salt:}` call options | `hasOptionValue`, `hasOptionGas`, `hasOptionSalt` |
| `CONDITIONAL` | conditional (ternary/if) | `hasConditional` |
| `LOOP` | loop header | `boundType`, `hasUserControlledBounds`, `maxIterations`, `guaranteedTermination` |
| `PROXY_PATTERN` | detected proxy pattern | `patternType`, `hasProxyPattern` |
| `USING_FOR` | `using … for …` directive | `libraryName` |
| `ENUM_VALUE` | enum member | `enumIndex`, `isEnumValue` |
| `UNCHECKED_BLOCK` | `unchecked { … }` block | `isUnchecked` |
| `TRY_CATCH_CLAUSE` | try/catch clause | `clauseType`, `catchType` |
| `ENUM` | enum definition | `name`, `values` |

(Also referenced with counts in cookbook Q1: `EXPRESSION` 2295, `CALL` 763, `FUNCTION` 488, `MODIFIER` 14 — 30 labels total on the dodo graph.)

### 4.2 Edge / relationship types (30) — verbatim from schema-key §2.2

| Edge | Direction | Meaning |
|---|---|---|
| `CONTAINS` | parent → child | AST/scope containment (`CONTAINS*` = everything inside X; bound the depth) |
| `TAINT` | source → sink | Data-flow path carrying untrusted data. Carries `taintType`, `confidence`, `bidirectionalConfirmed`, `vulnerabilityType` |
| `DATA_FLOW` | node → node | Value dependency; `flowType='ARG_TO_PARAM'` links call arg → callee param (`argumentIndex`) |
| `READS` | node → variable | Node reads the variable |
| `CONTROL_FLOW` | block → block | Execution order between CFG blocks |
| `DOMINATES` | block → block | `A DOMINATES B` ⇒ every path to B passes through A (use `DOMINATES*1..N`) |
| `POST_DOMINATES` | block → block | `A POST_DOMINATES B` ⇒ every path from B reaches A |
| `PARAMETER` | function → parameter | Declared parameters of a function |
| `RETURN_VALUE` | call → node | Value produced by a call |
| `SINK_CHAIN` | sink → sink | Two sinks sharing taint sources; `category`, `chainType`, `sharedTaintSources` |
| `READS_AGG` | callable → variable | (FUNCTION\|MODIFIER) reads this variable somewhere |
| `CALLS` | caller → callee | Resolved call graph (authoritative — prefer over name matching) |
| `STORAGE_FLOW` | writer → reader | State var written in one place read in another, incl. cross-contract (§4.6) |
| `RETURN` | function → node | Links function to its return construct |
| `SSA_DEF` | node → node | SSA definition edge |
| `WRITES` | node → variable | Node writes the variable; carries `writeType` |
| `MODIFIES` | function → modifier | Modifiers applied to a function |
| `WRITES_AGG` | callable → variable | (FUNCTION\|MODIFIER) writes this variable somewhere |
| `NAMED_ARGUMENT` | call → argument | Named call arguments |
| `SSA_USE` | node → node | SSA use edge |
| `INHERITS` | contract → parent | Inheritance (C3-linearized) |
| `DEPENDS_ON` | node → dependency | Declared/resolved dependency |
| `TUPLE_UNPACK` | tuple → element | Destructuring of a tuple assignment |
| `LOOP_BODY` | loop → body | Loop header to its body |
| `IMPLEMENTS` | contract → interface | Interface implementation |
| `DEFINES_LOOP` | node → loop | Construct that defines a loop |

### 4.3 Security enrichment — the differentiating layer

**On CALL nodes:** `isExternal`, `isExternalCallTarget`, `isLowLevelCall`/`isLowLevel`, `isDelegateCall`, `isStaticCall`, `isNarrowingCast`, `isInterfaceCall`, `isLibraryCall`, `memberName` (invoked method, e.g. `transfer`/`safeTransferFrom`/`call`), `resolvedTargetId` (compiler-resolved FUNCTION id), `isTaintSink`+`sinkType`, `isTaintSource`+`taintSource`.

**On MODIFIER nodes:** `isAccessControl` (gates on `msg.sender`/`tx.origin`), `isContractGated` (compares `msg.sender` to a contract-typed var — a bridge/gateway relay gate), `isReentrancyGuard`.

**On VARIABLE / write-target nodes:** `validationDominates` (a require/assert/revert dominates the write in the CFG), `validationScore` (strength), `validationBypassable` (dominating validation bypassable on some path).

### 4.4 Enum reference (`get_schema_catalog`) — schema-key §2.6

| Enum | Values |
|---|---|
| `sinkType` (8) | `EMIT_EVENT`, `EXTERNAL_CALL`, `EXTERNAL_CALL_TARGET`, `MEMORY_OFFSET_COMPUTED`, `NARROWING_CAST`, `REVERT`, `SELECTOR_CONTROLLED_CALL`, `STATE_WRITE` |
| `TAINT.taintType` | `direct_flow`, `backward_flow`, `loop_carried`, `external_call_target`, `advanced_multi_step` |
| `WRITES.writeType` | `assignment`, `unary_increment`, `unary_decrement`, `unary_delete` |
| `STORAGE_FLOW.flowType` | `WRITE_READ`, `WRITE_WRITE` |
| `DATA_FLOW.flowType` | `ARG_TO_PARAM`, `DEF_USE`, `USE`, `DEF`, `MAPPING_READ`, `MAPPING_WRITE`, `ARRAY_READ`, `ARRAY_WRITE`, `STRUCT_FIELD_READ`, `STRUCT_FIELD_WRITE`, `STRUCT_CONSTRUCTOR_ARG`, `CALLDATA_TO_STORAGE`, `CAST_TO_MEMBER_ACCESS`, `EXPR_CHAIN`, `INLINE_CALL_RETURN`, `TERNARY_BRANCH`, `TERNARY_INIT`, `YUL_*` (7 Yul flow kinds) |
| `SINK_CHAIN.category` | `CROSS_FUNC_CEI`, `CROSS_FUNC_STATE_CHAIN`, `ORACLE_TRUST`, `SEQUENTIAL_EXTERNAL` |
| `FUNCTION.visibility` | `external`, `internal`, `private`, `public` |
| `FUNCTION.stateMutability` | `pure`, `view`, `payable`, `nonpayable` |
| `VARIABLE.scope` | `STATE`, `LOCAL`, `PARAMETER`, `RETURN` (+`yul`, `yul_local`) |
| `CFG_BLOCK.blockType` | `ENTRY`, `EXIT`, `BASIC`, `CONDITIONAL`, `LOOP`, `TRY`, `CATCH` |
| `STATEMENT.statementType` | `Block`, `ExpressionStatement`, `IfStatement`, `ForStatement`, `Return`, `RevertStatement`, `EmitStatement`, `TryStatement`, `VariableDeclarationStatement`, `PlaceholderStatement` |
| `CONTRACT.contractType` | `contract`, `interface`, `library` |
| `callbackType` | `ether_receiver` |
| `TAINT.vulnerabilityType` | `ARBITRARY_EXTERNAL_CALL`, `DIRECT_INJECTION`, `LOOP_ACCUMULATION`, `STATE_MANIPULATION`, `UNSAFE_EXTERNAL_CALL`, `data_flow`, `data_flow_vulnerability`, `reentrancy` |

**taintSource origin kinds:** `msg_sender`, `msg_value`, `msg_data`, `msg_context`, `block_timestamp`, `external_call`, `external_call_return`, `external_data`, `catch_clause_data`, `user_input`, `string_literal`, `backward_propagated`, `propagated`, `unknown`, plus an open `struct_field:<path>` namespace (e.g. `struct_field:params.fromToken`, `struct_field:decoded.targetZRC20`).

### 4.5 Taint edge metadata (§2.4)
`confidence` (0–1, filter ≥0.7 for high-confidence), `taintType`, `bidirectionalConfirmed` (strongest flows — covers most edges so used to rank not filter), `bidirectionalTaint`, `meetingPoint` (node id where forward+backward taint met), `vulnerabilityType`.

### 4.6 Storage flow (§2.5)
`(writer)-[:STORAGE_FLOW {storageVariable, flowType, sourceContract, targetContract, sourceFunction, targetFunction, confidence, taintVerified}]->(reader)`. `sourceContract <> targetContract` = the **cross-contract** case a single-contract analysis misses entirely.

### 4.7 Modeling gotchas (material for anyone querying)
- External call = `call.isExternal`; call kind = `call.memberName`; CALL node names carry a `call_` prefix.
- **SSA copies** (`node_XX_ssa`) hold the moved `WRITES`/`DATA_FLOW` edges (`ssaRenamed=true`, `isTaintSink=false`) — select originals vs copies deliberately.
- **Primary `(f:FUNCTION)-[:WRITES]->(v)` returns 0 by design** — primary WRITES originate from ASSIGNMENT/EXPRESSION/CALL nodes; use `WRITES_AGG`/`READS_AGG` for "does callable F touch var X".
- Public state-var getters have no FunctionDefinition — modeled as a synthetic `READS` straight to the state VARIABLE.
- `REVERT` and `EMIT_EVENT` sinks live on `STATEMENT` nodes (not CALL) and `EMIT_EVENT`/`struct_field:*` nodes have null `contractName` — attribute via `n.containingFunction = fn.id`.
- Absent boolean/null ≠ verified `false`.

---

## 5. Query capabilities demonstrated (representative queries VERBATIM)

The kit ships 30 verified cookbook queries + 7 worked demos + 2 finding walk-throughs — all claimed run live against `solq.dev/api/v1/cpg/dodo/mcp` with row counts recorded.

**Capabilities shown:** typed sink inventory; taint source inventory (incl. field-level struct taint); bounded call-graph reach; guard/dominance proofs (CFG `DOMINATES`); `validationDominates` write-guard triage; access-control surface mapping; writer/reader asymmetry per variable; cross-contract taint & storage flow; CEI-violation flag; narrowing-cast/selector-controlled-call/low-level-call inventories; taint ranking by `confidence`/`bidirectionalConfirmed`; sink chains.

**Example A — bidirectional-confirmed taint into an external-call sink (the marketed "differentiator", demo-queries §2):**
```cypher
MATCH (src)-[r:TAINT]->(sink)
WHERE r.bidirectionalConfirmed = true
  AND src.isTaintSource = true
  AND sink.isTaintSink = true
  AND sink.sinkType = 'EXTERNAL_CALL'
MATCH (f:FUNCTION {id: sink.containingFunction})
WITH sink.contractName AS contract, f.name AS fn, sink.name AS externalCall,
     sink.line AS line, src.taintSource AS source,
     round(r.confidence, 2) AS confidence, r.vulnerabilityType AS vulnerabilityType
RETURN DISTINCT contract, fn, externalCall, line, source, confidence, vulnerabilityType
ORDER BY vulnerabilityType, confidence DESC, contract
LIMIT 6;
```
Returned rows e.g. `GatewayEVM._executeArbitraryCall / call_call @420 / user_input / 0.9 / ARBITRARY_EXTERNAL_CALL`.

**Example B — CFG dominance guard proof (cookbook Q29):**
```cypher
MATCH (sink:CALL {isTaintSink:true, contractName:'GatewayCrossChain'})
MATCH (sb:CFG_BLOCK)-[:CONTAINS*1..4]->(sink)
MATCH (g:CFG_BLOCK)-[:DOMINATES*1..10]->(sb)
WHERE g.blockType = 'CONDITIONAL'
RETURN sink.functionName AS inFunction, sink.name AS sinkCall, sink.sinkType AS sinkType,
       sink.line AS line, count(DISTINCT g) AS dominatingGuards
ORDER BY dominatingGuards DESC
LIMIT 12;
```
> verified: 10 rows (e.g. `safeTransferETH / call_safeTransferETH @164 / 1 dominating conditional guard`).

**Example C — cross-contract taint, source in A → sink in B (cookbook Q26):**
```cypher
MATCH (src)-[t:TAINT]->(sink:CALL {isTaintSink:true})
WHERE src.contractName IS NOT NULL AND sink.contractName IS NOT NULL
  AND src.contractName <> sink.contractName
RETURN src.contractName AS sourceContract, sink.contractName AS sinkContract,
       sink.sinkType AS sinkType, count(*) AS cnt
ORDER BY cnt DESC
LIMIT 15;
```
> verified: 15 rows (e.g. `GatewaySend → GatewayCrossChain / EXTERNAL_CALL / 736 flows`).

**Example D — writer/reader access-control asymmetry (demo-queries §4):**
```cypher
MATCH (w)-[:WRITES]->(v:VARIABLE {name: 'refundInfos', contractName: 'GatewayCrossChain'})
MATCH (wf:FUNCTION {id: w.containingFunction})
OPTIONAL MATCH (wf)-[:MODIFIES]->(m:MODIFIER)
WITH DISTINCT wf.name AS writer,
     collect(DISTINCT m.name) AS modifiers,
     max(CASE WHEN m.isAccessControl THEN 1 ELSE 0 END) AS ac
RETURN writer, modifiers, (ac = 1) AS accessControlled
ORDER BY accessControlled, writer;
```
> Returns `claimRefund [] false` vs `onAbort/onRevert [onlyGateway] true` — a structural asymmetry (one ungated writer) offered as a human lead.

---

## 6. Explicit limits — what it CANNOT do (stated by the vendor, not inferred)

- **Not a bug-finder.** README/SKILL/schema-key all repeat: *"It answers structural questions — it is not a bug-finder... A structural path is a lead for a human, never a confirmed exploit. It never asserts exploitability."* LICENSE §6: *"it does not identify vulnerabilities, assert exploitability, or guarantee the completeness or correctness of any result."*
- **Cannot analyze your code** — only the pre-loaded dodo graph (see §1). No load/build/upload path exists.
- **Read-only.** No write/load/admin tools; `CALL` procedures, schema changes, unbounded `*` paths rejected.
- **No semantic reasoning.** dodo-findings.md concedes wrong-formula / fee / economic bugs "a structural graph cannot prove" — it only hands over a review surface.
- **Semi-manual UX** — mistyped property → silent false zero; the docs devote whole sections to distinguishing a "failed query" from a "verified zero."

---

## 7. Licensing / hosting model

**Proprietary Evaluation License** (`LICENSE`, "Copyright (c) 2026 the Provider"):
- **Evaluation use only** — no production, no third-party benefit, no commercial use except deciding whether to license.
- **30-day term** from first access; provider may suspend/revoke anytime, with or without cause or notice.
- **Read-only, non-transferable, non-sublicensable, revocable.** API key is personal; sharing it is a breach.
- **No reverse-engineering** of the service/pipeline; **no building/benchmarking a competing tool**; **no redistributing** the Materials, schema, or "any substantial portion of the results, schema, or enrichment values."
- **Confidentiality** imposed on the Materials, schema, and enrichment values ("output of a proprietary analysis pipeline").
- **"AS IS", no warranty; total liability capped at USD $100.**
- Note: the license's confidentiality/no-redistribution terms sit oddly against the schema and example rows being published in a **public** GitHub repo — the kit contents are effectively already public despite the "confidential — provided for evaluation" banners.

---

## 8. Maturity signals (GitHub API + git log, fetched 2026-07-23)

| Signal | Value |
|---|---|
| Repo | `mishoko/cpg-oracle` (public) |
| Created / last push | 2026-07-22 (both) — **~1 day old at profiling** |
| Commits | **2** (both 2026-07-22, by `mishoko <cc.bankroll320@8alias.com>`) |
| Commit messages | "CPG Query Oracle access kit: skill + references + license"; "Validate schema-key against live graph + re-capture demo rows" |
| Releases / tags | **0** |
| Stars / forks / watchers | **0 / 0 / 0** |
| Open issues | 0 |
| Repo size | 90 KB (docs only) |
| Description / README topics | none set on GitHub |
| Owner | user `mishoko`, account created 2022-03-09, 59 public repos, no display name/bio. Commit email `cc.bankroll320@8alias.com` (alias-style address). |

**Read:** brand-new, single-author, zero-traction, docs-only kit fronting a closed hosted service. No independent adoption, no version history, no issue tracker activity, no verifiable provider identity. All "verified live" row counts are self-reported in the docs — not independently reproducible without a key (and only against dodo).

---

## 9. Bottom line for adoption

- **What you get:** an agent skill + Cypher cookbook + a genuinely rich, well-documented CPG **schema** (34 node labels, 30 edge types, a real security-enrichment layer: typed taint sources/sinks, CFG dominance guard proofs, cross-contract storage flow, field-sensitive struct taint, SSA). The schema design is the most valuable, transferable artifact here.
- **What you do NOT get:** the analysis pipeline, any server/graph-building code, or the ability to run this on your own codebase. You get read-only query access to **one frozen, redacted demo graph (dodo)** under a 30-day, revocable, eval-only license with a $100 liability cap.
- **Fit:** useful only to *evaluate the query experience* against a canned example. It is not a deployable audit tool, not a bug-finder (vendor-disclaimed), and cannot touch your code. Treat any "finding" as an unverified structural lead requiring full human confirmation.
```