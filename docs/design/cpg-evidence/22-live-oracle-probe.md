# Live Oracle Evidence — CPG MCP Server (`dodo`)

**Captured**: 2026-07-23 (server date header `Thu, 23 Jul 2026 08:22:04 GMT`)
**Endpoint**: `https://solq.dev/api/v1/cpg/dodo/mcp` (Streamable-HTTP MCP)
**Auth**: `X-API-Key: cpgk_live_***` (redacted)
**Transport**: HTTP/2, `content-type: text/event-stream` (SSE `data:` frames), Express behind Cloudflare/Caddy.

---

## 1. Handshake — SUCCESS

`POST initialize` → `HTTP/2 200`, session issued via header:

```
mcp-session-id: ada4fd76-bf34-4bf9-9d9b-1415853862d6
x-ratelimit-limit: 100000   x-ratelimit-remaining: 99999
```

SSE result frame:

```json
{"result":{"protocolVersion":"2025-06-18",
 "capabilities":{"resources":{"listChanged":true},"tools":{"listChanged":true}},
 "serverInfo":{"name":"cpg-oracle","version":"1.0.0"},
 "instructions":"Structural CPG query oracle for a Solidity codebase. Call cpg_status first; answer only from returned rows; treat a non-EMPTY_VERIFIED zero as a failed query, not \"absent\". This is an ORACLE (it verifies structural facts), not a bug-finder."}}
```

`notifications/initialized` → `HTTP 202` (accepted). Session is fully established.

---

## 2. tools/list — 7 tools confirmed

| # | Tool | Input schema (required) | Purpose |
|---|------|-------------------------|---------|
| 1 | `cpg_status` | `{}` | Which CPG is loaded: loaded flag, contract count, node count, contract list (identity). "Call this first." |
| 2 | `cypher` | `{ statement: string, params?: object }` | Read-only Cypher over the CPG. **Arg key is `statement`, NOT `query`.** Typed `zeroReason` (EMPTY_VERIFIED vs QUERY_ERROR). Writes / `dbms.*` / `apoc` / `gds` / unbounded `[*]` rejected. Description embeds the full Neo4j schema vocabulary. |
| 3 | `get_schema_catalog` | `{}` | Live-derived vocabulary: node labels (+counts), edge types (+counts), all property keys, enum-like value sets, semantic notes. |
| 4 | `validate_cypher` | `{ statement: string }` | Dry-run lint of a query against the live graph (read-only-safe? labels/props exist?) without executing. |
| 5 | `describe_node` | `{ label: string }` | Ground-truth property keys + sample for a node label. |
| 6 | `describe_edge` | `{ type: string }` | Ground-truth property keys + sample for an edge type. |
| 7 | `list_label_counts` | `{}` | Histogram: nodes per label, edges per type. |

All 7 carry `"execution":{"taskSupport":"forbidden"}`.

---

## 3. Tool-call outputs (REAL rows)

### 3.1 `cpg_status` — loaded, 59 contracts, 12,694 nodes

```json
{"loaded": true, "contractCount": 59, "nodeCount": 12694,
 "identity": "59 contracts: Abortable, AccessControlUpgradeable, AccountEncoder, Address, BytesHelperLib, Callable, ContextUpgradeable, ERC165Upgradeable, …"}
```

Contract list (59) includes the audit targets: `GatewayEVM`, `GatewayZEVM`, `GatewayCrossChain`, `GatewayTransferNative`, `GatewaySend`, `ZetaConnectorBase`, `AccountEncoder`, `SwapDataHelperLib`, `TransferHelper`, `IDODORouteProxy`, plus OZ-upgradeable and Uniswap/ZRC20/WETH9 interfaces. (This is a ZetaChain cross-chain gateway + DODO route-proxy codebase.)

### 3.2 `list_label_counts` — graph shape (selected)

Nodes: EXPRESSION 2295, IDENTIFIER 2231, VARIABLE 1814, CFG_BLOCK 1621, STATEMENT 1459, CALL 763, PARAMETER 516, FUNCTION 488, ASSIGNMENT 438, … CONTRACT 59, MODIFIER 14, LOOP 5.
Edges: CONTAINS 16350, TAINT 6365, DATA_FLOW 5429, READS 2235, CONTROL_FLOW 1305, DOMINATES 1133, POST_DOMINATES 1133, SINK_CHAIN 845, CALLS 792, STORAGE_FLOW 365, WRITES 158, MODIFIES 116, INHERITS 54.

### 3.3 `get_schema_catalog` — real vocabulary

Same label/edge histogram as above, PLUS ~300 property keys and enum value sets. Key enums (live-derived):
- `sinkType`: EMIT_EVENT, EXTERNAL_CALL, EXTERNAL_CALL_TARGET, MEMORY_OFFSET_COMPUTED, NARROWING_CAST, REVERT, SELECTOR_CONTROLLED_CALL, STATE_WRITE.
- `TAINT.taintType`: advanced_multi_step, backward_flow, direct_flow, external_call_target, loop_carried.
- `STORAGE_FLOW.flowType`: WRITE_READ, WRITE_WRITE.
- `SINK_CHAIN.category`: CROSS_FUNC_CEI, CROSS_FUNC_STATE_CHAIN, ORACLE_TRUST, SEQUENTIAL_EXTERNAL.
- `taintSource` includes protocol-specific `struct_field:*` origins (e.g. `struct_field:params.fromTokenAmount`, `struct_field:decoded.targetZRC20`, `struct_field:revertOptions.callOnRevert`).
- Semantic notes warn of SSA false-zeros, `*_AGG` callable-level edges, `isExternal` (NOT `isExternalCall`), and Neo4j syntax gotchas.

### 3.4 `cypher` (i) — unguarded external-entry state writes — 10 REAL rows

Query ran clean (`ok:true, empty:false, durationMs:789`). Rows:

| contract | function | state var | line |
|----------|----------|-----------|------|
| GatewayEVM | setCustody | custody | 346 |
| GatewayEVM | setConnector | zetaConnector | 356 |
| GatewayZEVM | initialize | zetaToken | 70 |
| GatewayCrossChain | setBot | bots | 158 |
| GatewayTransferNative | setBot | bots | 163 |
| GatewayEVM | initialize | tssAddress | 69 |
| GatewayEVM | initialize | zetaToken | 72 |
| GatewayEVM | updateTSSAddress | tssAddress | 89 |
| ZetaConnectorBase | initialize | gateway | 72 |
| ZetaConnectorBase | initialize | zetaToken | 73 |

(These are `validationDominates=false` writes; most are behind `onlyOwner`/initializer AC that the property does not model — the oracle flags candidates, it does not adjudicate. Consistent with the tool's "oracle, not bug-finder" self-description.)

### 3.5 `cypher` (ii) — high-confidence taint → EXTERNAL_CALL sinks — 10 REAL rows

Query ran clean (`ok:true, empty:false, durationMs:242`). All 10 rows:
`sink.contractName = TransferHelper`, `src.taintSource = user_input`, `t.confidence = 0.9`, `t.vulnerabilityType = ARBITRARY_EXTERNAL_CALL`, at `sink.line ∈ {8, 14, 20}` (the low-level `.call`/transfer helpers). Multiple TAINT edges converge on the same sink lines (expected: `.call` emits EXTERNAL_CALL + EXTERNAL_CALL_TARGET, and several sources reach each).

### 3.6 `cypher` (iii) — cross-contract storage flow — 10 REAL rows

Query ran clean (`ok:true, empty:false, durationMs:128`). Distinct flows:

| source → target | storageVariable | flowType | confidence |
|-----------------|-----------------|----------|-----------|
| GatewayCrossChain → GatewayTransferNative | refundInfos | WRITE_READ | 0.95 |
| GatewayEVM → AccessControlUpgradeable | _getAccessControlStorage | WRITE_READ | 0.60 |
| AccessControlUpgradeable → GatewayEVM | _getAccessControlStorage | WRITE_READ | 0.60 |

The `GatewayCrossChain → GatewayTransferNative` `refundInfos` WRITE_READ at 0.95 confidence is the standout cross-contract storage dependency.

---

## 4. Verdict

**The live graph CORROBORATES the schema-key doc.** Auth succeeded, a session was issued, all 7 documented tools are present with the documented schemas, and — contrary to the prior "degraded / 0 query workers" observation — **`cypher` is fully operational**: all three probe queries executed against the real Neo4j-backed CPG (59 contracts, 12,694 nodes, 6,365 TAINT edges) and returned concrete, citeable rows (sub-800ms each). The loaded codebase is a ZetaChain cross-chain gateway + DODO route-proxy. No rows were fabricated; every row above is the server's actual output. The one nuance vs. the doc: the `cypher` argument key is **`statement`** (the task's guessed `query` would have failed) — confirmed from the live `tools/list` input schema.
