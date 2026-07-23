# CPG Oracle (solq.dev / mishoko/cpg-oracle) — Hands-On Access Probe

**Date:** 2026-07-23
**Target:** MCP-over-HTTP endpoint `https://solq.dev/api/v1/cpg/dodo/mcp` (X-API-Key auth)
**Repo:** https://github.com/mishoko/cpg-oracle (the "access kit")
**Goal:** Determine how far one can exercise the live service *without a paid/issued key*, and document exactly what a genuine evaluation would require. All command output below is real (captured live), not fabricated.

---

## TL;DR

- The MCP endpoint is **hard-gated by `X-API-Key`**. Without a valid key you get `HTTP 401` and nothing more — no tool list, no schema, no `cpg_status`. **You cannot exercise a single oracle tool without an issued key.**
- **However, ~90% of what the oracle would *show* you is already in the public GitHub kit**: the full query vocabulary (schema-key), 30 copy-paste Cypher queries, and — critically — **7 demo questions with their live result rows already captured**, plus structural evidence for 2 real "dodo" findings. You can read the answers statically without ever connecting.
- `solq.dev` is a broader web platform ("SolQ") with **open self-service registration** and a separate "analysis upload" feature, but that JWT web account is **not** the same credential as the out-of-band CPG-oracle `X-API-Key`.
- **Zero public web footprint**: no writeups, no announcement, no benchmark, no pricing. Repo is 2 days old, 0 stars, 2 commits, author on an alias email. Access is invite/out-of-band; price undisclosed ("provided for evaluation").
- **Service is currently degraded**: `/health` reports the query **worker pool is down (0 workers)**. Even with a key, live query execution may not currently work.

---

## (a) The auth / access reality

### MCP `initialize`, NO API key → 401

```
$ curl -sS -i -X POST https://solq.dev/api/v1/cpg/dodo/mcp \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}'

HTTP/2 401
content-type: application/json; charset=utf-8
access-control-allow-headers: Content-Type, Authorization, X-API-Key
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-origin: https://solq.dev
content-security-policy: default-src 'self'; ... connect-src 'self' https://api.solq.dev wss://api.solq.dev;
via: 1.1 Caddy
server: cloudflare

{"success":false,"error":{"code":"AUTHENTICATION_ERROR","message":"Missing API key"}}
```

### With dummy key `X-API-Key: test` → 401 (distinct message)

```
# GET fast-path (6.6s):
$ curl ... -X GET https://solq.dev/api/v1/cpg/dodo -H "X-API-Key: test"
HTTP 401  {"success":false,"error":{"code":"AUTHENTICATION_ERROR","message":"Invalid API key"}}

# POST /mcp with X-API-Key: test → HTTP 401 (1.1s)
# POST /mcp with Authorization: Bearer test → HTTP 401  (X-API-Key is the accepted header, not Bearer)
```

**Precise auth behavior:**
- **No key** → 401 `AUTHENTICATION_ERROR / "Missing API key"`.
- **Bad key** → 401 `AUTHENTICATION_ERROR / "Invalid API key"` (the server distinguishes absent vs. wrong).
- Accepted auth header is **`X-API-Key`** (a `Authorization: Bearer` value is not honored for this route).
- CORS is locked to origin `https://solq.dev`; API host is `api.solq.dev`. Fronted by **Cloudflare → Caddy**, Express-style JSON error envelope with Zod validation. HSTS, CSP, nosniff, frame-deny all set.
- One transient 30s timeout was observed on the first dummy-key POST; immediate retries returned a clean 401, so that was network noise, not an auth path.

### Service health (public, no key) — currently DEGRADED

```
$ curl -sS https://solq.dev/health
{"status":"degraded", ...
 "checks":{
   "postgres":{"status":"up"}, "neo4j":{"status":"up"}, "redis":{"status":"up"},
   "worker":{"status":"down","message":"No workers available",
             "details":{"totalWorkers":0,"healthyWorkers":0,"busyWorkers":0,"queueDepth":0}}}}
```

Postgres / **Neo4j** (the graph DB) / Redis are up, but the **worker pool is empty**. The synchronous `cypher` tool may still run against Neo4j directly, but any queued/async job path (likely `analysis/upload`) would stall. A real evaluator must `cpg_status` first to confirm queries actually execute.

**Access model (from README + LICENSE):** the `X-API-Key` is *issued out-of-band*, identifies you, scopes you read-only, and is revocable. Governed by a **Proprietary Evaluation License**: internal-evaluation-only; no production use; no benchmarking against it or using its rows/schema to train/build a competing tool; no redistribution of schema/results; no key sharing.

---

## (b) What is inspectable WITHOUT a key

### 1. The GitHub "access kit" (fully public) — this is the big one

`git clone https://github.com/mishoko/cpg-oracle` gives the entire client-side kit. No server code, no `.cpg` file, but:

| File | Lines | Content |
|---|---|---|
| `README.md` | — | connect/install instructions, endpoint, tool list, kit map |
| `LICENSE` | — | proprietary evaluation license (full restrictions) |
| `skills/cpg-query-oracle/SKILL.md` | — | how an agent drives the oracle (introspect→validate→run→cite) |
| `references/schema-key.md` | 405 | **full live query vocabulary**: labels, edges, properties, enum values, engine gotchas |
| `references/query-cookbook.md` | 482 | **30 verified Cypher queries** to copy/adapt |
| `references/demo-queries.md` | 280 | **7 worked questions WITH their live result rows already captured** |
| `references/dodo-findings.md` | 174 | structural evidence + flow diagrams for 2 real dodo findings |

**Consequence:** you can read what the oracle returns *without connecting*. e.g. `demo-queries.md` §2 already shows the marquee "bidirectionally-confirmed taint into external-call sinks" result (GatewayEVM `_executeArbitraryCall` call_call @L420, conf 0.9, `ARBITRARY_EXTERNAL_CALL`, etc.), and `dodo-findings.md` shows the `refundInfos` unguarded-write lead (`validationDominates=false` @L539/L629) and the `withdrawToNativeChain` `call_transferFrom @536` unguarded-external-call lead. These are the deliverables — visible statically.

**The 7 tools** (all read-only, per README): `cpg_status`, `get_schema_catalog`, `list_label_counts`, `describe_node`, `describe_edge`, `validate_cypher`, `cypher`. No write/load/admin tools.

**The loaded graph:** redacted **"dodo"** cross-chain DEX gateway suite — `GatewayCrossChain`, `GatewayTransferNative`, `GatewaySend` + Zeta/Uniswap/OZ libs. **12,694 nodes / 39,811 edges.**

**Repo provenance:** 2 commits, both **2026-07-22**, author `mishoko <cc.bankroll320@8alias.com>` (alias email), 0 stars, 0 forks, no topics. i.e. brand-new, unpublicized.

### 2. Public (keyless) endpoints on solq.dev

The site is a **Vite SPA** ("frontend"); `/`, `/docs`, `/openapi.json` all return the same SPA shell (no real OpenAPI is exposed). Real public API surface found:

- `GET /health` → degraded status (above).
- `GET /api/v1/queries/categories` → **200, public** — a separate "known-vuln query library" catalog, NOT the CPG oracle:
  ```
  {"success":true,"data":[
    {"category":"reentrancy","count":10},{"category":"data-structures-misuse","count":3},
    {"category":"logic-error","count":3},{"category":"access-control","count":2},
    {"category":"call-options","count":2},{"category":"delegate-call","count":2},
    {"category":"ssa-analysis","count":2}]}
  ```
- Everything under `/api/v1/cpg/dodo*` and `/api/v1/auth/me` → 401 (gated).
- `/api/v1`, `/api/v1/auth/quota`, `/api/v1/openapi.json` → 404.

### 3. Frontend-referenced routes (from the compiled JS bundle)

`/api/v1/auth/{register,login,logout,me,refresh}`, `/api/v1/analysis/{upload,history}`, `/api/v1/admin/{users,stats/system}`, `/api/v1/queries/{categories,tags,stats}`. So SolQ is a full app with **registration, JWT auth, quota, an "analysis upload" pipeline, and an admin surface** — a broader product than the single dodo CPG oracle.

**Self-signup appears OPEN** (I did *not* complete a registration):
```
$ curl -X POST https://solq.dev/api/v1/auth/register -d '{"email":"probe@example.com","password":"x"}'
HTTP 400  VALIDATION_ERROR: "Password must be at least 8 characters" (+ regex rule)
```
The endpoint validated and rejected a weak password rather than refusing registration — i.e. a conforming payload would likely create a web account. **But** that yields a JWT web-app login, which is *not* the out-of-band `X-API-Key` that unlocks the `dodo` MCP graph. The two credentials are separate systems.

---

## (c) What a genuine evaluation would require

1. **Obtain an `X-API-Key` out-of-band from the provider.** There is **no public "request key"/"buy" button** anywhere on solq.dev or the repo. The README states the key is "sent to you out-of-band." Realistic contact vectors: the repo author (`cc.bankroll320@8alias.com`, an alias), or the "Contact"/"Sign up"/`mailto:` links in the SPA. This is effectively **invite-gated**.
2. **Point an MCP client at the endpoint:**
   ```bash
   claude mcp add --transport http cpg-query-oracle \
     https://solq.dev/api/v1/cpg/dodo/mcp --header "X-API-Key: <your-key>"
   ```
   (or the equivalent `.mcp.json` http entry).
3. **Scope is a single redacted graph.** You get exactly one loaded CPG — the "dodo" gateway suite — read-only. Via MCP there is **no way to load your own Solidity** into the CPG; ingesting new code is the separate, quota-gated `analysis/upload` web feature, not part of the dodo MCP key.
4. **Confirm liveness before trusting results.** Run `cpg_status` first. Given `/health` shows the worker pool down, an evaluator must verify `cypher` actually returns rows and isn't silently degraded.
5. **Stay inside license limits.** Evaluation-only; you may not benchmark it publicly, publish its rows/schema, or use outputs to build a competing analyzer. That directly constrains how a comparative security-tool eval could be reported.
6. **Interpret correctly.** By explicit design the oracle answers **structural** questions and returns **leads, never confirmed exploits** — it never asserts exploitability. Any eval that scores it as a "bug finder" would be measuring the wrong thing.

---

## (d) Pricing / availability facts from the web

- **No public footprint whatsoever.** WebSearches for `cpg-oracle solq.dev DODO`, `mishoko cpg-oracle`, `solq.dev API key`, and `solq.dev/cpg-oracle pricing/benchmark/writeup` returned **only** generic Code-Property-Graph material (Fraunhofer, Joern, Plume) and unrelated Oracle-Corp / Solidity-oracle-pattern results. **No announcement, no blog post, no third-party mention, no benchmark, no leaderboard, no price list.**
- **GitHub:** `mishoko/cpg-oracle` — created ~2026-07-22, **2 commits, 0 stars, 0 forks, no topics/description tags**, proprietary eval license. Not a marketed product.
- **Pricing: undisclosed.** README/LICENSE say only "Provided for evaluation … Read-only, term-limited, non-transferable." No free tier and no paid tier is stated; access is per-key, out-of-band, revocable. There is no evidence of any way — free or paid — to self-obtain a `dodo` MCP key from public channels; you must be given one.

**Sources (web):** general CPG references only — [Fraunhofer-AISEC/cpg](https://github.com/Fraunhofer-AISEC/cpg), [Joern CPG spec](https://cpg.joern.io/), [Wikipedia: Code property graph](https://en.wikipedia.org/wiki/Code_property_graph). No source specific to solq.dev / cpg-oracle exists in web indexes as of 2026-07-23.

---

## Appendix — endpoint probe matrix (all keyless unless noted)

| Method | URL | Result |
|---|---|---|
| POST | `/api/v1/cpg/dodo/mcp` (no key) | 401 "Missing API key" |
| POST | `/api/v1/cpg/dodo/mcp` (`X-API-Key: test`) | 401 "Invalid API key" |
| POST | `/api/v1/cpg/dodo/mcp` (`Authorization: Bearer test`) | 401 |
| GET | `/api/v1/cpg/dodo` | 401 "Missing API key" |
| GET | `/` , `/docs`, `/openapi.json` | 200 SPA shell (Vite) |
| GET | `/health` | 200 — **degraded (worker down)** |
| GET | `/api/v1/queries/categories` | 200 — public vuln-query catalog |
| GET | `/api/v1/auth/me` | 401 "No token provided" |
| POST | `/api/v1/auth/login` | 401 "Invalid email or password" |
| POST | `/api/v1/auth/register` | 400 validation (weak pw) — **signup appears open**; not completed |
| GET | `/api/v1`, `/api/v1/auth/quota`, `/api/v1/openapi.json` | 404 |
| GET | `https://api.solq.dev/` | 404 |
