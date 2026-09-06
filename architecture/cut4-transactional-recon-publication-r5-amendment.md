# Cut-4 transactional recon publication R5 amendment

Date: 2026-08-10
Status: Part-0 R5 architecture repair only
Supersedes: only the repaired clauses of the R1-R4 amendments
Authority: design for independent review; no fixture, production, test,
ArtifactLedger, G3, provider, audit, commit, push, install, release, or
audit-readiness authority

## 0. R5 decision

R5 keeps the accepted R4 properties: one DRIVER-owned immutable private seed
namespace; registry-compiled exact bundles; unchanged MODEL shards and
dependency units; lexical PhaseIO ordering; fixed typed provider slots;
non-vacuous valid zero; deterministic encoding; project-root containment;
one canonical writer; no glob or post-write discovery; and no ArtifactLedger
or G3 change.

It changes two R4 clauses.

1. **There is no completed-same-key re-arm.** Fresh transactional runs have one
   new, stable, registered DRIVER operation,
   `recon/canonical_publication_v2`. It is planned, armed, applied, and
   committed exactly once. An interrupted arm resumes its identical sealed
   plan. An exact completed replay is a no-op. Any post-arm semantic drift,
   marker/degrade request, normalizer change, or input change requires a new
   run in a fresh scratchpad. The old run remains immutable history.
2. **The public compatibility namespace remains until all consumers move.**
   The same `canonical_publication_v2` transaction owns both canonical output
   and an authenticated compatibility projection for every current hardcoded
   recon consumer. Public compatibility is not a fallback and is never
   discovered after execution. Its exact path set, source-to-projection rows,
   typed zero/debt states, and consumer denominator are sealed before the
   transaction. Partial private migration is forbidden.

This removes both R4 false premises: the frozen ledger does not need a rollover
API, and a current reader cannot silently miss a private-only artifact. Recall
is preserved because every accepted private row has a canonical or
compatibility disposition, every provider terminal state occupies its fixed
slot, and every current consumer continues to receive an authenticated path.
Precision is preserved because neutral nonapplicability and valid zero are
distinguished from failure debt, stale or unowned public bytes are rejected,
and a consumer cannot pass on an absent or empty denominator.

The R4 248-node roster remains predecessor evidence only. Section 9 defines a
new, closed 316-node R5 roster.

## 1. Authenticated basis and live API facts

The mandatory R4 independent REPAIR review was read end to end. It is 17,438
bytes and has the required SHA-256
`f2e74a31e00118ed1152c7e07b75da9b3f36bffedf2e7d7e372665ed6485f0ea`:

`review_fixtures/cut4_transactional_recon_publication_r4_amendment_independent_review_20260810.md`.

The authenticated architecture/review chain is:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| R1 amendment | 26,307 | `98032f3fbd33987bf5ff4c6d035c088fe6eab34cc9c8b8425b2ff9280e19356e` |
| R1 review | 10,865 | `3b6ff6ff20d2ac1aa6b7128cb0b5ddfe941b17a8bb8631d8f1021f48199078f5` |
| R2 amendment | 30,919 | `7400193cb40771ce61910b14b3d34830584f76b86219ee41ab4c2f0fc21c0f73` |
| R2 review | 8,991 | `5039a4f4ba09a253cba7cca27e55cf6b8f0fe94d0cacfef9bdfd5580c949f855` |
| R3 amendment | 40,006 | `583039a2eb7a8a2c496333d7438505461f03e14d870dd339160085d5b23fd715` |
| R3 review | 14,988 | `8c6c2f917c695be1911f501010fc32540b40d63f30d8880a6ec22a84daa432fe` |
| R4 amendment | 41,429 | `7424ae2606968c6f32f0fc102b3220aebc15f1f13dce574281651595ab1236d9` |
| R4 review | 17,438 | `f2e74a31e00118ed1152c7e07b75da9b3f36bffedf2e7d7e372665ed6485f0ea` |

The live source anchors read for R5 are:

| Source | SHA-256 | Relevant live fact |
|---|---|---|
| `scripts/phase_io_contracts.py` | `f3d580f5f560c10e3337287dec18e6dac4d2d86289ad34346f7b39477d1ec3af` | `resolve_phase_io_contract()` accepts exact input/output tuples; `PhaseIOContract` seals lexical input order; no publication-v2 branch exists yet. |
| `scripts/artifact_ledger.py` | `d9fd6d34249e522347d4bb26b7c207d549a534f5cdb29f663b84d20bb968663e` | successor plan, arm, ordered progress, and artifact commit APIs exist; no completed-plan rollover exists. |
| `scripts/plamen_driver.py` | `9e601fcb807cf5f32f1a25ef79dac3b69ed3b92b1bce09b69b9f86b987abae83` | recon, prompt, provider, breadth/depth, and downstream callsites still name public paths. |
| `scripts/recon_prepass.py` | `630de04c237e78deb0efb5a5030c0a48f65ce14b6e05e8d76824a19ab2ea25e6` | graph/scanner/SCIP/dependency producers and direct public writers exist. |
| `scripts/plamen_prompt.py` | `00578673a7f1aa91060fb5c1c2be4cb9632a32876926491a52f4696ffcfb4e1d` | prompt compiler and L1 depth instructions name public SCIP inputs. |
| `scripts/plamen_mechanical.py` | `0b62bf0bb313f4ff5c95651af7b2202e18e2aadf6632d7ed6c957a41107c7ef8` | canonical graph and prepass integration seams. |
| `scripts/plamen_validators.py` | `cf99150d9d0fac0cdba6b0f0582c00db986001856d71c9a611cf9950c215cec9` | OpenGrep/function-summary validators can currently pass on absent input. |
| `scripts/enumeration_gate.py` | `898dd38b6737bafcfb04bd60ff891964dd9fb4e8b896e0a2a50b868886c54fb7` | graph, scanner, and breadth evidence readers use public paths. |
| `scripts/chain_prep.py` | `6c2d3b9d34b36bf7af3aa10ebeed38bc9aefa26f0dcd9e6938bb89d3979053dd` | chain preparation consumes public graph/scanner projections. |
| `plamen_l1/scip_reader.py` | `9c6f2f784313ef2b9b63153ef0be62dd59ce4a04a68338aa976a5640e9c0dad1` | `ScipReader.__init__()` reads an argv-supplied index at lines 127-144; `_main()` takes it at lines 423-454. |

The decisive ledger trace is exact:

- `plan_driver_successor_transaction()` requires an exact byte mapping equal
  to the contract output identities and seals pre/post state without writing.
- `record_work_unit_inputs(..., successor_plan=plan)` stores the authority.
  If authority already exists, an omitted plan fails and a changed plan fails
  with `successor plan changed on resume`.
- `begin_driver_successor_step()` and `complete_driver_successor_step()` admit
  only the next ordinal and replay already-applied ordinals.
- `record_work_unit_artifacts()` requires complete successor progress and the
  planned output records.
- `apply_semantic_invalidation()` marks stale but preserves successor
  authority. `authorize_deterministic_work_unit_reexecution()` does not replace
  that authority. Therefore R4's completed-same-key replacement cannot work.

## 2. One supported publication transition

### 2.1 Registered identity and lineage

Implementation adds one explicit resolver branch, not a dynamic slash key:

```text
pipeline/mode/ecosystem/backend/recon/canonical_publication_v2
```

`work_unit_id` is the literal `canonical_publication_v2`. The existing
`recon/prepass`, `recon/worker.*`, `recon/dependency_research`, and
`recon/dependency_reconcile` identities remain unchanged. There is no
`attempt-*`, generation, action, marker, or timestamp in the key. The branch
requires exact registry-compiled `exact_inputs` and `exact_outputs`, rejects
duplicates/globs/absolute paths/aliases, uses only DRIVER outputs, and has one
closed model-free `LaunchSpec` whose configuration digest binds:

```json
{
  "operation": "canonical_publication_v2",
  "registry_version": "cut4.recon_publication_registry.v2",
  "normalizer_version": "cut4.recon_normalizer.v2",
  "projection_version": "cut4.recon_compatibility_projection.v1",
  "input_manifest_sha256": "<sha256>",
  "output_manifest_sha256": "<sha256>",
  "action": "INITIAL_PUBLICATION"
}
```

The bounded action enum has one member. Marker strip, degrade, resume, and
repair are not operation keys or postcommit reexecution actions. Their
requested semantics are normalized into staged bytes **before** the initial
plan. Producer/consumer lineage is:

```text
raw project/config/provider plan
  -> recon/prepass private seed + fixed provider outcomes
  -> unchanged recon/worker.* MODEL shards
  -> recon/dependency_research (R-EXT)
  -> recon/dependency_reconcile
  -> recon/canonical_publication_v2
  -> authenticated public canonical + compatibility projection
  -> instantiate, breadth, inventory, depth, chain, verification, report
```

The publication contract's immutable inputs are the committed private seed
manifest, provider receipts/debts/payload digests, MODEL shard receipts and
artifacts, dependency reconcile receipt/artifacts, normalized transform
request from the initial launch configuration, and registry manifests. No
publication output, prior public byte, or post-rewrite snapshot is an input.
Lexical `PhaseIOContract` identity order is used everywhere.

### 2.2 Actual API order

For a fresh transactional scratchpad the driver performs this exact sequence:

1. Resolve all predecessor PhaseIO contracts and commit their receipts.
2. Classify the closed legacy/private predicate. Continue only from
   `FRESH_TRANSACTIONAL_PREPUBLICATION`; legacy stays on legacy behavior.
3. Compile the canonical and compatibility output registry from pipeline,
   language, ecosystem, config, and committed fixed provider outcomes.
4. Render every output in a system temporary staging root. Apply initial
   marker stripping/degrade normalization there. Reject zero bytes, missing or
   extra paths, aliases, symlinks/reparse points, project-root paths, invalid
   schemas, noncanonical JSON/SARIF, unsorted walks, and source/projection
   reconciliation debt not explicitly typed.
5. Resolve `recon/canonical_publication_v2` with the exact tuples and construct
   the stable model-free `LaunchSpec`.
6. Call `plan_driver_successor_transaction(...,
   planned_output_bytes=exact_bytes, merge_events=exact_merge_events)`. Fresh
   outputs use `CREATE`; there is no adoption or merge over unowned preimages.
7. Call `record_work_unit_inputs(..., successor_plan=plan)` exactly once.
8. For each plan ordinal, call `begin_driver_successor_step()`, perform the
   exact filesystem transition, then call `complete_driver_successor_step()`.
9. Call `record_work_unit_artifacts(...,
   expected_output_records=plan.expected_output_records,
   merge_events=planned_merge_events)`.
10. Gate all consumers on the committed publication receipt, compatibility
    receipt, complete-set digest, and namespace-capture receipt.

This uses current APIs in their supported order. The only new ledger-facing
surface is the ordinary registered PhaseIO branch; `artifact_ledger.py` is not
changed.

### 2.3 Resume, degrade, and migration

The total behavior is:

| State | Action |
|---|---|
| Before step 7 and an input/config/degrade request changes | Delete only system-temp staging, recompute contract/launch/bytes, and plan once. No ledger unit exists. |
| After step 7 but before artifact commit | Resolve the same contract/launch, call `load_driver_successor_plan()`, pass that exact plan to `record_work_unit_inputs()`, replay ordinals, and commit. Changed bytes/config fail closed. |
| Exact completed replay | Validate committed receipts and bytes; return no-op. Do not call invalidation or authorization. |
| Completed run receives marker/degrade/normalizer/input drift | Emit loud `FRESH_RUN_REQUIRED` disposition outside the frozen work unit and start only by explicit operator choice in a fresh scratchpad/run. Old bytes and ledger remain untouched. |
| Unowned legacy canonical or compatibility path exists | Classify `LEGACY_COMPATIBILITY_DEBT`, retain old ownership/read behavior, warn without halting legacy execution, and offer fresh-run upgrade. Never adopt/delete/overwrite. |
| Fresh-run upgrade | Create a new empty scratchpad and new `run_id`; rebind external project/config inputs; rerun predecessors and the one publication operation. Do not copy canonical/public or ledger bytes. |

The optional mechanically safe external-input snapshot migration described in
R2-R4 remains future and inactive. It cannot import ArtifactLedger ownership.
No in-place migration is authorized.

## 3. Exact canonical and compatibility publication

### 3.1 One owner and exact compilation

`recon/canonical_publication_v2` is the only writer of the current canonical
SC/L1 publication and every compatibility public projection. Providers,
MODEL workers, late hooks, and validators cannot write them. The output tuple
is compiled before staging from the same registry used to derive the canonical
projection. Conditional raw SCIP indexes are selected from committed provider
status, never filesystem presence. No public glob, post-write enumeration, or
conditional repair marker exists.

The fixed compatibility core contains these 37 nonempty paths:

```json
[
  "_mechanical_graph.json",
  "_mechanical_graph_generation.json",
  "call_graph.md",
  "caller_map.md",
  "callee_map.md",
  "state_read_map.md",
  "state_write_map.md",
  "function_summary.md",
  "inheritance_tree.md",
  "access_control_map.md",
  "detector_findings.md",
  "opengrep_results.sarif",
  "opengrep_findings.md",
  "sec3_results.sarif",
  "sec3_findings.md",
  "dependency_audit_findings.md",
  "tool_coverage_ledger.json",
  "tool_coverage_ledger.md",
  "slither/primitive_status.md",
  "slither/function_summary.md",
  "slither/call_graph.md",
  "slither/inheritance_tree.md",
  "slither/access_control_map.md",
  "slither/detector_findings.md",
  "scip_rust.index",
  "scip_go.index",
  "scip/repo_map.md",
  "scip/repo_map_full.md",
  "scip/xref_map.md",
  "scip/call_graph_p2p.md",
  "scip/call_graph_consensus.md",
  "scip/call_graph_execution.md",
  "scip/type_hierarchy.md",
  "scip/concurrency_inventory.md",
  "scip/panic_sites.md",
  "recon_compatibility_projection_manifest.json",
  "recon_compatibility_projection_receipt.json"
]
```

The canonical registry adds the existing ecosystem-specific SC/DAML/L1/OS
canonical set enumerated in R4 section 6.1, including
`recon_signal_transform_receipt.json`. The two sets are de-duplicated by
physical identity before contract construction. Any overlap has exactly one
publication record and one semantic kind.

`scip_rust.index` and `scip_go.index` are fixed compatibility payloads. A
successful applicable selected slot projects the validated private index. All
other terminal states project a deterministic, nonzero, protobuf-valid SCIP
`Index` containing metadata only and no documents or symbols. The manifest
binds the precise neutral/debt state, so the query engine receives a stable
parseable path but zero references cannot become evidence or a false green.
This preserves both the physical path denominator and the semantic provider
denominator without inventing symbols.

### 3.2 Fixed provider and projection semantics

Every fixed provider slot uses R4's statuses `NOT_APPLICABLE`, `NOT_SELECTED`,
`SUCCESS`, `FAILURE`, `TIMEOUT`, and `MALFORMED`. The compatibility manifest
joins each public path to exactly one private source slot and records:

```json
{
  "public_identity": "opengrep_findings.md",
  "source_identity": "_recon_seed/providers/opengrep/outcome.json",
  "status": "SUCCESS",
  "applicable": true,
  "selected": true,
  "evidence_row_count": 0,
  "debt_row_count": 0,
  "valid_zero_proof_sha256": "<nonempty when SUCCESS has zero rows>",
  "source_sha256": "<sha256>",
  "projection_sha256": "<sha256>",
  "consumer_ids": ["<closed sorted consumer ids>"],
  "disposition": "VALID_TYPED_ZERO"
}
```

The allowed dispositions are `EVIDENCE`, `VALID_TYPED_ZERO`,
`OPEN_PROVIDER_DEBT`, `NEUTRAL_NOT_APPLICABLE`, and
`NEUTRAL_NOT_SELECTED`. `NOT_APPLICABLE` is neither evidence nor debt.
`NOT_SELECTED` is neutral only where selection is explicitly optional; a
required provider maps it to open debt. `FAILURE`, `TIMEOUT`, and `MALFORMED`
always map to nonempty open debt for each applicable consumer. A selected
`SUCCESS` with zero rows is valid only with terminal capture proof, input and
configuration digests, payload/schema validation, deterministic walk proof,
and a provider-specific zero certificate. Thus a public Markdown/SARIF zero
cannot falsely green a validator.

Graph/OpenGrep/Sec3/dependency-audit/SCIP provider execution occurs only in
the private prepass. The publication renders deterministic compatibility
bytes from committed outcomes. Foundry uses a system-temp overlay and never
changes project-root configuration. Provider failure, timeout, malformed
output, platform absence, disabled selection, and unsupported ecosystems all
preserve the fixed path denominator and typed semantics.

## 4. Consumer denominator and no-orphan invariant

Before instantiate and before every breadth, inventory, depth, chain,
verification, and report launch, the driver validates a single
`recon_compatibility_projection_receipt.json` and binds it through the current
prompt/input-binding machinery. The prompt compiler appends only a recon-input
authority block to phases that consume recon products; generic workers and
methodology prose/roles remain unchanged. Static instructions continue to name
their public paths, which now resolve to authenticated compatibility bytes.

A consumer join passes only if:

1. the publication work unit and all 37 fixed outputs are current-run ACTIVE;
2. the manifest and receipt digests match the exact physical namespace;
3. each hardcoded public read has a manifest row and consumer ID;
4. each accepted private evidence row appears exactly once in canonical or
   compatibility output, and every rejected/unknown row has exactly one debt;
5. each raw index is actual payload iff its SUCCESS predicate is true and is
   otherwise the exact metadata-only projection joined to neutral/debt state;
6. no public or private supersets, aliases, zero bytes, orphan payloads, stale
   owners, direct provider writes, or fallback reads exist; and
7. graph, scanner, dependency, and symbol denominators reconcile before a
   validator may interpret result counts.

The global gate makes old local validators safe while their parsers remain.
Specifically, absent `opengrep_findings.md` and absent/empty
`function_summary.md` can no longer return success before the denominator
gate. No `Path.exists() ? zero : fallback` branch is allowed in transactional
mode. A consumer wanting a new path must first enter the registry and manifest
and expand the atomic publication contract.

The no-orphan equation is exact:

```text
private accepted rows
  = canonical accepted rows + compatibility-only accepted rows
private unresolved rows
  = canonical debt rows + compatibility-only debt rows
published identities
  = registry fixed identities + provider-predicate conditional identities
hardcoded consumer identities
  = manifest consumer identities
```

All equalities are multiset equality over `(source identity, semantic row id,
status, consumer id)`, not counts alone.

## 5. Mechanical current-consumer manifest

The manifest below is the result of a repository-wide literal scan, excluding
tests, architecture, and review fixtures, for the closed public/private token
set in section 3 plus graph, Slither, OpenGrep, Sec3, dependency-audit, SCIP,
primitive-status, and tool-coverage variants. The exact scan is `rg -n
--no-heading` with exclusions `!tests/**`, `!architecture/**`,
`!review_fixtures/**`, `!scripts/test*.py`, and this regex:

```text
(_mechanical_graph(_generation)?\.json|caller_map\.md|callee_map\.md|state_read_map\.md|state_write_map\.md|function_summary\.md|call_graph\.md|inheritance_tree\.md|access_control_map\.md|detector_findings\.md|primitive_status\.md|opengrep_(results\.sarif|findings\.md)|sec3_(results\.sarif|findings\.md)|scip_(go|rust)\.index|repo_map(_full)?\.md|xref_map\.md|call_graph_(p2p|consensus|execution)\.md|type_hierarchy\.md|concurrency_inventory\.md|panic_sites\.md|dependency_audit_findings\.md|tool_coverage_ledger\.(json|md))
```

It yields 574 literal line hits in 68 files; R4's exact private-producer
anchors are unioned where they are outside this public token regex. C069 is the
one indirect argv consumer, so the denominator is 69 source entries. Line
lists are the authenticated current callsite denominator, not suggested edit
locations.

Classes are `RUNTIME`, `PRODUCER`, `PROMPT`, `SKILL`, `OPERATOR_DOC`, and
`INDIRECT_ARG`. Static prompts/skills/docs are retained byte-for-byte by the
compatibility projection. Runtime/compiler/validator callsites receive the
manifest gate and exact input binding during implementation. Producer paths
are removed as public writers and retained only as private producers.

| ID | Class | Exact source and matching lines |
|---:|---|---|
| C001 | SKILL | `agents/skills/injectable/l1/config-correctness/SKILL.md`: 49 |
| C002 | SKILL | `agents/skills/injectable/l1/consensus-safety-invariants/SKILL.md`: 223,349,366 |
| C003 | SKILL | `agents/skills/injectable/l1/cosmos-ibc-security/SKILL.md`: 31,94 |
| C004 | SKILL | `agents/skills/injectable/l1/cosmos-sdk-module-safety/SKILL.md`: 31,62,136 |
| C005 | SKILL | `agents/skills/injectable/l1/cross-environment-semantic-drift/SKILL.md`: 147 |
| C006 | SKILL | `agents/skills/injectable/l1/execution-client-hardening/SKILL.md`: 234 |
| C007 | SKILL | `agents/skills/injectable/l1/mempool-asymmetric-dos/SKILL.md`: 182 |
| C008 | SKILL | `agents/skills/injectable/l1/rpc-surface-audit/SKILL.md`: 175 |
| C009 | SKILL | `agents/skills/injectable/l1/validator-lifecycle-and-slashing/SKILL.md`: 120 |
| C010 | SKILL | `agents/skills/niche/semantic-consistency-audit/SKILL.md`: 51,64,71 |
| C011 | OPERATOR_DOC | `commands/plamen.md`: 1091 |
| C012 | OPERATOR_DOC | `commands/plamen-l1.md`: 210,317,318,321,330,333,337-339,341-344,349-351,356,357,360,361,364,365,369-371,374,376,377,390,462-467,474,511,522,554,589,614,615,705-709,734,737,891 |
| C013 | OPERATOR_DOC | `docs/design/recall-build-plan.md`: 72,83,183 |
| C014 | OPERATOR_DOC | `docs/internals.md`: 248,252,255,258-259,292-305 |
| C015 | PROMPT | `prompts/aptos/phase1-recon-prompt.md`: 27,553,615,626,628,641,643,659,661,673,765,1154 |
| C016 | PROMPT | `prompts/aptos/phase4b-depth-templates.md`: 37-40 |
| C017 | PROMPT | `prompts/aptos/v2/phase1-recon-prompt.md`: 380 |
| C018 | PROMPT | `prompts/daml/phase4b-depth-templates.md`: 29-31 |
| C019 | PROMPT | `prompts/daml/v2/phase1-recon-prompt.md`: 232 |
| C020 | PROMPT | `prompts/daml/v2/phase4a-inventory-prompt.md`: 150,260 |
| C021 | PROMPT | `prompts/evm/phase1-recon-prompt.md`: 29,192,194,205,215,219,250,268,270,287,289,307,309,322,323,328,484 |
| C022 | PROMPT | `prompts/evm/phase3-breadth-driver.md`: 13,18-21,30 |
| C023 | PROMPT | `prompts/evm/phase4b-depth-driver.md`: 88,92-95 |
| C024 | PROMPT | `prompts/evm/phase4b-depth-templates.md`: 36-39 |
| C025 | PROMPT | `prompts/evm/v2/phase1-recon-prompt.md`: 237,239,249,259,263 |
| C026 | PROMPT | `prompts/l1/phase05-bake.md`: 22,23,26,30,39-47,52,54,70,93 |
| C027 | PROMPT | `prompts/l1/phase1-recon-prompt.md`: 21,34,40,48,51,52,58,369 |
| C028 | PROMPT | `prompts/l1/phase3-breadth-driver.md`: 97,115,118 |
| C029 | PROMPT | `prompts/l1/phase4b-depth-driver.md`: 26,34-38,60,61,74-82,109,110 |
| C030 | PROMPT | `prompts/l1/v2/phase1-recon-prompt.md`: 33,76,109,112,131,137,145,148,149,155,500 |
| C031 | PROMPT | `prompts/shared/v2/phase3-breadth.md`: 108,176-179,183,196,203,214,407,408,411,416 |
| C032 | PROMPT | `prompts/shared/v2/phase4b4-attention-repair.md`: 14 |
| C033 | PROMPT | `prompts/shared/v2/phase4b-depth.md`: 220-223,240-243,254,256,257,259,260,262,263,265,326,329,385,387,390,395,397 |
| C034 | PROMPT | `prompts/shared/v2/pipeline-full-audit.md`: 318 |
| C035 | PROMPT | `prompts/shared/v2-full-assessment.md`: 101,107,117,127,131,132 |
| C036 | PROMPT | `prompts/solana/phase1-recon-prompt.md`: 27,356,392,404,406,419,421,437,439,451,476,478,721 |
| C037 | PROMPT | `prompts/solana/phase4b-depth-templates.md`: 27-30 |
| C038 | PROMPT | `prompts/solana/v2/phase1-recon-prompt.md`: 262 |
| C039 | PROMPT | `prompts/soroban/phase1-recon-prompt.md`: 27,375,410,421,423,435,437,454,456,466,511,753 |
| C040 | PROMPT | `prompts/soroban/phase4b-depth-templates.md`: 29-32 |
| C041 | PROMPT | `prompts/soroban/v2/phase1-recon-prompt.md`: 256 |
| C042 | PROMPT | `prompts/sui/phase1-recon-prompt.md`: 27,409,453,464,466,479,481,500,502,514,583,939 |
| C043 | PROMPT | `prompts/sui/phase4b-depth-templates.md`: 36-39 |
| C044 | PROMPT | `prompts/sui/v2/phase1-recon-prompt.md`: 282 |
| C045 | RUNTIME | `scripts/axis_disposition.py`: 1802 |
| C046 | RUNTIME | `scripts/chain_prep.py`: 169,176,291,293,339,918,919,1223,1224 |
| C047 | RUNTIME | `scripts/codex_adapter.py`: 1191 |
| C048 | RUNTIME | `scripts/enumeration_gate.py`: 10,272,542,735,3213,3219,3227,3281,3833,3947,3948,4538 |
| C049 | RUNTIME | `scripts/live_verify_queue_driver_adapter.py`: 63,64 |
| C050 | RUNTIME | `scripts/phase_io_contracts.py`: 2594,2595,3405,4045,5692,5856-5863,5936 |
| C051 | RUNTIME | `scripts/plamen_driver.py`: 10098,10099,31605,31649,31651,42538,42555,42612,42841,43009,43046,43054-43058,43062,43068,43076-43078,43086,43094-43096,43105-43109,43781,55694,55700,55706,55727,56846,56849,56854,56867,56871,56917,56921,56923,56932,57212,57266,57269,57295,57310,57371,57379,57411,60054,60055,60244,63799,64694,64841,64970 |
| C052 | RUNTIME/PRODUCER | `scripts/plamen_mechanical.py`: 12231 |
| C053 | RUNTIME | `scripts/plamen_parsers.py`: 9947,9954 |
| C054 | RUNTIME | `scripts/plamen_prompt.py`: 1973,1981,1982,1987,2002-2004,2087-2089,2419,3403,3704,3791-3794,3804,3816,3968,3974,3991 |
| C055 | RUNTIME | `scripts/plamen_validators.py`: 4352,9925,9938,9939,9960,9979,10324,10330-10335,10365,10395,10428,10957,10977-10984,11071,11138,14768-14771,14778,14918,14924,14981,15489,15497,15513,15525,15527,15534,15536,15558,15568,15579,15584,15630,15638,15665,15671 |
| C056 | PRODUCER | `scripts/recon_prepass.py`: 3279,3401,3444,3512,3532,3589,3590,3612,3623,3671,3680,3743,3835,3836,4153,4154,4163,4188,4434,4854,4867,4869,4887,4889,4902,4904,4928,4972,5008,5228-5232,5301,5436,5483,5743,5802,5878,5959,5970,5982,6021,6050,6146,6214,6225,6237,6275,6286,6622,6806,6820,6882,6897,6940,7002,7598,7643,7656,7692 |
| C057 | RUNTIME | `scripts/security_obligation_authority.py`: 65,122-127 |
| C058 | RUNTIME | `scripts/semantic_invariant_authority.py`: 54,552,719 |
| C059 | RUNTIME | `scripts/state_symbol_authority.py`: 20,147,198,328 |
| C060 | RUNTIME | `scripts/tool_coverage_ledger.py`: 5,29,30,52-56,59,1601 |
| C061 | RUNTIME | `scripts/verification_method_compiler.py`: 30,31 |
| C062 | PROMPT | `agents/depth-consensus-invariant.md`: 30 |
| C063 | PROMPT | `agents/depth-network-surface.md`: 30 |
| C064 | OPERATOR_DOC | `docs/l1-mode/design.md`: 152,154 |
| C065 | PROMPT | `prompts/l1/phase6-report-overrides.md`: 60,121 |
| C066 | PROMPT | `prompts/l1/v2/phase5-verification-prompt.md`: 40,134 |
| C067 | PROMPT | `prompts/shared/v2/phase6a-report-index.md`: 30,435 |
| C068 | RUNTIME | `scripts/plamen_types.py`: 2704 |
| C069 | INDIRECT_ARG | `plamen_l1/scip_reader.py`: 127-144,423-454; index supplied by C029/C054/C051 callsites |

The implementation runs the same scan from the checked-in manifest and fails
on any line-set difference. A new match cannot be ignored: it must be
classified, assigned a consumer ID, added to the compatibility/canonical
registry, and covered by a new test. A removed match must have proof that its
replacement is PhaseIO-bound before the projection path may retire. Retirement
is one atomic future cut, never piecemeal.

## 6. Legacy predicate and public/private reconciliation

R5 inherits R4's exact ecosystem canonical registry and expands the current
owned set with the 37 compatibility paths, including both fixed raw-index
projections.
Classification is closed and has no glob:

| Ledger/current paths | Private seed | Publication-v2 unit | Classification |
|---|---|---|---|
| no registered canonical/compat paths | complete valid prepublication seed | absent | `FRESH_TRANSACTIONAL_PREPUBLICATION` |
| exact complete current-owned set | complete valid seed | ACTIVE, same run | `FRESH_TRANSACTIONAL_COMMITTED` |
| exact planned transitional set | complete valid seed | armed, same run | `FRESH_TRANSACTIONAL_RESUMABLE` |
| any unowned/old-owner canonical or compatibility identity | any | absent or different owner | `LEGACY_COMPATIBILITY_DEBT` |
| partial/extra/invalid private seed, including orphan provider payload | invalid | any | `LEGACY_COMPATIBILITY_DEBT` |
| public/private alias, zero, superset, stale receipt, or wrong run | any | any | `LEGACY_COMPATIBILITY_DEBT` |
| completed publication plus changed semantic input/config | valid old | ACTIVE old digest | `FRESH_RUN_REQUIRED` |

Legacy mode flags loudly but does not halt its old read behavior. It never
calls publication-v2, rewrites, deletes, or claims existing paths. Fresh mode
never reads a legacy fallback. `recon_signal_transform_receipt.json`, all SC/L1
canonical paths, the 37 compatibility paths, both fixed indexes, ledger
unit/version presence, and all private namespace states participate in the
predicate.

## 7. PhaseIO keys, implementation ownership, and worker boundaries

Future implementation is serialized in bounded phases:

1. **Registry/contract worker:** `scripts/phase_io_contracts.py` and the new
   checked-in closed registry module/data. Adds only the literal
   `canonical_publication_v2` branch and compatibility manifest schema.
2. **Private producer worker:** `scripts/recon_prepass.py` and
   `scripts/plamen_mechanical.py`. Moves provider payloads to private fixed
   identities and removes direct public/project-root mutation.
3. **Publication worker:** `scripts/plamen_driver.py`. Owns compile, render,
   staging, current API sequence, resume/no-op/fresh-run disposition, and sole
   public writes.
4. **Binding/gate worker:** `scripts/plamen_prompt.py`,
   `scripts/plamen_validators.py`, `scripts/enumeration_gate.py`,
   `scripts/chain_prep.py`, `scripts/axis_disposition.py`,
   `scripts/security_obligation_authority.py`,
   `scripts/state_symbol_authority.py`,
   `scripts/semantic_invariant_authority.py`, `scripts/plamen_parsers.py`,
   `scripts/tool_coverage_ledger.py`,
   `scripts/verification_method_compiler.py`, and
   `scripts/live_verify_queue_driver_adapter.py`. Adds the global consumer
   denominator and removes false-green fallback. Generic roles are untouched.
5. **Consumer reconciliation worker:** owns the exact C001-C069 manifest scan
   and proves static prompt/skill/operator compatibility without methodology
   changes.
6. **Fixture worker:** owns only new copy-on-write R5 RED fixtures and receipt.

Workers are not alone in the tree, must preserve concurrent changes, write
only their assigned files, and must not alter ArtifactLedger, G3, prior
fixtures/reviews, provider installs, audit outputs, or MODEL shard/dependency
unit identities. Test phases run registry/PhaseIO, provider/zero, physical
set, MODEL visibility, publication lifecycle, compatibility paths, consumer
source scan, denominator joins, existing regressions, then platform matrices;
finally all R5 nodes run together with the frozen accepted V7 denominator.

## 8. Non-goals and acceptance boundary

R5 does not implement code or tests, run providers/audits, install tools,
change `artifact_ledger.py`, change G3/pins, change `artifact_ledger.json`,
commit, push, release, adopt legacy bytes, or authorize an audit. It does not
promise in-place transform reexecution. The safe operation is deliberately
one-time; a new semantic publication is a new run in a fresh scratchpad.

No architecture claim is accepted from prose alone. A future implementation
must pass the exact roster below, the checked-in C001-C069 scan, complete
source/projection multiset reconciliation, exact replay, failpoints,
all-old/all-new recovery, zero-byte/alias/containment checks, and the accepted
V7 tests.

## 9. Exact R5 test roster

The following JSON is the complete roster. It contains exactly **316** unique
pytest node IDs: 9 plan, 54 provider, 15 provider-zero, 28 set, 35 MODEL, 24
publication, 42 compatibility, 69 consumer-source, 20 denominator, 12 existing
regression, and 8 platform nodes. There are no implied parameterizations or
wildcards.

```json
{
  "plan": [
    "tests/test_cut4_r5_plan.py::test_registry_compile_sc_evm",
    "tests/test_cut4_r5_plan.py::test_registry_compile_sc_non_evm",
    "tests/test_cut4_r5_plan.py::test_registry_compile_daml",
    "tests/test_cut4_r5_plan.py::test_registry_compile_l1_rust",
    "tests/test_cut4_r5_plan.py::test_registry_compile_l1_go",
    "tests/test_cut4_r5_plan.py::test_registry_compile_os",
    "tests/test_cut4_r5_plan.py::test_lexical_input_order",
    "tests/test_cut4_r5_plan.py::test_projection_from_same_registry",
    "tests/test_cut4_r5_plan.py::test_plan_digest_tamper"
  ],
  "provider": [
    "tests/test_cut4_r5_provider.py::test_graph_not_applicable",
    "tests/test_cut4_r5_provider.py::test_graph_not_selected",
    "tests/test_cut4_r5_provider.py::test_graph_success",
    "tests/test_cut4_r5_provider.py::test_graph_failure",
    "tests/test_cut4_r5_provider.py::test_graph_timeout",
    "tests/test_cut4_r5_provider.py::test_graph_malformed",
    "tests/test_cut4_r5_provider.py::test_opengrep_not_applicable",
    "tests/test_cut4_r5_provider.py::test_opengrep_not_selected",
    "tests/test_cut4_r5_provider.py::test_opengrep_success",
    "tests/test_cut4_r5_provider.py::test_opengrep_failure",
    "tests/test_cut4_r5_provider.py::test_opengrep_timeout",
    "tests/test_cut4_r5_provider.py::test_opengrep_malformed",
    "tests/test_cut4_r5_provider.py::test_sec3_not_applicable",
    "tests/test_cut4_r5_provider.py::test_sec3_not_selected",
    "tests/test_cut4_r5_provider.py::test_sec3_success",
    "tests/test_cut4_r5_provider.py::test_sec3_failure",
    "tests/test_cut4_r5_provider.py::test_sec3_timeout",
    "tests/test_cut4_r5_provider.py::test_sec3_malformed",
    "tests/test_cut4_r5_provider.py::test_scip_rust_not_applicable",
    "tests/test_cut4_r5_provider.py::test_scip_rust_not_selected",
    "tests/test_cut4_r5_provider.py::test_scip_rust_success",
    "tests/test_cut4_r5_provider.py::test_scip_rust_failure",
    "tests/test_cut4_r5_provider.py::test_scip_rust_timeout",
    "tests/test_cut4_r5_provider.py::test_scip_rust_malformed",
    "tests/test_cut4_r5_provider.py::test_scip_go_not_applicable",
    "tests/test_cut4_r5_provider.py::test_scip_go_not_selected",
    "tests/test_cut4_r5_provider.py::test_scip_go_success",
    "tests/test_cut4_r5_provider.py::test_scip_go_failure",
    "tests/test_cut4_r5_provider.py::test_scip_go_timeout",
    "tests/test_cut4_r5_provider.py::test_scip_go_malformed",
    "tests/test_cut4_r5_provider.py::test_dependency_audit_not_applicable",
    "tests/test_cut4_r5_provider.py::test_dependency_audit_not_selected",
    "tests/test_cut4_r5_provider.py::test_dependency_audit_success",
    "tests/test_cut4_r5_provider.py::test_dependency_audit_failure",
    "tests/test_cut4_r5_provider.py::test_dependency_audit_timeout",
    "tests/test_cut4_r5_provider.py::test_dependency_audit_malformed",
    "tests/test_cut4_r5_provider.py::test_slither_not_applicable",
    "tests/test_cut4_r5_provider.py::test_slither_not_selected",
    "tests/test_cut4_r5_provider.py::test_slither_success",
    "tests/test_cut4_r5_provider.py::test_slither_failure",
    "tests/test_cut4_r5_provider.py::test_slither_timeout",
    "tests/test_cut4_r5_provider.py::test_slither_malformed",
    "tests/test_cut4_r5_provider.py::test_foundry_not_applicable",
    "tests/test_cut4_r5_provider.py::test_foundry_not_selected",
    "tests/test_cut4_r5_provider.py::test_foundry_success",
    "tests/test_cut4_r5_provider.py::test_foundry_failure",
    "tests/test_cut4_r5_provider.py::test_foundry_timeout",
    "tests/test_cut4_r5_provider.py::test_foundry_malformed",
    "tests/test_cut4_r5_provider.py::test_os_scanner_not_applicable",
    "tests/test_cut4_r5_provider.py::test_os_scanner_not_selected",
    "tests/test_cut4_r5_provider.py::test_os_scanner_success",
    "tests/test_cut4_r5_provider.py::test_os_scanner_failure",
    "tests/test_cut4_r5_provider.py::test_os_scanner_timeout",
    "tests/test_cut4_r5_provider.py::test_os_scanner_malformed"
  ],
  "provider_zero": [
    "tests/test_cut4_r5_provider_zero.py::test_graph_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_opengrep_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_sec3_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_scip_rust_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_scip_go_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_dependency_audit_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_slither_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_foundry_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_os_scanner_valid_zero",
    "tests/test_cut4_r5_provider_zero.py::test_missing_zero_proof",
    "tests/test_cut4_r5_provider_zero.py::test_wrong_input_digest",
    "tests/test_cut4_r5_provider_zero.py::test_wrong_configuration_digest",
    "tests/test_cut4_r5_provider_zero.py::test_nondeterministic_walk",
    "tests/test_cut4_r5_provider_zero.py::test_nonapplicable_neutral",
    "tests/test_cut4_r5_provider_zero.py::test_required_not_selected_debt"
  ],
  "set": [
    "tests/test_cut4_r5_set.py::test_complete_sc_evm",
    "tests/test_cut4_r5_set.py::test_complete_sc_solana",
    "tests/test_cut4_r5_set.py::test_complete_sc_aptos",
    "tests/test_cut4_r5_set.py::test_complete_sc_sui",
    "tests/test_cut4_r5_set.py::test_complete_sc_soroban",
    "tests/test_cut4_r5_set.py::test_complete_daml",
    "tests/test_cut4_r5_set.py::test_complete_l1_rust",
    "tests/test_cut4_r5_set.py::test_complete_l1_go",
    "tests/test_cut4_r5_set.py::test_complete_os",
    "tests/test_cut4_r5_set.py::test_missing_output",
    "tests/test_cut4_r5_set.py::test_extra_output",
    "tests/test_cut4_r5_set.py::test_zero_byte",
    "tests/test_cut4_r5_set.py::test_partial_write",
    "tests/test_cut4_r5_set.py::test_physical_alias",
    "tests/test_cut4_r5_set.py::test_symlink",
    "tests/test_cut4_r5_set.py::test_reparse_point",
    "tests/test_cut4_r5_set.py::test_case_alias",
    "tests/test_cut4_r5_set.py::test_unicode_alias",
    "tests/test_cut4_r5_set.py::test_path_traversal",
    "tests/test_cut4_r5_set.py::test_project_root_write",
    "tests/test_cut4_r5_set.py::test_namespace_capture",
    "tests/test_cut4_r5_set.py::test_noncanonical_json",
    "tests/test_cut4_r5_set.py::test_unsorted_projection",
    "tests/test_cut4_r5_set.py::test_compatibility_core_complete",
    "tests/test_cut4_r5_set.py::test_compatibility_core_partial",
    "tests/test_cut4_r5_set.py::test_compatibility_core_superset",
    "tests/test_cut4_r5_set.py::test_raw_index_success_projects_payload",
    "tests/test_cut4_r5_set.py::test_raw_index_nonsuccess_projects_typed_empty"
  ],
  "model": [
    "tests/test_cut4_r5_model.py::test_evm_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_evm_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_solana_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_solana_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_aptos_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_aptos_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_sui_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_sui_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_soroban_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_soroban_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_daml_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_daml_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_l1_rust_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_l1_rust_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_l1_go_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_l1_go_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_os_base_seed_visibility",
    "tests/test_cut4_r5_model.py::test_os_rext_seed_visibility",
    "tests/test_cut4_r5_model.py::test_pty_prelaunch_binding",
    "tests/test_cut4_r5_model.py::test_pty_prompt_binding",
    "tests/test_cut4_r5_model.py::test_pty_postcommit_binding",
    "tests/test_cut4_r5_model.py::test_codex_prelaunch_binding",
    "tests/test_cut4_r5_model.py::test_codex_prompt_binding",
    "tests/test_cut4_r5_model.py::test_codex_postcommit_binding",
    "tests/test_cut4_r5_model.py::test_claude_prelaunch_binding",
    "tests/test_cut4_r5_model.py::test_claude_prompt_binding",
    "tests/test_cut4_r5_model.py::test_claude_postcommit_binding",
    "tests/test_cut4_r5_model.py::test_lexical_prompt_order",
    "tests/test_cut4_r5_model.py::test_methodology_unchanged",
    "tests/test_cut4_r5_model.py::test_recon_role_scope_only",
    "tests/test_cut4_r5_model.py::test_no_public_fallback",
    "tests/test_cut4_r5_model.py::test_prompt_contradiction_scan",
    "tests/test_cut4_r5_model.py::test_consumer_visibility_complete",
    "tests/test_cut4_r5_model.py::test_dependency_research_after_base",
    "tests/test_cut4_r5_model.py::test_model_shard_identity_unchanged"
  ],
  "publication": [
    "tests/test_cut4_r5_publication.py::test_fresh_initial_publication",
    "tests/test_cut4_r5_publication.py::test_contract_key_stable",
    "tests/test_cut4_r5_publication.py::test_old_canonical_merge_not_rearmed",
    "tests/test_cut4_r5_publication.py::test_marker_normalized_before_plan",
    "tests/test_cut4_r5_publication.py::test_degrade_normalized_before_plan",
    "tests/test_cut4_r5_publication.py::test_resume_request_before_plan",
    "tests/test_cut4_r5_publication.py::test_prearm_input_drift_restages",
    "tests/test_cut4_r5_publication.py::test_plan_sealed_before_arm",
    "tests/test_cut4_r5_publication.py::test_arm_passes_exact_plan",
    "tests/test_cut4_r5_publication.py::test_steps_apply_in_ordinal_order",
    "tests/test_cut4_r5_publication.py::test_commit_uses_expected_records",
    "tests/test_cut4_r5_publication.py::test_crash_before_plan",
    "tests/test_cut4_r5_publication.py::test_crash_after_plan_before_arm",
    "tests/test_cut4_r5_publication.py::test_crash_after_arm_before_first",
    "tests/test_cut4_r5_publication.py::test_crash_mid_steps",
    "tests/test_cut4_r5_publication.py::test_crash_before_artifact_commit",
    "tests/test_cut4_r5_publication.py::test_resume_loads_same_plan",
    "tests/test_cut4_r5_publication.py::test_completed_exact_noop",
    "tests/test_cut4_r5_publication.py::test_completed_input_drift_requires_fresh_run",
    "tests/test_cut4_r5_publication.py::test_completed_normalizer_drift_requires_fresh_run",
    "tests/test_cut4_r5_publication.py::test_no_authorize_after_completed",
    "tests/test_cut4_r5_publication.py::test_no_manual_attempt_key",
    "tests/test_cut4_r5_publication.py::test_no_self_output_input",
    "tests/test_cut4_r5_publication.py::test_new_run_new_run_id_lineage"
  ],
  "compatibility": [
    "tests/test_cut4_r5_compat.py::test_path_mechanical_graph",
    "tests/test_cut4_r5_compat.py::test_path_mechanical_graph_generation",
    "tests/test_cut4_r5_compat.py::test_path_call_graph",
    "tests/test_cut4_r5_compat.py::test_path_caller_map",
    "tests/test_cut4_r5_compat.py::test_path_callee_map",
    "tests/test_cut4_r5_compat.py::test_path_state_read_map",
    "tests/test_cut4_r5_compat.py::test_path_state_write_map",
    "tests/test_cut4_r5_compat.py::test_path_function_summary",
    "tests/test_cut4_r5_compat.py::test_path_inheritance_tree",
    "tests/test_cut4_r5_compat.py::test_path_access_control_map",
    "tests/test_cut4_r5_compat.py::test_path_detector_findings",
    "tests/test_cut4_r5_compat.py::test_path_opengrep_sarif",
    "tests/test_cut4_r5_compat.py::test_path_opengrep_markdown",
    "tests/test_cut4_r5_compat.py::test_path_sec3_sarif",
    "tests/test_cut4_r5_compat.py::test_path_sec3_markdown",
    "tests/test_cut4_r5_compat.py::test_path_dependency_audit",
    "tests/test_cut4_r5_compat.py::test_path_tool_coverage_json",
    "tests/test_cut4_r5_compat.py::test_path_tool_coverage_markdown",
    "tests/test_cut4_r5_compat.py::test_path_slither_primitive_status",
    "tests/test_cut4_r5_compat.py::test_path_slither_function_summary",
    "tests/test_cut4_r5_compat.py::test_path_slither_call_graph",
    "tests/test_cut4_r5_compat.py::test_path_slither_inheritance_tree",
    "tests/test_cut4_r5_compat.py::test_path_slither_access_control_map",
    "tests/test_cut4_r5_compat.py::test_path_slither_detector_findings",
    "tests/test_cut4_r5_compat.py::test_path_scip_repo_map",
    "tests/test_cut4_r5_compat.py::test_path_scip_repo_map_full",
    "tests/test_cut4_r5_compat.py::test_path_scip_xref_map",
    "tests/test_cut4_r5_compat.py::test_path_scip_call_graph_p2p",
    "tests/test_cut4_r5_compat.py::test_path_scip_call_graph_consensus",
    "tests/test_cut4_r5_compat.py::test_path_scip_call_graph_execution",
    "tests/test_cut4_r5_compat.py::test_path_scip_type_hierarchy",
    "tests/test_cut4_r5_compat.py::test_path_scip_concurrency_inventory",
    "tests/test_cut4_r5_compat.py::test_path_scip_panic_sites",
    "tests/test_cut4_r5_compat.py::test_path_projection_manifest",
    "tests/test_cut4_r5_compat.py::test_path_projection_receipt",
    "tests/test_cut4_r5_compat.py::test_row_conservation",
    "tests/test_cut4_r5_compat.py::test_failure_debt_row",
    "tests/test_cut4_r5_compat.py::test_nonapplicable_neutral_row",
    "tests/test_cut4_r5_compat.py::test_unowned_projection_is_legacy",
    "tests/test_cut4_r5_compat.py::test_path_scip_go_index_query_safe",
    "tests/test_cut4_r5_compat.py::test_path_scip_rust_index_query_safe",
    "tests/test_cut4_r5_compat.py::test_no_public_cowriter"
  ],
  "consumer_source": [
    "tests/test_cut4_r5_consumers.py::test_c001_config_correctness_skill",
    "tests/test_cut4_r5_consumers.py::test_c002_consensus_safety_skill",
    "tests/test_cut4_r5_consumers.py::test_c003_cosmos_ibc_skill",
    "tests/test_cut4_r5_consumers.py::test_c004_cosmos_sdk_skill",
    "tests/test_cut4_r5_consumers.py::test_c005_cross_environment_skill",
    "tests/test_cut4_r5_consumers.py::test_c006_execution_client_skill",
    "tests/test_cut4_r5_consumers.py::test_c007_mempool_dos_skill",
    "tests/test_cut4_r5_consumers.py::test_c008_rpc_surface_skill",
    "tests/test_cut4_r5_consumers.py::test_c009_validator_lifecycle_skill",
    "tests/test_cut4_r5_consumers.py::test_c010_semantic_consistency_skill",
    "tests/test_cut4_r5_consumers.py::test_c011_plamen_command",
    "tests/test_cut4_r5_consumers.py::test_c012_plamen_l1_command",
    "tests/test_cut4_r5_consumers.py::test_c013_recall_build_plan_doc",
    "tests/test_cut4_r5_consumers.py::test_c014_internals_doc",
    "tests/test_cut4_r5_consumers.py::test_c015_aptos_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c016_aptos_depth_templates",
    "tests/test_cut4_r5_consumers.py::test_c017_aptos_v2_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c018_daml_depth_templates",
    "tests/test_cut4_r5_consumers.py::test_c019_daml_v2_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c020_daml_inventory_prompt",
    "tests/test_cut4_r5_consumers.py::test_c021_evm_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c022_evm_breadth_driver",
    "tests/test_cut4_r5_consumers.py::test_c023_evm_depth_driver",
    "tests/test_cut4_r5_consumers.py::test_c024_evm_depth_templates",
    "tests/test_cut4_r5_consumers.py::test_c025_evm_v2_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c026_l1_bake_prompt",
    "tests/test_cut4_r5_consumers.py::test_c027_l1_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c028_l1_breadth_driver",
    "tests/test_cut4_r5_consumers.py::test_c029_l1_depth_driver",
    "tests/test_cut4_r5_consumers.py::test_c030_l1_v2_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c031_shared_breadth_prompt",
    "tests/test_cut4_r5_consumers.py::test_c032_attention_repair_prompt",
    "tests/test_cut4_r5_consumers.py::test_c033_shared_depth_prompt",
    "tests/test_cut4_r5_consumers.py::test_c034_pipeline_full_audit_prompt",
    "tests/test_cut4_r5_consumers.py::test_c035_full_assessment_prompt",
    "tests/test_cut4_r5_consumers.py::test_c036_solana_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c037_solana_depth_templates",
    "tests/test_cut4_r5_consumers.py::test_c038_solana_v2_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c039_soroban_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c040_soroban_depth_templates",
    "tests/test_cut4_r5_consumers.py::test_c041_soroban_v2_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c042_sui_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c043_sui_depth_templates",
    "tests/test_cut4_r5_consumers.py::test_c044_sui_v2_recon_prompt",
    "tests/test_cut4_r5_consumers.py::test_c045_axis_disposition",
    "tests/test_cut4_r5_consumers.py::test_c046_chain_prep",
    "tests/test_cut4_r5_consumers.py::test_c047_codex_adapter",
    "tests/test_cut4_r5_consumers.py::test_c048_enumeration_gate",
    "tests/test_cut4_r5_consumers.py::test_c049_live_verify_adapter",
    "tests/test_cut4_r5_consumers.py::test_c050_phase_io_contracts",
    "tests/test_cut4_r5_consumers.py::test_c051_plamen_driver",
    "tests/test_cut4_r5_consumers.py::test_c052_plamen_mechanical",
    "tests/test_cut4_r5_consumers.py::test_c053_plamen_parsers",
    "tests/test_cut4_r5_consumers.py::test_c054_plamen_prompt",
    "tests/test_cut4_r5_consumers.py::test_c055_plamen_validators",
    "tests/test_cut4_r5_consumers.py::test_c056_recon_prepass",
    "tests/test_cut4_r5_consumers.py::test_c057_security_obligation_authority",
    "tests/test_cut4_r5_consumers.py::test_c058_semantic_invariant_authority",
    "tests/test_cut4_r5_consumers.py::test_c059_state_symbol_authority",
    "tests/test_cut4_r5_consumers.py::test_c060_tool_coverage_ledger",
    "tests/test_cut4_r5_consumers.py::test_c061_verification_method_compiler",
    "tests/test_cut4_r5_consumers.py::test_c062_depth_consensus_agent",
    "tests/test_cut4_r5_consumers.py::test_c063_depth_network_agent",
    "tests/test_cut4_r5_consumers.py::test_c064_l1_design_doc",
    "tests/test_cut4_r5_consumers.py::test_c065_l1_report_overrides",
    "tests/test_cut4_r5_consumers.py::test_c066_l1_verification_prompt",
    "tests/test_cut4_r5_consumers.py::test_c067_shared_report_index_prompt",
    "tests/test_cut4_r5_consumers.py::test_c068_plamen_types",
    "tests/test_cut4_r5_consumers.py::test_c069_scip_reader_indirect"
  ],
  "denominator": [
    "tests/test_cut4_r5_denominator.py::test_manifest_digest_binding",
    "tests/test_cut4_r5_denominator.py::test_receipt_digest_binding",
    "tests/test_cut4_r5_denominator.py::test_accepted_row_parity",
    "tests/test_cut4_r5_denominator.py::test_unresolved_debt_parity",
    "tests/test_cut4_r5_denominator.py::test_no_private_evidence_lost",
    "tests/test_cut4_r5_denominator.py::test_no_orphan_private_payload",
    "tests/test_cut4_r5_denominator.py::test_no_orphan_public_path",
    "tests/test_cut4_r5_denominator.py::test_opengrep_absent_not_vacuous",
    "tests/test_cut4_r5_denominator.py::test_function_summary_absent_not_vacuous",
    "tests/test_cut4_r5_denominator.py::test_graph_health_join",
    "tests/test_cut4_r5_denominator.py::test_chain_prep_join",
    "tests/test_cut4_r5_denominator.py::test_axis_disposition_join",
    "tests/test_cut4_r5_denominator.py::test_security_obligation_join",
    "tests/test_cut4_r5_denominator.py::test_state_symbol_join",
    "tests/test_cut4_r5_denominator.py::test_semantic_invariant_join",
    "tests/test_cut4_r5_denominator.py::test_instantiate_join",
    "tests/test_cut4_r5_denominator.py::test_breadth_join",
    "tests/test_cut4_r5_denominator.py::test_depth_join",
    "tests/test_cut4_r5_denominator.py::test_verification_join",
    "tests/test_cut4_r5_denominator.py::test_report_join"
  ],
  "existing": [
    "tests/test_cut4_r5_existing.py::test_legacy_empty",
    "tests/test_cut4_r5_existing.py::test_legacy_complete_unowned",
    "tests/test_cut4_r5_existing.py::test_legacy_partial",
    "tests/test_cut4_r5_existing.py::test_legacy_superset",
    "tests/test_cut4_r5_existing.py::test_legacy_transform_receipt",
    "tests/test_cut4_r5_existing.py::test_legacy_compatibility_projection",
    "tests/test_cut4_r5_existing.py::test_private_seed_complete",
    "tests/test_cut4_r5_existing.py::test_private_seed_partial",
    "tests/test_cut4_r5_existing.py::test_private_seed_extra",
    "tests/test_cut4_r5_existing.py::test_private_seed_orphan_payload",
    "tests/test_cut4_r5_existing.py::test_fresh_run_upgrade",
    "tests/test_cut4_r5_existing.py::test_postcommit_drift_fresh_run_required"
  ],
  "platform": [
    "tests/test_cut4_r5_platform.py::test_linux",
    "tests/test_cut4_r5_platform.py::test_macos",
    "tests/test_cut4_r5_platform.py::test_windows",
    "tests/test_cut4_r5_platform.py::test_provider_disabled",
    "tests/test_cut4_r5_platform.py::test_provider_timeout",
    "tests/test_cut4_r5_platform.py::test_provider_malformed",
    "tests/test_cut4_r5_platform.py::test_foundry_temp_overlay",
    "tests/test_cut4_r5_platform.py::test_no_project_root_mutation"
  ]
}
```

The roster is counted from this JSON object, not from prose. Each phase first
runs in isolation with unique system-temp roots, then the 316 nodes run as one
suite. The accepted V7 and R4 rosters run as predecessor regressions, not as
members of this count.
