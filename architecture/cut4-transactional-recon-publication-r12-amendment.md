# Cut-4 transactional recon publication R12 amendment

Date: 2026-08-10
Status: Part-0 R12 executable architecture repair only
Supersedes: only the three rejected clauses of the R11 amendment
Authority: design for independent review; all implementation, fixture, test,
provider, ArtifactLedger, G3, audit, commit, push, install, cutover, release,
and audit-readiness authority is false

## 0. Decision and immutable boundary

R12 repairs exactly R11-IR-01, R11-IR-02, and R11-IR-03. R1-R11 remain
immutable. In particular, R12 preserves the six authenticated source roots,
byte-covering document partition, post-edit S freeze, role/methodology
semantics, fixed provider roster and slots, sole DRIVER ownership, compatible
public projection, stable registered publication operation, legacy
non-adoption, private typed seed visibility, exact private-plan Kp, and all
accepted provider/applicability/selection rules. No public glob, provider
project-root write, canonical co-owner, conditional repair marker, manual
ledger row, dynamic slash key, or ArtifactLedger change is introduced.

The new exact RED roster in section 8 has 192 literal nodes. It replaces no
predecessor node and grants no authority to create those tests.

## 1. Authenticated repair input

The mandatory R11 independent REPAIR review was authenticated and read end to
end before authoring. It is 17,668 bytes and SHA-256
`f03f9040c5c58b3359433116cb82c69a7ae8f7dcae0d97cf6d9d7e41261993a6`:

`review_fixtures/cut4_transactional_recon_publication_r11_amendment_independent_review_20260810.md`.

The reviewed R11 amendment is 57,741 bytes and SHA-256
`6225b7e2ef0fe244168c66fc47dfe82634acad6fed079fb440cf8b4123c563bc`.
Its author receipt is 3,532 bytes and SHA-256
`85f802e2faab7701ff1b59b005bb2a286b579ee875c7982edc2447b7a0fff5a7`.
R12 accepts the review's locally accepted R11 clauses and does not reopen
them.

## 2. Common byte algebra and construction graph

Canonical JSON means RFC 8785 JSON encoded as UTF-8 without BOM. A canonical
file is those bytes plus exactly one LF. `H(d,x)` is lowercase hex SHA-256 of
`UTF8(d) || 0x00 || canonical_json(x)`. Ordinary `sha256(B)` hashes exactly B
without a domain. Arrays are ordered; sets never appear on disk. IDs, digests,
paths, enums, and strings use NFC. Integers are JSON integers in
`0..9007199254740991`. Byte payloads use unpadded RFC 4648 base64url.

The following is the complete dependency DAG for every R12 object. An edge
`[a,b]` means b may contain the ID/digest of a. No object may contain an ID or
digest of a node to its right in `topological_order`.

```json
{
  "schema": "cut4.r12.construction_dag.v1",
  "topological_order": [
    "source_file", "base_semantic", "graph_edge", "probe_plan",
    "probe_outcome", "probe_edge", "document_reference",
    "reach_denominator", "reach_plan", "document_candidate", "semantic_S",
    "base_request_intent", "request_digest", "generation_header",
    "attempt_allocation", "invocation_record", "payload_record",
    "provider_outcome", "normalized_semantic_row", "execution_evidence", "query_receipt",
    "terminal_envelope", "terminal_record", "publication_link",
    "provider_private_projection", "M4", "R4"
  ],
  "edges": [
    ["source_file", "base_semantic"],
    ["base_semantic", "graph_edge"],
    ["base_semantic", "probe_plan"],
    ["probe_plan", "probe_outcome"],
    ["probe_outcome", "probe_edge"],
    ["base_semantic", "probe_edge"],
    ["source_file", "document_reference"],
    ["document_reference", "reach_denominator"],
    ["graph_edge", "reach_denominator"],
    ["probe_edge", "reach_denominator"],
    ["base_semantic", "reach_denominator"],
    ["reach_denominator", "reach_plan"],
    ["reach_plan", "document_candidate"],
    ["document_candidate", "semantic_S"],
    ["base_request_intent", "request_digest"],
    ["request_digest", "generation_header"],
    ["request_digest", "attempt_allocation"],
    ["generation_header", "attempt_allocation"],
    ["attempt_allocation", "invocation_record"],
    ["request_digest", "invocation_record"],
    ["invocation_record", "payload_record"],
    ["invocation_record", "provider_outcome"],
    ["payload_record", "provider_outcome"],
    ["provider_outcome", "normalized_semantic_row"],
    ["payload_record", "normalized_semantic_row"],
    ["invocation_record", "execution_evidence"],
    ["payload_record", "execution_evidence"],
    ["provider_outcome", "execution_evidence"],
    ["execution_evidence", "query_receipt"],
    ["invocation_record", "query_receipt"],
    ["provider_outcome", "query_receipt"],
    ["invocation_record", "terminal_envelope"],
    ["payload_record", "terminal_envelope"],
    ["provider_outcome", "terminal_envelope"],
    ["normalized_semantic_row", "terminal_envelope"],
    ["execution_evidence", "terminal_envelope"],
    ["query_receipt", "terminal_envelope"],
    ["terminal_envelope", "terminal_record"],
    ["terminal_record", "publication_link"],
    ["payload_record", "provider_private_projection"],
    ["normalized_semantic_row", "provider_private_projection"],
    ["semantic_S", "M4"],
    ["provider_private_projection", "M4"],
    ["M4", "R4"]
  ]
}
```

The verifier parses this object, requires unique nodes, a total topological
rank, known endpoints, no self-edge, `rank(a)<rank(b)` for every edge, and a
zero result from Kahn's algorithm. It then rejects any serialized field whose
declared object dependency is absent from the edge set. The construction steps
below follow this order; no prose rule authorizes a forward reference.

## 3. Authenticated reach-source denominator

### 3.1 Source files and base semantic rows

The inherited frozen source-file registry covers exactly the recursive regular
files under `agents`, `commands`, `docs`, `plamen_l1`, `prompts`, and `scripts`,
with the inherited exclusions, containment rules, and byte digest. R12 first
projects every post-edit AST/callsite/dataflow classification into a base row.
It is not final S and cannot consume a reach result.

`BaseSemanticRow` fields, in order, are:

```text
schema=cut4.s.base_semantic_row.v1, base_semantic_row_id, source_file_id,
source_file_sha256, source_anchor_digest, semantic_class, consumer_id,
operation, exact_identity, direction, endpoint, required_phase_gate, probe_id,
producer_id, owner_kind, flow_edge_id, reach_source_mode,
declared_document_reach, reach_evidence_digest, multiplicity_key,
multiplicity_ordinal
```

`base_semantic_row_id = "bsr_" + H("cut4.s.base_semantic_row.v1",
row_without_base_semantic_row_id)`. It has a total FK to one source-file row;
the copied SHA must be byte-equal. Rows sort by all fields in schema order and
their array digest is `H("cut4.s.base_semantic_rows.v1",rows)`.
`reach_source_mode` is exactly `STATIC_EDGE`, `PROBE_REQUIRED`,
`NON_REACHING`, or `UNPROJECTABLE`. Static/unprojectable rows have nonempty
reach evidence and declared reach MODEL/TOOL/RUNTIME/CONTROL or UNRESOLVED;
probe-required rows declare UNRESOLVED with nonempty need-probe evidence;
non-reaching rows declare NONE with nonempty negative evidence. These base
rows are the reach-independent, authenticated source-semantic partition of
final S: final S must contain exactly one source semantic row whose source-row
subrecord is byte-equal to every BaseSemanticRow, and no source semantic row
without one. Thus `base_semantic_row_id` is a total final-S source-semantic FK,
not a provisional registry assertion.

### 3.2 Graph and probe source rows

A static graph match is one literal edge row:

```text
schema=cut4.s.reach_graph_edge.v1, graph_edge_id, base_semantic_row_id,
source_file_id, source_anchor_digest, semantic_class, consumer_id, operation,
exact_identity, document_reach, endpoint, required_phase_gate, probe_id,
flow_edge_id, reach_evidence_digest
```

Its `base_semantic_row_id` FK resolves exactly once. Every copied field
`source_file_id, source_anchor_digest, semantic_class, consumer_id, operation,
exact_identity, endpoint, required_phase_gate, probe_id, flow_edge_id` must be
byte-equal to the base row. Its reach and evidence equal the base row's
`declared_document_reach` and `reach_evidence_digest`. `document_reach` is the total semantic mapping:
MODEL for prompt/model input, TOOL for CLI/tool argument, RUNTIME for runtime
reader/dataflow, CONTROL for ownership/gate/prohibition, and UNRESOLVED with
typed debt when the classifier cannot choose. NONE is forbidden in a positive
edge. `graph_edge_id = "rge_" + H("cut4.s.reach_graph_edge.v1",
row_without_graph_edge_id)`.

Each required runtime/fixture observation first has a plan and then one
outcome; neither is ambient evidence:

```text
schema=cut4.s.reach_probe_plan.v1, probe_plan_row_id, base_semantic_row_id,
probe_id, probe_kind, consumer_id, operation, exact_identity,
required_phase_gate, input_snapshot_digests, bounded_limit

schema=cut4.s.reach_probe_outcome.v1, probe_outcome_row_id, probe_plan_row_id,
probe_status, observed_reach, observed_endpoint, observed_flow_edge_id,
evidence_bytes_sha256, evidence_byte_size, receipt_identity, receipt_digest

schema=cut4.s.reach_probe_edge.v1, probe_edge_id, probe_plan_row_id,
probe_outcome_row_id, base_semantic_row_id, source_file_id,
source_anchor_digest, semantic_class, consumer_id, operation, exact_identity,
document_reach, endpoint, required_phase_gate, probe_id, flow_edge_id,
reach_evidence_digest
```

`probe_status` is exactly `POSITIVE`, `NEGATIVE`, `DEBT`, `FAILURE`, `TIMEOUT`,
or `MALFORMED`. A positive outcome has a non-UNRESOLVED observed reach and
nonempty endpoint/flow/evidence/receipt. A negative outcome has empty observed
reach/endpoint/flow and nonempty evidence/receipt. Every other status has
`observed_reach=UNRESOLVED`, empty endpoint/flow, and nonempty typed evidence
and receipt. Plan, outcome, and edge IDs use respectively prefixes `rpp_`,
`rpo_`, `rpe_` and domains equal to their schema strings over row-without-ID.
The probe edge repeats plan/base fields byte-for-byte. POSITIVE copies observed
reach/endpoint/flow. DEBT/FAILURE/TIMEOUT/MALFORMED produces UNRESOLVED. A
NEGATIVE outcome produces no positive probe edge and participates in the
negative proof described below.

Rows use the following canonical keys:

```text
GraphKey=(exact_identity,document_reach,consumer_id,operation,endpoint,
          required_phase_gate,probe_id,base_semantic_row_id,graph_edge_id)
ProbeKey=(exact_identity,document_reach,consumer_id,operation,endpoint,
          required_phase_gate,probe_id,base_semantic_row_id,probe_edge_id)
```

The graph and probe arrays sort by these keys and digest with domains
`cut4.s.reach_graph_edges.v1` and `cut4.s.reach_probe_edges.v1`.

### 3.3 Closed row schemas

The following schema is normative. `Digest` is lowercase 64-hex; `Id` is
nonempty NFC without slash or NUL; `Reach` is closed.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r12.reach_rows.schema.v1",
  "$defs": {
    "Digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "Id": {"type": "string", "minLength": 1, "pattern": "^[^/\\u0000]+$"},
    "Reach": {"enum": ["NONE", "MODEL", "TOOL", "RUNTIME", "CONTROL", "UNRESOLVED"]},
    "BaseSemanticRow": {
      "type": "object", "additionalProperties": false,
      "required": ["schema","base_semantic_row_id","source_file_id","source_file_sha256","source_anchor_digest","semantic_class","consumer_id","operation","exact_identity","direction","endpoint","required_phase_gate","probe_id","producer_id","owner_kind","flow_edge_id","reach_source_mode","declared_document_reach","reach_evidence_digest","multiplicity_key","multiplicity_ordinal"],
      "properties": {
        "schema":{"const":"cut4.s.base_semantic_row.v1"}, "base_semantic_row_id":{"$ref":"#/$defs/Id"}, "source_file_id":{"$ref":"#/$defs/Id"}, "source_file_sha256":{"$ref":"#/$defs/Digest"}, "source_anchor_digest":{"$ref":"#/$defs/Digest"}, "semantic_class":{"type":"string","minLength":1}, "consumer_id":{"type":"string"}, "operation":{"type":"string"}, "exact_identity":{"type":"string"}, "direction":{"type":"string","minLength":1}, "endpoint":{"type":"string"}, "required_phase_gate":{"type":"string"}, "probe_id":{"type":"string"}, "producer_id":{"type":"string"}, "owner_kind":{"type":"string","minLength":1}, "flow_edge_id":{"type":"string"}, "reach_source_mode":{"enum":["STATIC_EDGE","PROBE_REQUIRED","NON_REACHING","UNPROJECTABLE"]}, "declared_document_reach":{"$ref":"#/$defs/Reach"}, "reach_evidence_digest":{"$ref":"#/$defs/Digest"}, "multiplicity_key":{"$ref":"#/$defs/Digest"}, "multiplicity_ordinal":{"type":"integer","minimum":0,"maximum":9007199254740991}
      }
    },
    "GraphEdgeRow": {
      "type":"object", "additionalProperties":false,
      "required":["schema","graph_edge_id","base_semantic_row_id","source_file_id","source_anchor_digest","semantic_class","consumer_id","operation","exact_identity","document_reach","endpoint","required_phase_gate","probe_id","flow_edge_id","reach_evidence_digest"],
      "properties":{"schema":{"const":"cut4.s.reach_graph_edge.v1"},"graph_edge_id":{"$ref":"#/$defs/Id"},"base_semantic_row_id":{"$ref":"#/$defs/Id"},"source_file_id":{"$ref":"#/$defs/Id"},"source_anchor_digest":{"$ref":"#/$defs/Digest"},"semantic_class":{"type":"string","minLength":1},"consumer_id":{"type":"string","minLength":1},"operation":{"type":"string","minLength":1},"exact_identity":{"type":"string","minLength":1},"document_reach":{"$ref":"#/$defs/Reach"},"endpoint":{"type":"string","minLength":1},"required_phase_gate":{"type":"string","minLength":1},"probe_id":{"type":"string"},"flow_edge_id":{"type":"string","minLength":1},"reach_evidence_digest":{"$ref":"#/$defs/Digest"}}
    },
    "ProbePlanRow": {
      "type":"object", "additionalProperties":false,
      "required":["schema","probe_plan_row_id","base_semantic_row_id","probe_id","probe_kind","consumer_id","operation","exact_identity","required_phase_gate","input_snapshot_digests","bounded_limit"],
      "properties":{"schema":{"const":"cut4.s.reach_probe_plan.v1"},"probe_plan_row_id":{"$ref":"#/$defs/Id"},"base_semantic_row_id":{"$ref":"#/$defs/Id"},"probe_id":{"$ref":"#/$defs/Id"},"probe_kind":{"enum":["RUNTIME","FIXTURE"]},"consumer_id":{"type":"string","minLength":1},"operation":{"type":"string","minLength":1},"exact_identity":{"type":"string","minLength":1},"required_phase_gate":{"type":"string","minLength":1},"input_snapshot_digests":{"type":"array","items":{"$ref":"#/$defs/Digest"}},"bounded_limit":{"type":"integer","minimum":1,"maximum":1000000}}
    },
    "ProbeOutcomeRow": {
      "type":"object", "additionalProperties":false,
      "required":["schema","probe_outcome_row_id","probe_plan_row_id","probe_status","observed_reach","observed_endpoint","observed_flow_edge_id","evidence_bytes_sha256","evidence_byte_size","receipt_identity","receipt_digest"],
      "properties":{"schema":{"const":"cut4.s.reach_probe_outcome.v1"},"probe_outcome_row_id":{"$ref":"#/$defs/Id"},"probe_plan_row_id":{"$ref":"#/$defs/Id"},"probe_status":{"enum":["POSITIVE","NEGATIVE","DEBT","FAILURE","TIMEOUT","MALFORMED"]},"observed_reach":{"type":"string"},"observed_endpoint":{"type":"string"},"observed_flow_edge_id":{"type":"string"},"evidence_bytes_sha256":{"$ref":"#/$defs/Digest"},"evidence_byte_size":{"type":"integer","minimum":0,"maximum":9007199254740991},"receipt_identity":{"$ref":"#/$defs/Id"},"receipt_digest":{"$ref":"#/$defs/Digest"}}
    },
    "ProbeEdgeRow": {
      "type":"object", "additionalProperties":false,
      "required":["schema","probe_edge_id","probe_plan_row_id","probe_outcome_row_id","base_semantic_row_id","source_file_id","source_anchor_digest","semantic_class","consumer_id","operation","exact_identity","document_reach","endpoint","required_phase_gate","probe_id","flow_edge_id","reach_evidence_digest"],
      "properties":{"schema":{"const":"cut4.s.reach_probe_edge.v1"},"probe_edge_id":{"$ref":"#/$defs/Id"},"probe_plan_row_id":{"$ref":"#/$defs/Id"},"probe_outcome_row_id":{"$ref":"#/$defs/Id"},"base_semantic_row_id":{"$ref":"#/$defs/Id"},"source_file_id":{"$ref":"#/$defs/Id"},"source_anchor_digest":{"$ref":"#/$defs/Digest"},"semantic_class":{"type":"string","minLength":1},"consumer_id":{"type":"string","minLength":1},"operation":{"type":"string","minLength":1},"exact_identity":{"type":"string","minLength":1},"document_reach":{"$ref":"#/$defs/Reach"},"endpoint":{"type":"string","minLength":1},"required_phase_gate":{"type":"string","minLength":1},"probe_id":{"$ref":"#/$defs/Id"},"flow_edge_id":{"type":"string"},"reach_evidence_digest":{"$ref":"#/$defs/Digest"}}
    },
    "ReachDenominatorRow": {
      "type":"object", "additionalProperties":false,
      "required":["schema","reach_denominator_row_id","document_reference_id","source_kind","source_row_id","base_semantic_row_id","source_file_id","source_anchor_digest","semantic_class","consumer_id","operation","exact_identity","document_reach","reach_resolution","endpoint","required_phase_gate","probe_id","flow_edge_id","reach_evidence_digest","debt_code"],
      "properties":{"schema":{"const":"cut4.s.reach_denominator_row.v1"},"reach_denominator_row_id":{"$ref":"#/$defs/Id"},"document_reference_id":{"$ref":"#/$defs/Id"},"source_kind":{"enum":["GRAPH","PROBE","PROVED_NONE","UNPROJECTABLE","UNRESOLVED_FALLBACK"]},"source_row_id":{"type":"string"},"base_semantic_row_id":{"type":"string"},"source_file_id":{"type":"string"},"source_anchor_digest":{"type":"string"},"semantic_class":{"type":"string"},"consumer_id":{"type":"string"},"operation":{"type":"string"},"exact_identity":{"type":"string","minLength":1},"document_reach":{"$ref":"#/$defs/Reach"},"reach_resolution":{"enum":["RESOLVED","PROVED_NONE","UNRESOLVED"]},"endpoint":{"type":"string"},"required_phase_gate":{"type":"string"},"probe_id":{"type":"string"},"flow_edge_id":{"type":"string"},"reach_evidence_digest":{"$ref":"#/$defs/Digest"},"debt_code":{"type":"string"}}
    }
  },
  "type":"object", "additionalProperties":false,
  "required":["base_semantic_rows","graph_edges","probe_plans","probe_outcomes","probe_edges","reach_denominator_rows"],
  "properties":{"base_semantic_rows":{"type":"array","items":{"$ref":"#/$defs/BaseSemanticRow"}},"graph_edges":{"type":"array","items":{"$ref":"#/$defs/GraphEdgeRow"}},"probe_plans":{"type":"array","items":{"$ref":"#/$defs/ProbePlanRow"}},"probe_outcomes":{"type":"array","items":{"$ref":"#/$defs/ProbeOutcomeRow"}},"probe_edges":{"type":"array","items":{"$ref":"#/$defs/ProbeEdgeRow"}},"reach_denominator_rows":{"type":"array","items":{"$ref":"#/$defs/ReachDenominatorRow"}}}
}
```

Conditional empty/nonempty rules stated in this section are additional schema
constraints and are tested byte-for-byte; JSON Schema shape validation is not
a substitute for the joins.

### 3.4 Edge selection and exact denominator

Before reference matching, the source rows themselves satisfy this exact
denominator. `G(b)` is the unique graph-row construction that copies b and
uses b's declared reach/evidence. `Q(b)` is the unique probe-plan construction;
`O(q)` is the unique authenticated outcome slot for q; and `E(q,o)` is the
unique probe edge for POSITIVE or nonnegative debt status. Then:

```text
multiset(graph_edges)
 = multiset(G(b) for b where mode in {STATIC_EDGE,UNPROJECTABLE})
multiset(probe_plans)
 = multiset(Q(b) for b where mode=PROBE_REQUIRED)
multiset(probe_outcomes by probe_plan_row_id)
 = multiset(exactly_one O(q) for q in probe_plans)
multiset(probe_edges)
 = multiset(E(q,O(q)) where O(q).status != NEGATIVE)

mode=NON_REACHING -> zero graph edges and zero probe plans
mode=STATIC_EDGE or UNPROJECTABLE -> exactly one graph edge and zero probe plans
mode=PROBE_REQUIRED -> zero graph edges and exactly one probe plan/outcome
```

Array byte equality, exact-one FKs, and copied-field equality enforce these
equations. Missing source edge/plan/outcome, extra source edge, duplicate
outcome, or a fabricated mode is blocking source-denominator debt before any
document reference is expanded.

Let `IdentityMatch(ref,edge)` mean both rows join the sealed identity registry,
their canonical identity bytes are equal, and their registered composition
component multiset is equal. Basename/fuzzy/text containment never matches.
Let `Live(e)` mean its base row belongs to the final six-root source snapshot,
its required gate is enabled, and its copied fields pass the FK equality. The
positive selector is exactly:

```text
Selected(ref,e) = IdentityMatch(ref,e) AND Live(e)
                  AND e.document_reach IN {MODEL,TOOL,RUNTIME,CONTROL}

Unprojectable(ref,e) = IdentityMatch(ref,e) AND e is authenticated
                       AND NOT safely representable as Selected(ref,e)
```

For each selected graph or probe edge there is exactly one denominator row.
It copies the reference identity and every source field byte-for-byte,
`source_kind` names the array, and `source_row_id` is its exact FK. For every
authenticated matching edge that is unprojectable there is exactly one
`source_kind=UNPROJECTABLE`, `document_reach=UNRESOLVED`,
`reach_resolution=UNRESOLVED`, nonempty source/base FKs and
`debt_code=UNPROJECTABLE_REACH_SOURCE_DEBT`. It is never discarded.

If a reference has no selected or unprojectable row, it receives exactly one
PROVED_NONE denominator row only when every applicable probe plan has a valid
NEGATIVE outcome and the sealed graph has no matching edge. Otherwise it gets
exactly one `source_kind=UNRESOLVED_FALLBACK` UNRESOLVED row with empty
source/base FKs and
`debt_code=UNRESOLVED_DOC_REACHABILITY_DEBT`. Even this fallback has nonempty
negative/debt evidence and retains the reference's exact identity.

`reach_denominator_row_id = "rdr_" +
H("cut4.s.reach_denominator_row.v1",row_without_id)`. Its key is:

```text
ReachKey=(document_reference_id,source_kind,source_row_id,base_semantic_row_id,
          document_reach,consumer_id,operation,endpoint,required_phase_gate,
          probe_id,flow_edge_id,reach_denominator_row_id)
```

Rows sort by `ReachKey`; the ordered multiset digest is
`H("cut4.s.reach_denominator_rows.v1",rows)`. Multiplicity is retained: two
authenticated source edges with otherwise equal copied fields remain two rows
because their source-row IDs differ.

Define `P_graph`, `P_probe`, `P_debt`, and `P_fallback` as the ordered row
projections above. The normative equations are:

```text
Expected = sort(P_graph(Selected graph edges)
              ++ P_probe(Selected probe edges)
              ++ P_debt(Unprojectable authenticated matching edges)
              ++ P_fallback(references with no prior projected row))
Observed = sort(reach_denominator_rows)

multiset(Observed) = multiset(Expected)
count(Observed) = count(Expected)
count_by(ReachKey,Observed) = count_by(ReachKey,Expected)

for each GRAPH row: exactly_one_fk(source_row_id,graph_edges)
for each PROBE row: exactly_one_fk(source_row_id,probe_edges)
for each row with base_semantic_row_id: exactly_one_fk(base_semantic_row_id,base_semantic_rows)
for each source FK: copied_fields(row) = copied_fields(source)
```

The omission set is `Expected - Observed`; fabrication is `Observed -
Expected`; duplicates are positive excess counts by ReachKey; orphans are
failed exact-one FKs. Any nonempty set blocks S sealing. The expected and
observed canonical bytes and their ordinary SHA-256 are retained in the diff
receipt; equality of only aggregate counts or hashes is insufficient.

Every denominator row projects one-to-one to the inherited R11 reach-plan,
candidate, and final S row, now with `reach_denominator_row_id` replacing the
unauthenticated reach-source ID. Exact equations are:

```text
multiset(ReachKey from denominator)
 = multiset(ReachKey from reach plans)
 = multiset(ReachKey from recognized candidates)
 = multiset(ReachKey from final S semantic rows)
 = multiset(ReachKey from independent rescan/runtime observations)
```

The reach denominator rows/digest, graph rows/digest, probe plan/outcome/edge
rows/digests, and base semantic rows/digest are explicit S v5 fields. P0, D,
M4, and R4 bind the rederived S v5 identity. UNRESOLVED remains typed blocking
debt, not evidence success. Thus a found reach cannot be lost and a fabricated
writer cannot enter the denominator unnoticed.

## 4. Acyclic request and immutable generation records

### 4.1 Staged query objects

The exact closed schemas below are constructed only in their DAG order.

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"cut4.r12.query_stages.schema.v1",
  "$defs":{
    "Digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
    "Id":{"type":"string","minLength":1,"pattern":"^[^/\\u0000]+$"},
    "StringArray":{"type":"array","items":{"type":"string"}},
    "BaseRequestIntent":{
      "type":"object","additionalProperties":false,
      "required":["schema","consumer_row_id","query_id","query_input_digest","query_session_preimage_digest","prior_envelope_binding","cursor_in","page_size","result_limit","timeout_ms","argv","argv_digest","project_snapshot_digest","provider_plan_digest"],
      "properties":{"schema":{"const":"cut4.query.base_request_intent.v1"},"consumer_row_id":{"$ref":"#/$defs/Id"},"query_id":{"$ref":"#/$defs/Id"},"query_input_digest":{"$ref":"#/$defs/Digest"},"query_session_preimage_digest":{"$ref":"#/$defs/Digest"},"prior_envelope_binding":{"type":"object","additionalProperties":false,"required":["phaseio_output_identity","file_size","file_sha256","canonical_envelope_digest"],"properties":{"phaseio_output_identity":{"type":"string"},"file_size":{"type":"integer","minimum":0,"maximum":9007199254740991},"file_sha256":{"type":"string"},"canonical_envelope_digest":{"type":"string"}}},"cursor_in":{"type":"string"},"page_size":{"type":"integer","minimum":1,"maximum":10000},"result_limit":{"type":"integer","minimum":1,"maximum":1000000},"timeout_ms":{"type":"integer","minimum":1,"maximum":3600000},"argv":{"$ref":"#/$defs/StringArray"},"argv_digest":{"$ref":"#/$defs/Digest"},"project_snapshot_digest":{"$ref":"#/$defs/Digest"},"provider_plan_digest":{"$ref":"#/$defs/Digest"}}
    },
    "AttemptAllocation":{
      "type":"object","additionalProperties":false,
      "required":["schema","request_digest","generation_id","allocation_ordinal","previous_record_digest","attempt_id"],
      "properties":{"schema":{"const":"cut4.query.attempt_allocation.v1"},"request_digest":{"$ref":"#/$defs/Digest"},"generation_id":{"$ref":"#/$defs/Id"},"allocation_ordinal":{"type":"integer","minimum":0,"maximum":9007199254740991},"previous_record_digest":{"type":"string"},"attempt_id":{"$ref":"#/$defs/Id"}}
    },
    "InvocationRecord":{
      "type":"object","additionalProperties":false,
      "required":["schema","request_digest","attempt_id","attempt_allocation_digest","provider_id","tool_id","tool_version","tool_configuration_digest","immutable_input_digests","timeout_ms","argv_digest","invocation_digest"],
      "properties":{"schema":{"const":"cut4.query.invocation_record.v1"},"request_digest":{"$ref":"#/$defs/Digest"},"attempt_id":{"$ref":"#/$defs/Id"},"attempt_allocation_digest":{"$ref":"#/$defs/Digest"},"provider_id":{"$ref":"#/$defs/Id"},"tool_id":{"$ref":"#/$defs/Id"},"tool_version":{"type":"string","minLength":1},"tool_configuration_digest":{"$ref":"#/$defs/Digest"},"immutable_input_digests":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/Digest"}},"timeout_ms":{"type":"integer","minimum":1,"maximum":3600000},"argv_digest":{"$ref":"#/$defs/Digest"},"invocation_digest":{"$ref":"#/$defs/Digest"}}
    },
    "ExecutionEvidence":{
      "type":"object","additionalProperties":false,
      "required":["schema","execution_evidence_identity","request_digest","attempt_id","invocation_digest","provider_outcome_row_id","provider_outcome_digest","payload_records_digest","tool_exit_class","elapsed_bound_class","stdout_sha256","stderr_sha256","execution_evidence_digest"],
      "properties":{"schema":{"const":"cut4.query.execution_evidence.v1"},"execution_evidence_identity":{"$ref":"#/$defs/Id"},"request_digest":{"$ref":"#/$defs/Digest"},"attempt_id":{"$ref":"#/$defs/Id"},"invocation_digest":{"$ref":"#/$defs/Digest"},"provider_outcome_row_id":{"$ref":"#/$defs/Id"},"provider_outcome_digest":{"$ref":"#/$defs/Digest"},"payload_records_digest":{"$ref":"#/$defs/Digest"},"tool_exit_class":{"enum":["ZERO","NONZERO","TIMEOUT","NOT_RUN"]},"elapsed_bound_class":{"enum":["WITHIN_BOUND","BOUND_EXCEEDED","NOT_RUN"]},"stdout_sha256":{"$ref":"#/$defs/Digest"},"stderr_sha256":{"$ref":"#/$defs/Digest"},"execution_evidence_digest":{"$ref":"#/$defs/Digest"}}
    },
    "QueryReceipt":{
      "type":"object","additionalProperties":false,
      "required":["schema","query_receipt_identity","request_digest","attempt_id","invocation_digest","provider_outcome_row_id","provider_outcome_digest","execution_evidence_identity","execution_evidence_digest","terminal_status","cursor_in","cursor_out","exhausted","query_receipt_digest"],
      "properties":{"schema":{"const":"cut4.query.receipt.v1"},"query_receipt_identity":{"$ref":"#/$defs/Id"},"request_digest":{"$ref":"#/$defs/Digest"},"attempt_id":{"$ref":"#/$defs/Id"},"invocation_digest":{"$ref":"#/$defs/Digest"},"provider_outcome_row_id":{"$ref":"#/$defs/Id"},"provider_outcome_digest":{"$ref":"#/$defs/Digest"},"execution_evidence_identity":{"$ref":"#/$defs/Id"},"execution_evidence_digest":{"$ref":"#/$defs/Digest"},"terminal_status":{"enum":["SUCCESS","SUCCESS_EMPTY","PARTIAL","NOT_APPLICABLE","DEBT","FAILURE","TIMEOUT","MALFORMED"]},"cursor_in":{"type":"string"},"cursor_out":{"type":"string"},"exhausted":{"type":"boolean"},"query_receipt_digest":{"$ref":"#/$defs/Digest"}}
    },
    "TerminalEnvelope":{
      "type":"object","additionalProperties":false,
      "required":["schema","request_digest","attempt_id","invocation_digest","provider_outcome_row_id","provider_outcome_digest","terminal_status","cursor_in","cursor_out","exhausted","payload_record_ids","payload_records_digest","normalized_semantic_row_ids","normalized_semantic_rows_digest","execution_evidence_identity","execution_evidence_digest","query_receipt_identity","query_receipt_digest","terminal_envelope_digest"],
      "properties":{"schema":{"const":"cut4.query.terminal_envelope.v1"},"request_digest":{"$ref":"#/$defs/Digest"},"attempt_id":{"$ref":"#/$defs/Id"},"invocation_digest":{"$ref":"#/$defs/Digest"},"provider_outcome_row_id":{"$ref":"#/$defs/Id"},"provider_outcome_digest":{"$ref":"#/$defs/Digest"},"terminal_status":{"enum":["SUCCESS","SUCCESS_EMPTY","PARTIAL","NOT_APPLICABLE","DEBT","FAILURE","TIMEOUT","MALFORMED"]},"cursor_in":{"type":"string"},"cursor_out":{"type":"string"},"exhausted":{"type":"boolean"},"payload_record_ids":{"type":"array","items":{"$ref":"#/$defs/Id"}},"payload_records_digest":{"$ref":"#/$defs/Digest"},"normalized_semantic_row_ids":{"type":"array","items":{"$ref":"#/$defs/Id"}},"normalized_semantic_rows_digest":{"$ref":"#/$defs/Digest"},"execution_evidence_identity":{"$ref":"#/$defs/Id"},"execution_evidence_digest":{"$ref":"#/$defs/Digest"},"query_receipt_identity":{"$ref":"#/$defs/Id"},"query_receipt_digest":{"$ref":"#/$defs/Digest"},"terminal_envelope_digest":{"$ref":"#/$defs/Digest"}}
    }
  },
  "type":"object","additionalProperties":false,
  "required":["base_request_intent","attempt_allocation","invocation_record","execution_evidence","query_receipt","terminal_envelope"],
  "properties":{"base_request_intent":{"$ref":"#/$defs/BaseRequestIntent"},"attempt_allocation":{"$ref":"#/$defs/AttemptAllocation"},"invocation_record":{"$ref":"#/$defs/InvocationRecord"},"execution_evidence":{"$ref":"#/$defs/ExecutionEvidence"},"query_receipt":{"$ref":"#/$defs/QueryReceipt"},"terminal_envelope":{"$ref":"#/$defs/TerminalEnvelope"}}
}
```

`BaseRequestIntent` is serialized first. It contains only user/query/session,
prior-envelope, cursor/limit, provider-plan, project-input, and argv/config
authority. The field names `request_digest`, `attempt_id`, `invocation_digest`,
evidence/receipt IDs, terminal IDs, and journal IDs are forbidden anywhere in
that object. Then:

```text
request_digest = H("cut4.query.base_request_intent.v1",BaseRequestIntent)

attempt_id = "qat_" + H("cut4.query.attempt_id.v1",
  [request_digest,generation_id,allocation_ordinal,previous_record_digest])
attempt_allocation_digest = H("cut4.query.attempt_allocation.v1",
                              AttemptAllocation)

invocation_digest = H("cut4.query.invocation_record.v1",
                      InvocationRecord without invocation_digest)
```

The provider/tool configuration and exact registered immutable PhaseIO input
digests enter only `InvocationRecord`; there is no nonexistent LaunchSpec
configuration field. Execution evidence is constructed from the invocation,
provider outcome, and payload roster. The query receipt is constructed from
that evidence and outcome. Neither contains terminal-envelope or record
identity. Their exact formulas are:

```text
execution_evidence_digest = H("cut4.query.execution_evidence.v1",
  ExecutionEvidence without execution_evidence_identity and execution_evidence_digest)
execution_evidence_identity = "qev_" + H("cut4.query.execution_evidence_id.v1",
  [request_digest,attempt_id,invocation_digest,execution_evidence_digest])
query_receipt_digest = H("cut4.query.receipt.v1",
  QueryReceipt without query_receipt_identity and query_receipt_digest)
query_receipt_identity = "qrc_" + H("cut4.query.receipt_id.v1",
  [request_digest,attempt_id,invocation_digest,query_receipt_digest])
```

Finally:

```text
terminal_envelope_digest = H("cut4.query.terminal_envelope.v1",
                             TerminalEnvelope without terminal_envelope_digest)
```

No staged object contains a downstream ID. The provider process receives the
sealed invocation object; it cannot allocate an attempt, choose an ordinal, or
write a record.

### 4.2 Registered private generation work unit

The existing stable canonical-publication successor consumes terminal bytes;
R12 does not re-arm a completed key. The private durable precursor is a new
registered PhaseIO operation `recon_query_terminal_generation_v1` with work
unit `DRIVER_RECON_QUERY_TERMINAL_GENERATION_V1`, producer/owner DRIVER, and
private output identity `private/query-terminal-generations.v1`. This fixed
identity is a registered immutable output, not a dynamic ledger key. Its
sealed root is:

```text
<scratchpad>/.phaseio-private/query-terminal-generations.v1/
  <namespace_digest>/gen-<generation_ordinal_20>-<generation_id>/
```

`namespace_digest = H("cut4.query.generation_namespace.v1",
[run_id,consumer_row_id,query_id,query_input_digest,query_session_preimage_digest])`.
No component comes from raw user text. The resolver rejects symlink, junction,
reparse point, alternate-data-stream, nonregular committed file, case-fold
alias, or resolved escape before any mutation. One DRIVER lease, scoped to the
fixed registered work unit plus namespace digest, serializes scan and create;
providers and MODEL workers have read-only or no access as declared by their
PhaseIO bindings.

The generation and record schemas are closed:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"cut4.r12.generation_records.schema.v1",
  "$defs":{
    "Digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
    "Id":{"type":"string","minLength":1,"pattern":"^[^/\\u0000]+$"},
    "GenerationHeader":{
      "type":"object","additionalProperties":false,
      "required":["schema","namespace_digest","request_digest","generation_ordinal","generation_id","parent_generation_id","parent_valid_head_digest","sealed_invalid_file_facts_digest","created_by_operation"],
      "properties":{"schema":{"const":"cut4.query.generation_header.v1"},"namespace_digest":{"$ref":"#/$defs/Digest"},"request_digest":{"$ref":"#/$defs/Digest"},"generation_ordinal":{"type":"integer","minimum":0,"maximum":9007199254740991},"generation_id":{"$ref":"#/$defs/Id"},"parent_generation_id":{"type":"string"},"parent_valid_head_digest":{"type":"string"},"sealed_invalid_file_facts_digest":{"$ref":"#/$defs/Digest"},"created_by_operation":{"const":"recon_query_terminal_generation_v1"}}
    },
    "RecordBody":{
      "type":"object","additionalProperties":false,
      "required":["schema","kind","request_digest","attempt_id","object_identity","object_digest","object_byte_size","object_bytes_sha256","object_bytes_base64url"],
      "properties":{"schema":{"const":"cut4.query.generation_record_body.v1"},"kind":{"enum":["ATTEMPT_ALLOCATION","INVOCATION","ABORTED_UNOBSERVED","TERMINAL_ENVELOPE","PUBLICATION_LINK"]},"request_digest":{"$ref":"#/$defs/Digest"},"attempt_id":{"type":"string"},"object_identity":{"$ref":"#/$defs/Id"},"object_digest":{"$ref":"#/$defs/Digest"},"object_byte_size":{"type":"integer","minimum":1,"maximum":9007199254740991},"object_bytes_sha256":{"$ref":"#/$defs/Digest"},"object_bytes_base64url":{"type":"string"}}
    },
    "GenerationRecord":{
      "type":"object","additionalProperties":false,
      "required":["schema","generation_id","record_ordinal","previous_record_digest","previous_file_byte_size","previous_file_sha256","body","body_digest","record_digest"],
      "properties":{"schema":{"const":"cut4.query.generation_record.v1"},"generation_id":{"$ref":"#/$defs/Id"},"record_ordinal":{"type":"integer","minimum":0,"maximum":9007199254740991},"previous_record_digest":{"type":"string"},"previous_file_byte_size":{"type":"integer","minimum":0,"maximum":9007199254740991},"previous_file_sha256":{"type":"string"},"body":{"$ref":"#/$defs/RecordBody"},"body_digest":{"$ref":"#/$defs/Digest"},"record_digest":{"$ref":"#/$defs/Digest"}}
    },
    "InvalidFileFact":{
      "type":"object","additionalProperties":false,
      "required":["schema","projected_relative_path","file_byte_size","file_sha256","classification"],
      "properties":{"schema":{"const":"cut4.query.invalid_file_fact.v1"},"projected_relative_path":{"type":"string","minLength":1},"file_byte_size":{"type":"integer","minimum":0,"maximum":9007199254740991},"file_sha256":{"$ref":"#/$defs/Digest"},"classification":{"enum":["INCOMPLETE_TEMP","INVALID_COMMITTED","ALIAS","NONREGULAR"]}}
    }
  },
  "type":"object","additionalProperties":false,
  "required":["generation_header","records","invalid_file_facts"],
  "properties":{"generation_header":{"$ref":"#/$defs/GenerationHeader"},"records":{"type":"array","items":{"$ref":"#/$defs/GenerationRecord"}},"invalid_file_facts":{"type":"array","items":{"$ref":"#/$defs/InvalidFileFact"}}}
}
```

`generation_id = "qgen_" + H("cut4.query.generation_header.v1",
header_without_generation_id)`. Header bytes are canonical JSON+LF in
`00000000000000000000-header-<generation_id>.json`. For a record:

```text
body_digest = H("cut4.query.generation_record_body.v1",body)
record_digest = H("cut4.query.generation_record.v1",record_without_record_digest)
committed_name = ordinal20 + "-" + record_digest + ".json"
```

`object_byte_size`, ordinary object SHA, and base64url must decode to exactly
the canonical bytes of the named staged object and recompute its domain
digest. Record-file bytes are canonical JSON+LF; the next record repeats the
prior committed file's exact length and ordinary SHA. Ordinals are contiguous
after header, names and bodies agree, and the digest chain is exact.

### 4.3 Filesystem commit, CAS, and recovery

Under the lease, DRIVER rescans and authenticates the whole namespace. It
creates a same-directory temporary file named
`.tmp-<ordinal20>-<attempt_id>-<record_digest>` with create-new/O_EXCL, writes
all bytes, flushes the file, and atomically renames with no-replace semantics
to the committed name, then flushes the directory. On Windows this is a
fail-if-exists atomic move; on POSIX it is rename-no-replace. A platform that
cannot prove those semantics emits `GENERATION_ATOMICITY_DEBT` and makes no
provider call or public commit.

A temporary file is never a record. Recovery hashes it into an
`INCOMPLETE_TEMP` fact, reports debt, and ignores it when finding the valid
head. It is not deleted or reused by the protocol. A malformed/hash-bad/
noncontiguous committed file seals that generation at the preceding valid
head. DRIVER creates exactly one next generation whose header ordinal is old
plus one, whose parent IDs/digest name that valid head, and whose
`sealed_invalid_file_facts_digest` is
`H("cut4.query.invalid_file_facts.v1",sorted_facts)`. No old byte is truncated,
overwritten, or adopted.

Generation creation is the namespace CAS: its header path uses create-new and
its header binds the authenticated prior generation/head/facts. If a same-path
winner exists, the loser rereads; byte-equal header means success, otherwise
`GENERATION_CAS_CONFLICT_DEBT`. Record creation is the ordinal CAS: an existing
committed ordinal is accepted only if filename, canonical bytes, digest, and
the requested staged object are byte-equal; otherwise it conflicts. The lease
plus both CAS rules serialize identical and distinct requests without a
mutable head file.

Every committed record has exactly one registered namespace/generation and
one prior valid head. Every generation except ordinal zero has exactly one
parent; parent ordinals decrease, so cycles are impossible. Orphan generation,
record, publication link, temp alias, duplicate ordinal, skipped ordinal, or
unregistered path is blocking typed debt. Recovery never uses glob discovery
as authority: it enumerates the exact registered root and validates every
direct child against the closed name grammar; an unexpected child is debt.

### 4.4 Total attempt and replay transitions

Construction order per new attempt is allocation record, invocation record,
provider call, evidence/receipt, terminal envelope, terminal record, then
publication link. A terminal record is durable before any public/consumer
PhaseIO commit.

| observed durable state | only legal action |
|---|---|
| no allocation for request | allocate next ordinal and attempt ID |
| allocation, no invocation | append ABORTED_UNOBSERVED; allocate a new attempt |
| invocation, no terminal | append ABORTED_UNOBSERVED; allocate a new attempt |
| temp only | record temp debt; do not treat it as terminal; new generation/attempt |
| invalid committed tail | seal generation; new generation/attempt |
| valid terminal, no publication link | replay exact journaled envelope bytes to successor publication |
| valid terminal and publication link, public bytes equal | exact no-op replay |
| valid terminal and publication link, public bytes absent | replay exact journaled bytes |
| valid terminal and public bytes differ | PUBLICATION_RECONCILIATION_DEBT; no overwrite |

ABORTED_UNOBSERVED is not a provider terminal status and has empty provider
payload/evidence/receipt. Its object commits the abandoned allocation and
invocation if present. A new attempt uses the next allocation ordinal and a
different attempt ID. SUCCESS, SUCCESS_EMPTY, PARTIAL, NOT_APPLICABLE, DEBT,
FAILURE, TIMEOUT, and MALFORMED all require a durable terminal envelope;
TIMEOUT has exact invocation/timeout evidence and empty cursor out. Only
SUCCESS/PARTIAL may carry nonempty cursor out; exhausted terminal pages carry
empty cursor out and reject later continuation. Identical cursor-in requests
after a terminal record return the exact stored terminal bytes; providers are
never reinvoked. Crash after provider return but before terminal commit remains
unobserved and becomes a distinct attempt; no byte-identical claim is made.

## 5. Exact payload and normalized semantic commitments

### 5.1 Closed data schemas

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"cut4.r12.payload_semantic.schema.v1",
  "$defs":{
    "Digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
    "Id":{"type":"string","minLength":1,"pattern":"^[^/\\u0000]+$"},
    "NormalizedField":{
      "type":"object","additionalProperties":false,
      "required":["schema","name","value_type","string_value","integer_value","boolean_value","string_array_value"],
      "properties":{"schema":{"const":"cut4.private.normalized_field.v1"},"name":{"type":"string","minLength":1},"value_type":{"enum":["STRING","INTEGER","BOOLEAN","STRING_ARRAY"]},"string_value":{"type":"string"},"integer_value":{"type":"integer","minimum":-9007199254740991,"maximum":9007199254740991},"boolean_value":{"type":"boolean"},"string_array_value":{"type":"array","items":{"type":"string"}}}
    },
    "PayloadRecord":{
      "type":"object","additionalProperties":false,
      "required":["schema","payload_id","provider_id","private_plan_row_id","invocation_digest","payload_ordinal","content_type","byte_size","raw_sha256","raw_base64url","payload_digest"],
      "properties":{"schema":{"const":"cut4.private.payload_record.v1"},"payload_id":{"$ref":"#/$defs/Id"},"provider_id":{"$ref":"#/$defs/Id"},"private_plan_row_id":{"$ref":"#/$defs/Id"},"invocation_digest":{"$ref":"#/$defs/Digest"},"payload_ordinal":{"type":"integer","minimum":0,"maximum":9007199254740991},"content_type":{"enum":["APPLICATION_JSON","TEXT_MARKDOWN","TEXT_PLAIN","APPLICATION_OCTET_STREAM"]},"byte_size":{"type":"integer","minimum":0,"maximum":9007199254740991},"raw_sha256":{"$ref":"#/$defs/Digest"},"raw_base64url":{"type":"string"},"payload_digest":{"$ref":"#/$defs/Digest"}}
    },
    "ProviderOutcomeRow":{
      "type":"object","additionalProperties":false,
      "required":["schema","provider_outcome_row_id","private_plan_row_id","consumer_row_id","provider_id","invocation_digest","applicability_predicate_id","selection_predicate_id","status","payload_records","payload_records_digest","explicit_zero_proof_digest","provider_receipt_identity","provider_receipt_digest","provider_outcome_digest"],
      "properties":{"schema":{"const":"cut4.provider_outcome_row.v3"},"provider_outcome_row_id":{"$ref":"#/$defs/Id"},"private_plan_row_id":{"$ref":"#/$defs/Id"},"consumer_row_id":{"$ref":"#/$defs/Id"},"provider_id":{"$ref":"#/$defs/Id"},"invocation_digest":{"$ref":"#/$defs/Digest"},"applicability_predicate_id":{"$ref":"#/$defs/Id"},"selection_predicate_id":{"$ref":"#/$defs/Id"},"status":{"enum":["NOT_APPLICABLE","NOT_SELECTED","SUCCESS","FAILURE","TIMEOUT","MALFORMED"]},"payload_records":{"type":"array","items":{"$ref":"#/$defs/PayloadRecord"}},"payload_records_digest":{"$ref":"#/$defs/Digest"},"explicit_zero_proof_digest":{"type":"string"},"provider_receipt_identity":{"$ref":"#/$defs/Id"},"provider_receipt_digest":{"$ref":"#/$defs/Digest"},"provider_outcome_digest":{"$ref":"#/$defs/Digest"}}
    },
    "NormalizedSemanticRow":{
      "type":"object","additionalProperties":false,
      "required":["schema","normalized_semantic_row_id","private_plan_row_id","consumer_row_id","consumer_id","provider_id","provider_outcome_row_id","applicability_predicate_id","selection_predicate_id","target_identity","scope_id","flow_instance_id","multiplicity_key","multiplicity_ordinal","payload_id","payload_digest","normalizer_id","normalizer_version","semantic_kind","normalized_identity","normalized_fields","normalized_fields_digest","source_snapshot_digest","normalized_semantic_digest"],
      "properties":{"schema":{"const":"cut4.private.normalized_semantic_row.v1"},"normalized_semantic_row_id":{"$ref":"#/$defs/Id"},"private_plan_row_id":{"$ref":"#/$defs/Id"},"consumer_row_id":{"$ref":"#/$defs/Id"},"consumer_id":{"$ref":"#/$defs/Id"},"provider_id":{"$ref":"#/$defs/Id"},"provider_outcome_row_id":{"$ref":"#/$defs/Id"},"applicability_predicate_id":{"$ref":"#/$defs/Id"},"selection_predicate_id":{"$ref":"#/$defs/Id"},"target_identity":{"type":"string","minLength":1},"scope_id":{"type":"string","minLength":1},"flow_instance_id":{"type":"string","minLength":1},"multiplicity_key":{"$ref":"#/$defs/Digest"},"multiplicity_ordinal":{"type":"integer","minimum":0,"maximum":9007199254740991},"payload_id":{"$ref":"#/$defs/Id"},"payload_digest":{"$ref":"#/$defs/Digest"},"normalizer_id":{"$ref":"#/$defs/Id"},"normalizer_version":{"type":"string","minLength":1},"semantic_kind":{"enum":["SOURCE_NODE","SOURCE_EDGE","DEPENDENCY_UNIT","CONFIGURATION_FACT","PROVIDER_FACT","DEBT_FACT"]},"normalized_identity":{"type":"string","minLength":1},"normalized_fields":{"type":"array","items":{"$ref":"#/$defs/NormalizedField"}},"normalized_fields_digest":{"$ref":"#/$defs/Digest"},"source_snapshot_digest":{"$ref":"#/$defs/Digest"},"normalized_semantic_digest":{"$ref":"#/$defs/Digest"}}
    }
  },
  "type":"object","additionalProperties":false,
  "required":["payload_records","provider_outcomes","normalized_semantic_rows"],
  "properties":{"payload_records":{"type":"array","items":{"$ref":"#/$defs/PayloadRecord"}},"provider_outcomes":{"type":"array","items":{"$ref":"#/$defs/ProviderOutcomeRow"}},"normalized_semantic_rows":{"type":"array","items":{"$ref":"#/$defs/NormalizedSemanticRow"}}}
}
```

For a payload byte string B:

```text
payload_digest = H("cut4.private.payload_bytes.v1",
  {"byte_size":len(B),"raw_sha256":sha256(B),"raw_base64url":base64url(B)})
payload_id = "pay_" + H("cut4.private.payload_record_id.v1",
  [provider_id,private_plan_row_id,invocation_digest,payload_ordinal,
   content_type,len(B),sha256(B),payload_digest])
```

`raw_base64url` must decode to exactly B; size, SHA, and digest must recompute.
Payload ordinals for an outcome are contiguous from zero and rows sort by
`(private_plan_row_id,provider_id,invocation_digest,payload_ordinal,
payload_id)`. `payload_records_digest =
H("cut4.private.payload_records.v1",ordered_rows)` is nonrecursive: the data
rows do not include the aggregate digest or terminal/manifest/receipt IDs.

The provider receipt identity and digest are constructed from invocation,
status, exact payload rows/digest, predicate IDs, and evidence, but contain no
provider-outcome ID/digest. The ProviderOutcomeRow is then constructed:

```text
provider_outcome_digest = H("cut4.provider_outcome_row.v3",
  ProviderOutcomeRow without provider_outcome_row_id and provider_outcome_digest)
provider_outcome_row_id = "por_" + H("cut4.provider_outcome_row_id.v3",
  [private_plan_row_id,provider_id,invocation_digest,provider_outcome_digest])
```

The provider outcome embeds the exact ordered PayloadRecord array and its
digest, not only IDs. SUCCESS may use zero or more records; zero requires
the inherited non-vacuous explicit-zero proof. NOT_APPLICABLE, NOT_SELECTED,
FAILURE, TIMEOUT, and MALFORMED require the empty array and
`H("cut4.private.payload_records.v1",[])`. Partial provider data is retained
only under its inherited typed debt status and still participates in equality.

Each provider-private row repeats one full PayloadRecord plus its expanded Kp.
Define:

```text
PayloadTuple=(private_plan_row_id,provider_id,invocation_digest,
              payload_ordinal,payload_id,content_type,byte_size,raw_sha256,
              payload_digest,raw_base64url)

sort(pi_payload_outcome(outcomes))
 = sort(PayloadTuple for every embedded PayloadRecord)
sort(pi_payload_private(provider_private_rows))
 = sort(PayloadTuple for every repeated PayloadRecord)
```

The ordered arrays must be byte-equal. Missing, extra, ordinal, payload-ID,
content-type, size, raw-SHA, payload-digest, and raw-bytes mismatches produce
respectively `PAYLOAD_MISSING`, `PAYLOAD_EXTRA`, `PAYLOAD_ORDINAL_MISMATCH`,
`PAYLOAD_ID_MISMATCH`, `PAYLOAD_CONTENT_TYPE_MISMATCH`,
`PAYLOAD_SIZE_MISMATCH`, `PAYLOAD_SHA_MISMATCH`,
`PAYLOAD_DIGEST_MISMATCH`, and `PAYLOAD_BYTES_MISMATCH`. Expected side is the
provider outcome embedded row; observed side is provider-private. Both sides
use the inherited exact diff-side bytes and expanded Kp; an empty side uses
the inherited typed empty digest. Every payload is embedded in exactly one
provider outcome matching its plan/provider/invocation and, for provider states
requiring private rows, has exactly one provider-private FK. This staged
construction eliminates the payload/outcome self-cycle.

### 5.2 Normalized semantic rows

A `NormalizedField` array sorts by `(name,value_type,canonical row bytes)` and
has unique names. Exactly the selected value slot is meaningful: STRING uses
`string_value` with integer `0`, boolean `false`, and empty array; INTEGER uses
the integer with empty string, false, empty array; BOOLEAN uses the boolean
with empty string, integer 0, empty array; STRING_ARRAY uses lexical unique NFC
strings with empty string, integer 0, false. This makes every field total.

```text
normalized_fields_digest = H("cut4.private.normalized_fields.v1",
                             normalized_fields)

normalized_semantic_digest = H("cut4.private.normalized_semantic_row.v1",
  NormalizedSemanticRow without normalized_semantic_row_id and
  normalized_semantic_digest)

normalized_semantic_row_id = "nsr_" +
  H("cut4.private.normalized_semantic_row_id.v1",
    [private_plan_row_id,payload_id,normalizer_id,normalizer_version,
     normalized_identity,normalized_semantic_digest])
```

All expanded-Kp fields are copied byte-for-byte from the referenced private
plan; outcome and payload FKs resolve exactly once and repeat the same provider,
plan, payload digest, and source snapshot. A payload may yield zero or more
normalized rows. Zero is allowed only for an explicit typed rejection/debt;
it is never silently treated as successful empty evidence.

`NormalizedKey=(private_plan_row_id,provider_id,provider_outcome_row_id,
payload_id,normalizer_id,normalizer_version,semantic_kind,normalized_identity,
multiplicity_key,multiplicity_ordinal,normalized_semantic_row_id)`. Rows sort by
that key and digest with domain `cut4.private.normalized_semantic_rows.v1`.

The accepted provider-private projection repeats every full normalized row.
Its normalized tuple is all fields in the exact schema order. Therefore:

```text
sort(pi_normalized_source(normalized_semantic_rows))
 = sort(pi_normalized_private(provider_private_projection_rows))
 = sort(pi_normalized_M4(M4))
 = sort(pi_normalized_R4(R4))
```

The comparison is byte equality, not selected-field equality. Missing, extra,
ID, payload FK, Kp, normalizer, semantic-kind, identity, field-array,
field-digest, source-snapshot, and semantic-digest mismatches have the exact
diff kinds `NORMALIZED_MISSING`, `NORMALIZED_EXTRA`, `NORMALIZED_ID_MISMATCH`,
`NORMALIZED_PAYLOAD_FK_MISMATCH`, `NORMALIZED_KP_MISMATCH`,
`NORMALIZED_NORMALIZER_MISMATCH`, `NORMALIZED_KIND_MISMATCH`,
`NORMALIZED_IDENTITY_MISMATCH`, `NORMALIZED_FIELDS_MISMATCH`,
`NORMALIZED_FIELDS_DIGEST_MISMATCH`, `NORMALIZED_SOURCE_MISMATCH`, and
`NORMALIZED_DIGEST_MISMATCH`. Expected source is the normalized source array;
observed source is the named downstream projection. No row, payload, outcome,
plan, or diff side may be orphaned.

M4 and R4 add exact top-level arrays and digests named `payload_records`,
`payload_records_digest`, `normalized_semantic_rows`, and
`normalized_semantic_rows_digest`, plus their ordered diff rows/digests. Their
data payload digest domains exclude M/R manifest, receipt, aggregate, and
self-slot control rows. Manifest bodies hash the exact data roster; receipts
hash the manifest identity and completed data roster. The canonical merge
still exclusively owns all SC/L1 canonical outputs and transform receipt in
one atomic publication.

## 6. Completion, failure, recall, and precision

Publication requires: construction DAG validation; all reach-source FKs and
multiset equations; generation authentication; a durable terminal record;
payload and normalized ordered equality; inherited predicate-inclusive Kp,
provider status, consumer, private, M/R, and complete-output equations; zero
unexpected physical aliases; no zero-byte required artifact; and all-new or
all-old crash recovery. A nonempty debt/diff blocks canonical success but is
itself durably represented.

Platform absence of atomic no-replace/fsync semantics is typed debt before a
provider call. Provider failure, timeout, malformed data, inapplicability, or
nonselection retains the inherited fixed nonempty outcome slot and exact
cursor semantics. A disabled provider never changes the path denominator.
Foundry and other tool configuration remains a scratchpad-contained temporary
overlay. No provider or direct tool mutates project root.

Recall improves because every authenticated static/probe source edge is either
projected one-for-one or retained as unprojectable debt, every provider byte is
bound by a full payload record, and every normalized fact is conserved through
M/R. Precision improves because copied-field FKs, content types, raw byte
hashes, stable attempt layers, typed zero/debt distinctions, and exact diff
sources prevent unrelated or fabricated rows from masquerading as evidence.

Non-goals are implementation, fixtures, tests, migration of legacy canonical
preimages, MODEL/dependency-unit changes, methodology-role changes, provider
roster changes, ArtifactLedger/G3 changes, audit execution, release, or a claim
that R12 is accepted before independent review.

## 7. Future worker ownership and execution phases

If separately authorized, one fixture worker owns only the new R12 RED nodes.
One DRIVER implementation worker would atomically own the private registered
generation operation, reach compiler, payload/normalizer schemas, and canonical
merge integration; splitting those into independent public writers is
forbidden. Existing MODEL shards and dependency units remain unchanged and
receive only the already specified immutable PhaseIO-bound inputs.

The exact future order is: (A) schemas/DAG, (B) reach denominator, (C) private
generation/replay, (D) payload/normalization conservation, (E) inherited
regression and all-old/all-new crash checks. Each phase must be RED before the
corresponding implementation and green with the complete denominator; no
subset or false-green zero permits progression.

## 8. Exact R12 RED roster

The following JSON contains exactly 192 unique literal pytest node IDs: 56
reach-denominator, 68 request-generation, 56 payload-semantic, and 12
regression nodes. There are no wildcards, ranges, implied nodes, or predecessor
nodes.

```json
{
  "reach_denominator": [
    "tests/test_cut4_r12_reach_denominator.py::test_construction_dag_schema_closed",
    "tests/test_cut4_r12_reach_denominator.py::test_construction_dag_nodes_unique",
    "tests/test_cut4_r12_reach_denominator.py::test_construction_dag_edges_known",
    "tests/test_cut4_r12_reach_denominator.py::test_construction_dag_topological_order",
    "tests/test_cut4_r12_reach_denominator.py::test_construction_dag_kahn_acyclic",
    "tests/test_cut4_r12_reach_denominator.py::test_construction_dag_field_dependencies_total",
    "tests/test_cut4_r12_reach_denominator.py::test_six_source_roots_exact",
    "tests/test_cut4_r12_reach_denominator.py::test_source_file_registry_authenticated",
    "tests/test_cut4_r12_reach_denominator.py::test_base_semantic_schema_closed",
    "tests/test_cut4_r12_reach_denominator.py::test_base_semantic_field_order",
    "tests/test_cut4_r12_reach_denominator.py::test_base_semantic_id_domain",
    "tests/test_cut4_r12_reach_denominator.py::test_base_semantic_source_fk",
    "tests/test_cut4_r12_reach_denominator.py::test_base_semantic_copied_sha_equal",
    "tests/test_cut4_r12_reach_denominator.py::test_base_semantic_array_order_digest",
    "tests/test_cut4_r12_reach_denominator.py::test_graph_edge_schema_closed",
    "tests/test_cut4_r12_reach_denominator.py::test_graph_edge_field_order",
    "tests/test_cut4_r12_reach_denominator.py::test_graph_edge_id_domain",
    "tests/test_cut4_r12_reach_denominator.py::test_graph_edge_semantic_fk_exact_one",
    "tests/test_cut4_r12_reach_denominator.py::test_graph_edge_copied_fields_equal",
    "tests/test_cut4_r12_reach_denominator.py::test_graph_edge_positive_reach_only",
    "tests/test_cut4_r12_reach_denominator.py::test_graph_edge_array_order_digest",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_plan_schema_closed",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_plan_id_domain",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_plan_semantic_fk",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_plan_bounded_limit",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_outcome_schema_closed",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_outcome_id_domain",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_outcome_plan_fk",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_positive_field_rules",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_negative_field_rules",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_debt_failure_timeout_malformed_rules",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_edge_schema_closed",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_edge_plan_outcome_semantic_fks",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_edge_copied_fields_equal",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_edge_array_order_digest",
    "tests/test_cut4_r12_reach_denominator.py::test_identity_match_exact_registry_only",
    "tests/test_cut4_r12_reach_denominator.py::test_selected_edge_predicate_exact",
    "tests/test_cut4_r12_reach_denominator.py::test_unprojectable_edge_predicate_exact",
    "tests/test_cut4_r12_reach_denominator.py::test_denominator_schema_closed",
    "tests/test_cut4_r12_reach_denominator.py::test_denominator_field_order",
    "tests/test_cut4_r12_reach_denominator.py::test_denominator_id_domain",
    "tests/test_cut4_r12_reach_denominator.py::test_denominator_reach_key_order",
    "tests/test_cut4_r12_reach_denominator.py::test_denominator_ordered_multiset_digest",
    "tests/test_cut4_r12_reach_denominator.py::test_graph_projection_one_to_one",
    "tests/test_cut4_r12_reach_denominator.py::test_probe_projection_one_to_one",
    "tests/test_cut4_r12_reach_denominator.py::test_unprojectable_projection_typed_debt",
    "tests/test_cut4_r12_reach_denominator.py::test_proved_none_requires_all_negative",
    "tests/test_cut4_r12_reach_denominator.py::test_unresolved_fallback_retains_identity",
    "tests/test_cut4_r12_reach_denominator.py::test_missing_second_edge_detected",
    "tests/test_cut4_r12_reach_denominator.py::test_fabricated_denominator_row_detected",
    "tests/test_cut4_r12_reach_denominator.py::test_duplicate_denominator_row_detected",
    "tests/test_cut4_r12_reach_denominator.py::test_dangling_semantic_id_detected",
    "tests/test_cut4_r12_reach_denominator.py::test_copied_field_mismatch_detected",
    "tests/test_cut4_r12_reach_denominator.py::test_denominator_plan_candidate_s_equality",
    "tests/test_cut4_r12_reach_denominator.py::test_independent_rescan_equality",
    "tests/test_cut4_r12_reach_denominator.py::test_unresolved_equal_debt_still_blocks"
  ],
  "request_generation": [
    "tests/test_cut4_r12_request_generation.py::test_base_request_intent_schema_closed",
    "tests/test_cut4_r12_request_generation.py::test_base_request_intent_field_order",
    "tests/test_cut4_r12_request_generation.py::test_base_request_has_zero_downstream_ids",
    "tests/test_cut4_r12_request_generation.py::test_base_request_start_prior_binding",
    "tests/test_cut4_r12_request_generation.py::test_base_request_nonstart_prior_binding",
    "tests/test_cut4_r12_request_generation.py::test_base_request_cursor_limits_bounded",
    "tests/test_cut4_r12_request_generation.py::test_base_request_argv_digest",
    "tests/test_cut4_r12_request_generation.py::test_request_digest_domain",
    "tests/test_cut4_r12_request_generation.py::test_changed_prior_changes_request_digest",
    "tests/test_cut4_r12_request_generation.py::test_attempt_allocation_schema_closed",
    "tests/test_cut4_r12_request_generation.py::test_attempt_allocation_field_order",
    "tests/test_cut4_r12_request_generation.py::test_attempt_id_formula",
    "tests/test_cut4_r12_request_generation.py::test_attempt_ordinal_driver_allocated",
    "tests/test_cut4_r12_request_generation.py::test_new_attempt_id_after_abort",
    "tests/test_cut4_r12_request_generation.py::test_invocation_record_schema_closed",
    "tests/test_cut4_r12_request_generation.py::test_invocation_record_field_order",
    "tests/test_cut4_r12_request_generation.py::test_invocation_binds_request_attempt",
    "tests/test_cut4_r12_request_generation.py::test_invocation_binds_registered_inputs",
    "tests/test_cut4_r12_request_generation.py::test_invocation_binds_provider_tool_config",
    "tests/test_cut4_r12_request_generation.py::test_invocation_digest_domain",
    "tests/test_cut4_r12_request_generation.py::test_no_launchspec_configuration_field",
    "tests/test_cut4_r12_request_generation.py::test_evidence_identity_after_invocation",
    "tests/test_cut4_r12_request_generation.py::test_receipt_identity_after_evidence",
    "tests/test_cut4_r12_request_generation.py::test_terminal_envelope_schema_closed",
    "tests/test_cut4_r12_request_generation.py::test_terminal_envelope_field_order",
    "tests/test_cut4_r12_request_generation.py::test_terminal_binds_invocation_outcome_evidence_receipt",
    "tests/test_cut4_r12_request_generation.py::test_terminal_digest_domain",
    "tests/test_cut4_r12_request_generation.py::test_no_forward_reference_any_stage",
    "tests/test_cut4_r12_request_generation.py::test_private_operation_registered_fixed",
    "tests/test_cut4_r12_request_generation.py::test_private_work_unit_single_driver_owner",
    "tests/test_cut4_r12_request_generation.py::test_private_output_identity_fixed",
    "tests/test_cut4_r12_request_generation.py::test_namespace_digest_formula",
    "tests/test_cut4_r12_request_generation.py::test_namespace_rejects_raw_user_path",
    "tests/test_cut4_r12_request_generation.py::test_namespace_containment",
    "tests/test_cut4_r12_request_generation.py::test_namespace_alias_reparse_rejected",
    "tests/test_cut4_r12_request_generation.py::test_generation_header_schema_closed",
    "tests/test_cut4_r12_request_generation.py::test_generation_id_formula",
    "tests/test_cut4_r12_request_generation.py::test_generation_header_filename",
    "tests/test_cut4_r12_request_generation.py::test_generation_parent_chain",
    "tests/test_cut4_r12_request_generation.py::test_generation_invalid_fact_digest",
    "tests/test_cut4_r12_request_generation.py::test_record_body_schema_closed",
    "tests/test_cut4_r12_request_generation.py::test_generation_record_schema_closed",
    "tests/test_cut4_r12_request_generation.py::test_record_body_digest_formula",
    "tests/test_cut4_r12_request_generation.py::test_record_digest_formula",
    "tests/test_cut4_r12_request_generation.py::test_record_filename_ordinal_digest",
    "tests/test_cut4_r12_request_generation.py::test_record_object_bytes_length_sha",
    "tests/test_cut4_r12_request_generation.py::test_record_previous_file_length_sha",
    "tests/test_cut4_r12_request_generation.py::test_record_ordinals_contiguous",
    "tests/test_cut4_r12_request_generation.py::test_temp_create_new_same_directory",
    "tests/test_cut4_r12_request_generation.py::test_atomic_rename_no_replace",
    "tests/test_cut4_r12_request_generation.py::test_file_and_directory_flush",
    "tests/test_cut4_r12_request_generation.py::test_platform_without_atomicity_debt",
    "tests/test_cut4_r12_request_generation.py::test_incomplete_temp_typed_ignored",
    "tests/test_cut4_r12_request_generation.py::test_invalid_committed_tail_seals_generation",
    "tests/test_cut4_r12_request_generation.py::test_new_generation_binds_valid_head",
    "tests/test_cut4_r12_request_generation.py::test_generation_header_cas",
    "tests/test_cut4_r12_request_generation.py::test_record_ordinal_cas",
    "tests/test_cut4_r12_request_generation.py::test_identical_request_cas_replay",
    "tests/test_cut4_r12_request_generation.py::test_distinct_request_serialization",
    "tests/test_cut4_r12_request_generation.py::test_orphan_generation_detected",
    "tests/test_cut4_r12_request_generation.py::test_orphan_record_detected",
    "tests/test_cut4_r12_request_generation.py::test_crash_before_invocation_new_attempt",
    "tests/test_cut4_r12_request_generation.py::test_crash_after_invocation_new_attempt",
    "tests/test_cut4_r12_request_generation.py::test_crash_after_terminal_exact_replay",
    "tests/test_cut4_r12_request_generation.py::test_timeout_terminal_durable_replay",
    "tests/test_cut4_r12_request_generation.py::test_cursor_in_out_terminal_contract",
    "tests/test_cut4_r12_request_generation.py::test_publication_link_exact_bytes",
    "tests/test_cut4_r12_request_generation.py::test_public_mismatch_no_overwrite"
  ],
  "payload_semantic": [
    "tests/test_cut4_r12_payload_semantic.py::test_payload_record_schema_closed",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_record_field_order",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_id_formula",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_digest_preimage",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_raw_sha_exact_bytes",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_base64url_roundtrip",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_byte_size_exact",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_content_type_closed",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_ordinals_contiguous",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_array_canonical_order",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_records_digest_nonrecursive",
    "tests/test_cut4_r12_payload_semantic.py::test_outcome_embeds_full_payload_records",
    "tests/test_cut4_r12_payload_semantic.py::test_success_empty_requires_zero_proof",
    "tests/test_cut4_r12_payload_semantic.py::test_non_success_payload_roster_empty",
    "tests/test_cut4_r12_payload_semantic.py::test_partial_payload_typed_debt_retained",
    "tests/test_cut4_r12_payload_semantic.py::test_provider_private_repeats_full_payload",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_outcome_private_ordered_equality",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_missing_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_extra_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_ordinal_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_id_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_content_type_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_size_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_sha_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_digest_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_bytes_diff_mapping",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_outcome_fk_exact_one",
    "tests/test_cut4_r12_payload_semantic.py::test_payload_private_fk_exact_one",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_field_schema_closed",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_field_names_unique",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_field_string_rules",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_field_integer_rules",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_field_boolean_rules",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_field_string_array_rules",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_semantic_schema_closed",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_semantic_field_order",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_fields_digest_domain",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_semantic_digest_domain",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_semantic_id_formula",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_expanded_kp_equal_plan",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_outcome_payload_fks",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_zero_requires_typed_rejection",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_key_order_digest",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_private_full_row_equality",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_m4_full_row_equality",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_r4_full_row_equality",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_missing_extra_diffs",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_id_payload_kp_diffs",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_normalizer_kind_identity_diffs",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_fields_and_digest_diffs",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_source_and_semantic_diffs",
    "tests/test_cut4_r12_payload_semantic.py::test_normalized_no_orphan_total",
    "tests/test_cut4_r12_payload_semantic.py::test_m4_r4_top_level_arrays_exact",
    "tests/test_cut4_r12_payload_semantic.py::test_data_digest_excludes_control_rows",
    "tests/test_cut4_r12_payload_semantic.py::test_manifest_receipt_digest_nonrecursive",
    "tests/test_cut4_r12_payload_semantic.py::test_complete_payload_normalized_denominator"
  ],
  "regression": [
    "tests/test_cut4_r12_regression.py::test_r11_document_byte_denominator_preserved",
    "tests/test_cut4_r12_regression.py::test_r11_multi_reach_identity_preserved",
    "tests/test_cut4_r12_regression.py::test_r11_provider_kp_preserved",
    "tests/test_cut4_r12_regression.py::test_r10_docs_totality_preserved",
    "tests/test_cut4_r12_regression.py::test_r9_cursor_session_preserved",
    "tests/test_cut4_r12_regression.py::test_r8_projection_contracts_preserved",
    "tests/test_cut4_r12_regression.py::test_r7_single_canonical_owner_preserved",
    "tests/test_cut4_r12_regression.py::test_r6_provider_roster_preserved",
    "tests/test_cut4_r12_regression.py::test_legacy_nonadoption_preserved",
    "tests/test_cut4_r12_regression.py::test_artifact_ledger_g3_unchanged",
    "tests/test_cut4_r12_regression.py::test_no_project_root_mutation",
    "tests/test_cut4_r12_regression.py::test_part0_all_authority_false"
  ]
}
```

Execution is bounded to the five phases in section 7 and stops after the
regression phase. The future fixture worker may write only the listed R12 test
files and receipts. This amendment itself creates no fixture or test.
