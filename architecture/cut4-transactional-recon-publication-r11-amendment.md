# Cut-4 transactional recon publication R11 amendment

Date: 2026-08-10
Status: Part-0 R11 architecture repair only
Supersedes: only the repaired clauses of the R10 amendment
Authority: design for independent review; no fixture, production, test,
ArtifactLedger, G3, provider, audit, commit, push, install, cutover, release,
or audit-readiness authority

## 0. Decision and inherited boundary

R11 closes only the three blockers in the mandatory R10 independent review.
R1-R10 remain immutable. R11 preserves R10's six-root byte denominator,
byte-covering segment partition, mandatory coverage/negative/debt candidates,
sealed registries, c3 current/prior authority equality, exhausted-cursor input
rejection, predicate-inclusive Kp, closed M3/R3 top levels, and explicit
consumer-plan-predicate-provider foreign keys. It preserves every accepted
R8/R9 projection, ownership, provider denominator, PhaseIO/publication, state,
compatibility, crash-recovery, legacy, and containment contract not explicitly
versioned below.

R11 makes three bounded repairs:

1. A syntactic reference is separated from all of its reach edges. Every
   authenticated recognized reference emits one candidate per distinct reach,
   with a distinct preauthorized flow instance. Recognized-but-unresolved reach
   retains the registered identity and emits DOC_REACHABILITY_DEBT. An
   unrecognized form remains identity-empty extraction debt. Segment/reference
   bytes, UTF-8/NFC/invalid/empty cases, semantic classes, field emptiness,
   ordering, cardinality, and `pi_instruction.v3` are literal.
2. A prior envelope's canonical digest participates before request,
   invocation, and per-attempt session identities are derived. Provider
   terminal bytes are durably appended to the DRIVER-private journal before
   consumer/public commit. Only journaled terminal bytes replay. A crash with
   no terminal row is ABORTED_UNOBSERVED and receives a new derived attempt ID;
   R11 makes no byte-identical wall-clock reexecution claim.
3. All new private row IDs have literal prefixes and exact row-without-ID hash
   formulas. Provider outcome, predicate evidence, provider-private, private
   evidence, disposition, normalizer/payload evidence, and diff sides have
   recursive byte schemas/domains. Expanded Kp is equal across plan,
   provider-private, evidence, disposition, projection, completion, and every
   applicable diff source.

Section 8 defines a new exact **192-node** roster. No predecessor node is
counted in 192.

## 1. Authenticated repair input

The mandatory R10 independent review was authenticated and read end to end
before authoring. It is 20,297 bytes and SHA-256
`2c0a4d862252eda5ddb68f771331894d94bf801b00285b25af80bbe5ecdf7eb2`:

`review_fixtures/cut4_transactional_recon_publication_r10_amendment_independent_review_20260810.md`.

The reviewed R10 amendment is 56,513 bytes and SHA-256
`bf5a67badfdd5650d900cad1414564172956e34721e439087ef38dbd56baf170`.
Its author receipt is 3,402 bytes and SHA-256
`5f3b55bc2da34bc65fb56d13a694f6dd332d24b5cc2c155ab655885cca7ec059`.
The review accepted R10's source-byte and represented-row exactness, c3
session-preimage equality, neutral private state, predicate-inclusive plan key,
and literal M3/R3 top-level fields. R11 does not reopen them.

## 2. Canonical bytes and closed R11 enums

R10 canonical JSON and `H(domain,value)` remain exact. `base64url(bytes)` means
RFC 4648 URL-safe base64 without padding. Raw ordinary SHA-256 means lowercase
hex SHA-256 directly over bytes, with no domain prefix. R11 adds:

```json
{
  "document_reach": ["NONE", "MODEL", "TOOL", "RUNTIME", "CONTROL", "UNRESOLVED"],
  "document_semantic_class": ["DOC_SEGMENT_COVERAGE", "DOC_MODEL_INSTRUCTION", "DOC_TOOL_INSTRUCTION", "DOC_RUNTIME_INSTRUCTION", "DOC_CONTROL_INSTRUCTION", "DOC_NONEXECUTING_REFERENCE", "DOC_REACHABILITY_DEBT", "DOC_EXTRACTION_DEBT"],
  "reach_resolution": ["RESOLVED", "PROVED_NONE", "UNRESOLVED"],
  "utf8_state": ["VALID", "INVALID"],
  "query_journal_row_kind": ["ATTEMPT_ALLOCATED", "TERMINAL_ENVELOPE", "ABORTED_UNOBSERVED", "PUBLICATION_LINK"],
  "query_terminal_journal_status": ["SUCCESS", "SUCCESS_EMPTY", "PARTIAL", "NOT_APPLICABLE", "DEBT", "FAILURE", "TIMEOUT", "MALFORMED"],
  "predicate_source_kind": ["PROJECT_SNAPSHOT", "CONFIGURATION", "PROVIDER_RECEIPT", "SEMANTIC_MANIFEST"],
  "provider_private_content_type": ["APPLICATION_JSON", "TEXT_MARKDOWN", "TEXT_PLAIN", "APPLICATION_OCTET_STREAM"],
  "private_normalizer_rejection_code": ["SCHEMA_INVALID", "IDENTITY_UNRESOLVED", "DUPLICATE_SEMANTIC_ROW", "OUT_OF_SCOPE", "UNSUPPORTED_CONTENT"],
  "private_diff_side": ["EXPECTED", "OBSERVED"],
  "private_diff_source_kind": ["EMPTY", "CONSUMER_PLAN_REF", "PLAN_REF", "PREDICATE_REGISTRY_JOIN", "PREDICATE_EVIDENCE_JOIN", "PROVIDER_PLAN_JOIN", "PROVIDER_OUTCOME_JOIN", "PROVIDER_PRIVATE_ROW", "PRIVATE_EVIDENCE_ROW", "DERIVED_EVIDENCE_PROJECTION", "PRIVATE_DISPOSITION_ROW", "PRIVATE_PROJECTION_ROW", "PRIVATE_COMPLETION_ROW", "MULTIPLICITY_MULTISET"]
}
```

`document_semantic_class` is the exact document subset of the inherited
`semantic_class` enum; all eight values are added to that enum. The inherited
ordinary semantic classes remain legal for non-document rows.

## 3. Reference x reach totality

### 3.1 Segment byte and text digests

R11 versions the segment row to `cut4.s.document_segment.v2`. Its field order
is exactly:

```text
schema, segment_id, source_file_id, source_file_sha256, byte_start, byte_end,
segment_ordinal, segment_kind, utf8_state, raw_bytes_digest,
nfc_text_digest, invalid_utf8_digest, parse_state
```

Let `B` be the exact source-file byte slice `[byte_start,byte_end)`, including
the zero-length empty-file sentinel slice. Define:

```text
raw_bytes_preimage = {
  "schema":"cut4.s.document_raw_bytes.v1",
  "byte_length":len(B),
  "raw_base64url":base64url(B)
}
raw_bytes_digest = H("cut4.s.document_raw_bytes.v1", raw_bytes_preimage)
```

If strict UTF-8 decoding succeeds, `utf8_state=VALID`, `invalid_utf8_digest=""`,
and:

```text
nfc_text_preimage = {
  "schema":"cut4.s.document_nfc_text.v1",
  "codepoint_length":len(NFC(UTF8_DECODE_STRICT(B))),
  "nfc_text":NFC(UTF8_DECODE_STRICT(B))
}
nfc_text_digest = H("cut4.s.document_nfc_text.v1", nfc_text_preimage)
```

This formula applies to `B=b""`; the empty valid text digest is nonempty. If
strict decoding fails, `utf8_state=INVALID`, `nfc_text_digest=""`,
`parse_state=DEBT`, and:

```text
invalid_utf8_digest = H("cut4.s.document_invalid_utf8.v1",
                        raw_bytes_preimage)
```

No replacement character decoding is allowed. `segment_id = "dseg_" +
H("cut4.s.document_segment.v2", row_without_segment_id)`. Segment ordering and
byte-partition equations remain R10, using the joined segment row rather than
an unstored candidate ordinal.

### 3.2 Syntactic reference and reach-plan rows

R11 keeps R10 SEGMENT_COVERAGE, NO_RECON_REFERENCE, PARSE_DEBT, and
UNRECOGNIZED_FORM_DEBT classification candidates, but separates recognized
references into their own denominator. A reference row has exactly, in order:

```text
schema=cut4.s.document_reference.v1, document_reference_id, source_file_id,
segment_id, reference_ordinal, candidate_kind, reference_byte_start,
reference_byte_end, identity_row_id, canonical_identity, identity_match_mode,
composition_component_ids, raw_reference_digest
```

Byte offsets are absolute source-file half-open offsets and must lie inside the
joined segment. Let `RB` be that exact byte slice. Its digest preimage is:

```text
{
  "schema":"cut4.s.document_reference_raw.v1",
  "source_file_sha256":"<joined file sha256>",
  "byte_start":<integer>,
  "byte_end":<integer>,
  "raw_base64url":"<base64url(RB)>"
}
```

`raw_reference_digest = H("cut4.s.document_reference_raw.v1", preimage)`.
It is always nonempty for a recognized reference, even for a syntactically
recognized zero-byte placeholder range, whose base64url value is `""` and
whose start equals end. `document_reference_id = "dref_" +
H("cut4.s.document_reference.v1", row_without_id)`. References sort by
`(source_file_id, joined_segment_ordinal, reference_byte_start,
reference_byte_end, identity_row_id, reference_ordinal,
document_reference_id)`. The segment ordinal is obtained only by the required
`segment_id` foreign-key join.

Every recognized reference has one or more reach-plan rows. Each has exactly:

Before planning, the compiler forms the closed reach-source registry from the
post-edit semantic consumer graph. Every exact model input binding, tool/CLI
edge, runtime reader, and control-authority edge whose identity matches a
reference contributes one row:

```text
schema=cut4.s.document_reach_source_row.v1, document_reach_source_row_id,
document_reference_id, source_semantic_row_id, document_reach, consumer_id,
endpoint, probe_id, required_phase_gate, reach_evidence_digest
```

`document_reach_source_row_id = "drs_" +
H("cut4.s.document_reach_source_row.v1",row_without_id)`. Rows sort by
`(document_reference_id,document_reach,consumer_id,endpoint,probe_id,
source_semantic_row_id)` and use domain
`cut4.s.document_reach_source_rows.v1`. Distinct means distinct values of that
tuple; no grouping by reach enum or identity is allowed. The registry is
derived from the same closed six-root semantic graph and runtime/fixture probe
registry used by S, so every graph edge must be either projected or typed debt.

Each reach-plan row has exactly:

```text
schema=cut4.s.document_reach_plan_row.v1, document_reach_plan_row_id,
document_reference_id, document_reach_source_row_id, reach_edge_id,
document_reach, reach_resolution,
consumer_id, endpoint, probe_id, required_phase_gate, flow_instance_id,
reach_evidence_digest, debt_code
```

Reach evidence body has exactly:

```text
schema=cut4.s.document_reach_evidence.v1, document_reference_id,
analyzer_id, analyzer_version, document_reach, reach_resolution,
consumer_id, endpoint, probe_id, source_input_digests
```

Source input digests are lexical unique nonempty S source/registry digests.
`reach_evidence_digest = H("cut4.s.document_reach_evidence.v1",body)` and is
nonempty for RESOLVED, PROVED_NONE, and UNRESOLVED.

Resolved MODEL/TOOL/RUNTIME/CONTROL edges use `reach_resolution=RESOLVED`, a
nonempty exact source-row ID, nonempty consumer/endpoint/probe/gate/evidence,
and empty debt. A mechanically
proved nonconsumer uses reach NONE, PROVED_NONE, empty consumer/endpoint/probe/
gate/source-row ID, nonempty negative evidence, and empty debt. If identity resolution
succeeds but reach cannot be resolved or proved absent, the compiler emits
exactly one UNRESOLVED row with empty consumer, `endpoint=INSTRUCTION`, a
nonempty probe/gate/evidence digest, empty source-row ID, and
`debt_code=UNRESOLVED_DOC_REACHABILITY_DEBT`.

```text
reach_edge_id = "dreach_" + H("cut4.s.document_reach_edge.v1",
  [document_reference_id, document_reach_source_row_id,
   document_reach, consumer_id, endpoint, probe_id])

flow_instance_id = "dfi_" + H("cut4.s.document_flow_instance.v1",
  [document_reference_id, reach_edge_id, required_phase_gate])
```

Even NONE/UNRESOLVED rows have a nonempty stable flow instance. The reach-plan
row ID is `"drp_" + H("cut4.s.document_reach_plan_row.v1",
row_without_id)`. Rows sort by `(document_reference_id,document_reach,
consumer_id,endpoint,probe_id,document_reach_source_row_id,reach_edge_id)`. Their array domain is
`cut4.s.document_reach_plan_rows.v1`.

If a reference has reach-source rows, resolved reach-plan rows are a one-to-one
projection of those rows and no NONE/UNRESOLVED fallback is allowed. If it has
none, the analyzer must emit exactly one PROVED_NONE row when the closed graph
and probes prove absence, or exactly one UNRESOLVED debt row otherwise. Thus
the reach-plan denominator cannot silently omit the second edge of a
MODEL+TOOL reference.

### 3.3 One candidate per reference x distinct reach

For each reach-plan row, S emits exactly one recognized-reference candidate.
Its exact v3 schema is:

```text
schema=cut4.s.document_candidate.v3, candidate_id, source_file_id,
segment_id, document_reference_id, document_reach_plan_row_id,
candidate_ordinal, candidate_kind, reference_byte_start, reference_byte_end,
identity_row_id, canonical_identity, identity_match_mode,
composition_component_ids, source_class, document_reach, reach_edge_id,
instruction_role, semantic_class, flow_instance_id,
raw_reference_digest, debt_code
```

All reference/identity/byte fields copy the reference row exactly; all
reach/flow fields copy the reach-plan row exactly. `candidate_ordinal` is the
zero-based rank of that reach-plan row in its reference's canonical reach order.
`candidate_id = "dcand_" + H("cut4.s.document_candidate.v3",
row_without_id)`. Candidates sort by `(source_file_id,
joined_segment_ordinal,document_reference_id,candidate_ordinal,document_reach,
reach_edge_id,candidate_id)`. The joined segment supplies the ordinal.

Semantic fields are total:

| candidate/reach | semantic_class | instruction_role | identity | flow | debt |
|---|---|---|---|---|---|
| SEGMENT_COVERAGE | DOC_SEGMENT_COVERAGE | NONE | empty | empty | empty |
| NO_RECON_REFERENCE | DOC_NONEXECUTING_REFERENCE | NONE | empty | empty | empty |
| PARSE_DEBT or UNRECOGNIZED_FORM_DEBT | DOC_EXTRACTION_DEBT | NONE | empty | empty | form-specific nonempty debt |
| recognized reference / NONE | DOC_NONEXECUTING_REFERENCE | REFERENCE | retained | nonempty | empty |
| recognized PATH reference / MODEL, TOOL, RUNTIME, CONTROL | corresponding DOC_*_INSTRUCTION | PATH_INSTRUCTION | retained | nonempty | empty |
| recognized CONTENT_INSTRUCTION / MODEL, TOOL, RUNTIME, CONTROL | corresponding DOC_*_INSTRUCTION | CONTENT_INSTRUCTION | retained | nonempty | empty |
| recognized CONTENT_REFERENCE / live reach | corresponding DOC_*_INSTRUCTION | REFERENCE | retained | nonempty | empty |
| recognized PROHIBITION / CONTROL | DOC_CONTROL_INSTRUCTION | PROHIBITION | retained | nonempty | empty |
| any recognized reference / UNRESOLVED | DOC_REACHABILITY_DEBT | PATH_INSTRUCTION, CONTENT_INSTRUCTION, PROHIBITION, or REFERENCE as fixed by candidate kind | retained | nonempty | UNRESOLVED_DOC_REACHABILITY_DEBT |

For identity-empty coverage/negative/extraction candidates,
`document_reference_id`, reach-plan ID, reference offsets, identity fields,
composition IDs, reach edge, flow instance, and raw-reference digest are exact
empty values (`""`, `[]`, and integer offsets `0`). UNRECOGNIZED_FORM_DEBT
never borrows a recognized identity; once an identity row resolves, only the
recognized-reference branch is legal, including UNRESOLVED reach.

One syntactic reference with MODEL and TOOL edges therefore has two candidates,
two semantic rows, distinct reach-edge/flow IDs, and the same retained
reference/identity/raw digest. It is not grouped by candidate kind or identity.

### 3.4 Cardinality, row projection, and `pi_instruction.v3`

Every recognized candidate emits exactly one S semantic row. The R11 document
fields in that row are source class, segment ID, reference ID, reach-plan ID,
candidate ID/kind, reach, reach-edge ID, instruction role, identity row ID,
composition IDs, flow instance, raw-reference digest, semantic class, and
debt code. The semantic row uses the same preauthorized flow instance in the
inherited multiplicity-key formula.

`pi_instruction.v3` is exactly:

```text
(consumer_id, operation, exact_identity, direction, projection_row_id,
 source_file, source_anchor_digest, semantic_class, source_class,
 document_segment_id, document_reference_id,
 document_reach_plan_row_id, document_candidate_id,
 document_candidate_kind, document_reach, reach_edge_id,
 instruction_role, identity_row_id, composition_component_ids,
 raw_reference_digest, flow_instance_id, multiplicity_key,
 multiplicity_ordinal)
```

Its domain is `cut4.s.pi_instruction.v3`. Static S, independent final rescan,
and runtime/prompt/tool observation use the same tuple and order by canonical
tuple bytes. The exact conservation equations are:

```text
count(reach-plan rows by document_reference_id)
  = count(recognized candidates by document_reference_id)
  = count(S semantic rows by document_reference_id)

multiset(distinct resolved edge tuple from reach-source registry)
  = multiset(same tuple from RESOLVED reach-plan rows)

multiset(document_reference_id,reach_edge_id,flow_instance_id from reach plan)
  = same multiset from recognized candidates
  = same multiset from S semantic rows
  = same multiset from final independent rescan

multiset(pi_instruction.v3(S))
  = multiset(pi_instruction.v3(final rescan))
  = multiset(pi_instruction.v3(runtime/instruction observations))
```

An unresolved row remains nonempty semantic debt, so equality does not make it
successful. Missing one of multiple reaches, duplicate reach emission, changed
raw bytes, identity loss, PATH/CONTENT/role flip, or flow reuse creates a
canonical diff and blocks. S v4/P0/M3/R3 bind reference rows/digest,
reach-source rows/digest, reach-plan rows/digest, candidate v3 rows/digest, and
`pi_instruction.v3` digest. D/M/R
commitments are rederived after final freeze; no predecessor digest is reused
by assertion.

## 4. Canonical prior envelope and append-only terminal journal

### 4.1 Canonical envelope and prior binding

R11 query envelope body v5 has exactly:

```text
schema=cut4.scip_query_envelope_body.v5, request_body, request_digest,
session_preimage_body, query_session_preimage_digest,
invocation_preimage_body, invocation_digest, attempt_session_identity,
attempt_id, execution_evidence_body, execution_evidence_digest,
result_rows, query_zero_proof_body, query_zero_proof_digest,
receipt_body, query_receipt_digest, terminal_journal_binding
```

The file envelope is exactly:

```text
schema=cut4.scip_query_envelope_file.v5, body,
canonical_envelope_digest
```

`canonical_envelope_digest = H("cut4.query.canonical_envelope.v1", body)`.
The ordinary file bytes are canonical JSON plus one LF; file size and ordinary
SHA-256 are computed over those exact bytes. There is no self hash in `body`.
`terminal_journal_binding` is constructed before provider execution and has
exactly `schema=cut4.query.preterminal_journal_binding.v1`, journal identity,
ATTEMPT_ALLOCATED row ID/digest, attempt ID, and preterminal journal-head
digest. It contains no TERMINAL_ENVELOPE row ID/digest, envelope hash, or
publication link. Consequently envelope -> terminal-journal-record hashing is
acyclic.

For START, the request's prior-envelope binding has exactly identity `""`,
size `0`, file SHA `""`, and canonical digest `""`. For non-START it has
exactly:

```text
schema=cut4.query.prior_envelope_binding.v1, phaseio_output_identity,
file_size, file_sha256, canonical_envelope_digest
```

The reader loads that declared immutable PhaseIO file, rejects extra bytes or
schema fields, recomputes its canonical body digest, canonical file bytes,
size, and ordinary SHA, and requires every value to match. The term
`prior_envelope_digest` means only this `canonical_envelope_digest`; it is
never an ambient file hash or digest of a partial object.

### 4.2 Request, invocation, and per-attempt session identity

R11 request body v3 is R10's request body with the exact
`prior_envelope_binding` object before prior receipt fields. Therefore:

```text
request_digest = H("cut4.query.invocation_request.v3", request_body)
```

changes if any prior-envelope identity/size/file SHA/canonical digest changes.
The invocation preimage v3 has exactly:

```text
schema=cut4.query.invocation_preimage.v3, request_digest,
query_session_digest, query_session_preimage_digest,
prior_envelope_digest, prior_receipt_identity, prior_receipt_digest,
cursor_in_body_or_start, cursor_in_integrity_digest,
invocation_limits, argv_digest
```

`invocation_preimage_digest = H("cut4.query.invocation_preimage.v3", body)`.
R9's immutable `query_session_digest` remains the chain-wide semantic core and
does not absorb mutable prior-envelope state. R11 adds the per-attempt session
identity:

```text
attempt_session_identity = "qsi_" + H("cut4.query.attempt_session.v1",
  [query_session_digest, query_session_preimage_digest,
   prior_envelope_digest, request_digest])
```

Thus the prior digest participates in request, invocation, and the applicable
session identity without breaking the accepted stable chain digest.

### 4.3 Append-only DRIVER-private journal

The query provider does not directly publish. The sole DRIVER owner maintains
the registered private journal identity
`private/query_terminal_journal.v1`. It is not a canonical/public output and
not a provider/project-root mutation. Journal rows are append-only canonical
JSON records with one LF, serialized by the DRIVER. Each has common fields:

```text
schema=cut4.query.journal_row.v1, journal_row_id, sequence,
previous_journal_row_digest, row_kind, request_digest,
attempt_session_identity, attempt_id, row_body, journal_row_digest
```

`row_body` is one of the exact tagged bodies below. The row digest is
`H("cut4.query.journal_row.v1", row_without_journal_row_digest_and_id)`;
`journal_row_id = "qjr_" + journal_row_digest`. Sequence begins at 0 and
increments by one; previous digest is empty only for sequence 0. The journal
head digest is the last row digest or the fixed empty head
`H("cut4.query.journal_empty.v1",[])`. A torn/invalid tail is retained as typed
journal debt and is never interpreted as a terminal row.

Before provider execution, the DRIVER appends and fsyncs ATTEMPT_ALLOCATED:

```text
schema=cut4.query.attempt_allocated.v1, allocation_ordinal,
request_digest, invocation_preimage_digest, prior_journal_head_digest
```

```text
attempt_id = "qat_" + H("cut4.query.attempt_id.v1",
  [request_digest, invocation_preimage_digest,
   prior_journal_head_digest, allocation_ordinal])
```

The ordinal is the zero-based count of allocated attempts for the request in
the validated journal. It is not caller supplied and is not a ledger attempt
key.

Once the provider reaches any terminal state, the DRIVER constructs the full
canonical envelope bytes and appends/fsyncs exactly one TERMINAL_ENVELOPE body
before PhaseIO/public commit:

```text
schema=cut4.query.terminal_envelope_journal.v1, terminal_status,
cursor_in_integrity_digest, cursor_out_integrity_digest,
canonical_envelope_digest, envelope_file_size, envelope_file_sha256,
envelope_file_base64url
```

Decoded bytes must equal the canonical v5 file bytes and reproduce all three
size/hash/digest fields. There is at most one TERMINAL_ENVELOPE for an
`attempt_id` and at most one terminal envelope across all attempts for one
`request_digest`. Once it exists, any replay uses it; no new attempt is
allocated.

After consumer/public PhaseIO commit, the DRIVER appends PUBLICATION_LINK:

```text
schema=cut4.query.publication_link.v1, terminal_journal_row_id,
phaseio_output_identity, phaseio_file_size, phaseio_file_sha256,
phaseio_completion_receipt_digest
```

The committed PhaseIO bytes must equal the terminal journal bytes exactly.
This link is history, not a second owner.

### 4.4 Crash, timeout, replay, and cursor semantics

Recovery scans only the registered journal chain. An ATTEMPT_ALLOCATED with no
later terminal row for that attempt is completed by appending:

```text
schema=cut4.query.aborted_unobserved.v1, allocated_journal_row_id,
abort_reason=TERMINAL_NOT_JOURNALED, observed_terminal=false
```

The attempt status is ABORTED_UNOBSERVED. Its provider behavior may have
succeeded, failed, or timed out, but no terminal bytes are authoritative and
R11 makes no identical-rerun claim. A retry appends a new allocation with a new
ordinal/attempt ID. It may produce different terminal bytes; its identities
include that new attempt.

If TERMINAL_ENVELOPE exists but public commit does not, recovery republishes
the exact stored bytes and appends PUBLICATION_LINK. If publication already
exists, replay verifies it and returns those bytes. A completed identical
request never reexecutes the provider.

Timeout is a real terminal envelope. It has status TIMEOUT, the original
cursor-in digest, empty cursor-out digest, no page/result rows, no zero proof,
non-evidentiary receipt status TIMEOUT, and the inherited terminal error code.
It is journaled before publication exactly like SUCCESS/PARTIAL. A retry after
a journaled timeout replays TIMEOUT; a caller must change an authorized request
input (for example a larger bounded timeout) to create a different request.

Cursor rules are exact:

| terminal | cursor-in | cursor-out |
|---|---|---|
| SUCCESS/SUCCESS_EMPTY | START or nonexhausted c3 | nonempty exhausted c3 |
| PARTIAL | START or nonexhausted c3 | nonempty nonexhausted c3 |
| NOT_APPLICABLE/DEBT/FAILURE/TIMEOUT/MALFORMED | START or nonexhausted c3 | exact empty string |
| any new request with exhausted c3 as input | rejected exit 2 | no envelope |

The journal terminal body repeats both cursor digests, and the embedded
envelope/evidence/receipt must match. A terminal final replay submits the same
original request identity and returns the journaled exhausted cursor-out; it
never submits that output token as input. ABORTED_UNOBSERVED produces no
envelope, receipt, result, or cursor-out. The next attempt retains the same
logical request digest but has a distinct attempt ID/invocation identity.

Evidence identity is
`scip-evidence:<attempt_session_identity>:<attempt_id>` and receipt identity is
`scip-receipt:<attempt_session_identity>:<attempt_id>`. The final invocation
digest is `H("cut4.query.invocation.v4",
[invocation_preimage_digest,attempt_id,attempt_allocated_journal_row_digest])`.
Every terminal envelope binds this digest. Exact journal terminal bytes, not
wall-clock repeatability, are replay authority.

## 5. Recursively closed private row and diff bytes

### 5.1 Common row hash rule and expanded Kp

For every row below, `row_without_id` means the exact field-ordered object with
only the named ID field removed; no digest/evidence field is removed. Canonical
JSON still code-point-sorts object keys on wire. Literal formulas are:

```text
provider_outcome_row_id = "pout_" + H("cut4.m.provider_outcome_row.v2", row_without_id)
predicate_evidence_row_id = "pevd_" + H("cut4.m.predicate_evidence_row.v2", row_without_id)
provider_private_row_id = "ppriv_" + H("cut4.m.provider_private_row.v2", row_without_id)
private_evidence_row_id = "pev_" + H("cut4.m.private_evidence_row.v3", row_without_id)
private_disposition_row_id = "pdisp_" + H("cut4.m.private_disposition_row.v3", row_without_id)
```

Array formulas are literal:

```text
provider_outcome_rows_digest = H("cut4.m.provider_outcome_rows.v2", rows)
predicate_evidence_rows_digest = H("cut4.m.predicate_evidence_rows.v2", rows)
provider_private_rows_digest = H("cut4.m.provider_private_rows.v2", rows)
private_evidence_rows_digest = H("cut4.m.private_evidence_rows.v3", rows)
private_disposition_rows_digest = H("cut4.m.private_disposition_rows.v3", rows)
```

Arrays use R10's fixed provider order or expanded Kp order, never discovery
order.

Expanded Kp remains exactly:

```text
private_plan_row_id, semantic_row_id, private_source_identity, provider_id,
consumer_id, flow_instance_id, multiplicity_key, multiplicity_ordinal,
applicability_predicate_id, selection_predicate_id, accept_disposition,
accept_projected_identity
```

Plan, provider-private, private evidence, disposition, projection, completion,
and each nonempty diff side serialize or derive all twelve fields and must be
byte-equal to the referenced plan.

### 5.2 Provider outcome bytes

The provider outcome receipt body has exactly:

```text
schema=cut4.provider.outcome_receipt_body.v1, provider_id,
provider_plan_digest, outcome_status, started, terminal_code,
tool_identity, tool_version, input_snapshot_digest,
stdout_bytes_digest, stderr_bytes_digest, payload_ids,
payload_roster_digest, explicit_zero_proof_digest
```

Stdout/stderr use `H("cut4.provider.stream_bytes.v1",
{"byte_length":n,"raw_base64url":base64url(bytes)})`; empty streams have
nonempty digests under the same formula. Payload IDs are lexical unique.
`payload_roster_digest = H("cut4.provider.payload_roster.v1",payload_ids)`.
The receipt digest is
`H("cut4.provider.outcome_receipt.v1",receipt_body)`. Receipt identity is
`"por_" + H("cut4.provider.outcome_identity.v1",
[provider_id,provider_plan_digest])`. All six provider statuses have nonempty
receipt identity/digest. NOT_APPLICABLE and NOT_SELECTED require
`started=false`; SUCCESS requires true. FAILURE, TIMEOUT, and MALFORMED retain
the observed boolean so a platform prestart failure remains representable;
their closed terminal code and stream evidence distinguish prestart from
started failure. Zero-proof emptiness follows the inherited provider table.

Provider outcome row v2 field order is exactly:

```text
schema, provider_outcome_row_id, provider_id, provider_plan_digest,
applicability_registry_digest, selection_registry_digest, outcome_status,
outcome_receipt_identity, outcome_receipt_body, outcome_receipt_digest,
explicit_zero_digest
```

The embedded body must equal the repeated provider/plan/status fields. Outcome
identity is recomputed from provider/plan by the formula above; outcome digest
is recomputed over the body; explicit-zero fields must agree. Registry digests use domains
`cut4.private.applicability_registry.v1` and
`cut4.private.selection_registry.v1` over their exact sorted registry rows.
Explicit zero is empty unless SUCCESS with an exact inherited provider-zero
body, whose domain is `cut4.provider.explicit_zero.v1`.

### 5.3 Predicate and provider-private evidence bytes

Predicate input body has exactly:

```text
schema=cut4.private.predicate_input.v1, private_plan_row_id, predicate_id,
predicate_kind, provider_id, project_snapshot_digest,
configuration_digest, normalized_arguments
```

Arguments are a lexical array of exact NFC strings. Its digest domain is
`cut4.private.predicate_input.v1`. Each predicate source-evidence row has
exactly:

```text
schema=cut4.private.predicate_source_evidence.v1, source_kind,
source_identity, byte_size, file_sha256, authority_digest
```

File size/SHA are exact declared PhaseIO input bytes or 0/empty only when the
source kind is a digest-only CONFIGURATION. `authority_digest` is respectively
the sealed project snapshot, configuration, provider outcome receipt, or S
manifest digest. Rows sort by `(source_kind,source_identity)` and use
`H("cut4.private.predicate_source_evidence_rows.v1",rows)`. Predicate
evaluation body has exactly:

```text
schema=cut4.private.predicate_evaluation.v1, predicate_input_digest,
predicate_result, evaluator_id, evaluator_version,
source_evidence_rows, source_evidence_rows_digest
```

The array is nonempty, has unique source identities, and its repeated digest
must equal the array-domain result. Evaluation digest is
`H("cut4.private.predicate_evaluation.v1",body)`.

Predicate evidence row v2 field order is exactly:

```text
schema, predicate_evidence_row_id, private_plan_row_id,
predicate_registry_row_id, predicate_id, predicate_kind, provider_id,
provider_outcome_row_id, predicate_result, predicate_input_body,
predicate_input_digest, evaluator_id, evaluator_version,
predicate_evaluation_body, evidence_digest
```

Embedded bodies and repeated fields must match. Its evidence digest is the
predicate evaluation digest above. There is exactly one applicability row per
plan and one selection row iff applicability is TRUE, as R10 specifies.

Provider-private payload body has exactly:

```text
schema=cut4.provider.private_payload.v1, provider_private_identity,
content_type, byte_length, raw_sha256, raw_base64url
```

`raw_sha256` is ordinary SHA-256 over decoded raw bytes; length must match.
`content_type` is the closed R11 enum, not a free MIME string.
`provider_private_digest = H("cut4.provider.private_payload.v1",body)`.
The identity is `"ppay_" + H("cut4.provider.private_identity.v1",
[provider_id,private_plan_row_id,raw_sha256])`.

Provider-private row v2 field order is exactly:

```text
schema, provider_private_row_id, <expanded Kp>, provider_outcome_row_id,
provider_private_payload_body, provider_private_identity,
provider_private_digest
```

The two repeated payload fields must equal the embedded body/digest. Expanded
Kp must equal the referenced plan byte-for-byte; sorting never substitutes plan
values for mismatched serialized values. A mismatch emits a diff.

### 5.4 Private evidence and disposition bytes

Normalizer evidence body has exactly:

```text
schema=cut4.private.normalizer_evidence.v1, private_plan_row_id,
provider_private_row_id, normalizer_id, normalizer_version,
source_payload_digest, normalizer_status, normalized_semantic_digest,
rejection_code
```

`normalizer_evidence_digest = H("cut4.private.normalizer_evidence.v1",body)`.
For ACCEPTED, `normalized_semantic_digest =
H("cut4.private.normalized_semantic.v1", <exact normalized semantic row
without its row ID>)` and rejection code is empty. For
REJECTED, semantic digest is empty and rejection code is one closed R11
normalizer rejection code. For UNKNOWN/
NOT_APPLICABLE the entire body is `{}` and digest is `""`.

Private evidence row v3 field order is exactly:

```text
schema, private_evidence_row_id, <expanded Kp>,
applicability_predicate_registry_row_id,
applicability_predicate_evidence_row_id,
applicability_predicate_evidence_digest, applicability_result,
selection_predicate_registry_row_id,
selection_predicate_evidence_row_id,
selection_predicate_evidence_digest, selection_result,
provider_outcome_row_id, provider_outcome_status,
provider_private_row_id, private_row_status, private_normalizer_status,
provider_evidence_identity, provider_evidence_digest,
normalizer_evidence_body, normalizer_evidence_digest
```

Predicate evidence digests equal joined predicate rows; provider evidence
identity/digest equal the joined provider outcome receipt, except the accepted/
rejected payload reference additionally joins provider-private. Empty fields
follow R10's total status table.

Private disposition row v3 has exactly:

```text
schema, private_disposition_row_id, <expanded Kp>,
applicability_predicate_registry_row_id,
applicability_predicate_evidence_row_id,
applicability_predicate_evidence_digest, applicability_result,
selection_predicate_registry_row_id,
selection_predicate_evidence_row_id,
selection_predicate_evidence_digest, selection_result,
provider_outcome_row_id, provider_outcome_status,
provider_private_row_id, private_row_status, private_normalizer_status,
provider_evidence_identity, provider_evidence_digest,
normalizer_evidence_body, normalizer_evidence_digest,
private_disposition, projected_identity, private_debt_id,
private_debt_code
```

Every shared field copies the joined evidence row exactly. Final fields derive
only by R10's closed state table and referenced plan. Disposition arrays use
`cut4.m.private_disposition_rows.v3`.

### 5.5 Exact diff-side preimages and mapping

Every expected/observed side is first represented by:

```text
schema=cut4.m.private_diff_side.v1, diff_kind, side, source_kind,
source_row_schema, source_row_id, expanded_kp, source_body_digest, count
```

`expanded_kp` is the literal twelve-element JSON array or `[]` only for a truly
unkeyed empty side. For a row source,
`source_body_digest = H("cut4.m.private_diff_source_body.v1",
{"source_kind":source_kind,"row_without_id":<exact joined row without ID>})`.
For a projection/plan-ref/multiset source, `row_without_id` is replaced by the
exact canonical tuple or sorted tuple array. For EMPTY, schema/ID are empty,
expanded Kp is the other side's Kp when known, count is 0, and
`source_body_digest = H("cut4.m.private_diff_empty.v1",[])`.

```text
diff_side_digest = H("cut4.m.private_diff_side.v1", diff_side_body)
```

The exact source mapping is:

| diff kind | expected source | observed source |
|---|---|---|
| MISSING_CONSUMER_PLAN_REF | PLAN_REF | EMPTY |
| EXTRA_CONSUMER_PLAN_REF | EMPTY | CONSUMER_PLAN_REF |
| PLAN_SEMANTIC_MISMATCH | PLAN_REF | CONSUMER_PLAN_REF |
| PREDICATE_FOREIGN_KEY_MISMATCH | PREDICATE_REGISTRY_JOIN | PREDICATE_EVIDENCE_JOIN |
| PROVIDER_FOREIGN_KEY_MISMATCH | PROVIDER_PLAN_JOIN | PROVIDER_OUTCOME_JOIN |
| MISSING_PROVIDER_PRIVATE_ROW | PLAN_REF | EMPTY |
| EXTRA_PROVIDER_PRIVATE_ROW | EMPTY | PROVIDER_PRIVATE_ROW |
| MISSING_EVIDENCE_ROW | PLAN_REF | EMPTY |
| EXTRA_EVIDENCE_ROW | EMPTY | PRIVATE_EVIDENCE_ROW |
| EVIDENCE_DISPOSITION_MISMATCH | DERIVED_EVIDENCE_PROJECTION | PRIVATE_DISPOSITION_ROW |
| MISSING_COMPLETION_ROW | PRIVATE_PROJECTION_ROW | EMPTY |
| EXTRA_COMPLETION_ROW | EMPTY | PRIVATE_COMPLETION_ROW |
| PRIVATE_MULTIPLICITY_MISMATCH | MULTIPLICITY_MULTISET | MULTIPLICITY_MULTISET |

For row sources, `source_row_schema` and `source_row_id` are the exact source
values. For tuple/projection/multiset sources, `source_row_schema` is the
literal projection/source-kind name, `source_row_id=""`, and the canonical
tuple/array is the source body. A diff row's expanded Kp equals the expected
side Kp when expected is nonempty, otherwise the observed side Kp. Each
nonempty side body carries the Kp derived from its actual source; a mismatch is
therefore preserved inside the two side digests rather than normalized away.

Private diff row v3 has exactly:

```text
schema=cut4.m.private_diff_row.v3, private_diff_row_id, <expanded Kp>,
diff_kind, expected_side_body, expected_row_digest,
observed_side_body, observed_row_digest, expected_count,
observed_count, debt_code=PRIVATE_FOREIGN_KEY_DEBT
```

Side bodies must match the mapping; row digests equal their side digests; counts
repeat body counts. `private_diff_row_id = "pdiff_" +
H("cut4.m.private_diff_row.v3",row_without_id)`. Rows sort by expanded Kp,
diff kind, and ID; array domain is `cut4.m.private_diff_rows.v3`.

### 5.6 Expanded-Kp equality and recursive no-orphan closure

R11 versions projection/completion rows only to reference the v2/v3 IDs above;
their full R10 field lists and ID formulas remain exact. Their expanded Kp must
equal the plan. No-orphan equations are:

```text
multiset(expanded Kp from S plans)
  = multiset(expanded Kp from provider-private rows where required)
    plus the exact plan subset whose state requires no provider-private row
  = multiset(expanded Kp from private evidence)
  = multiset(expanded Kp from private disposition)
  = multiset(expanded Kp from private projection)
  = multiset(expanded Kp from R private completion)

for each provider-private row:
  serialized expanded Kp = referenced plan expanded Kp

for each evidence/disposition/projection/completion row:
  serialized expanded Kp = referenced plan expanded Kp

for each keyed diff side:
  side expanded Kp = serialized source expanded Kp
```

The provider-private equality is conditional only on R10's exact state table:
ACCEPTED/REJECTED require one row, every other state requires zero. Plan IDs,
predicate rows, provider outcomes, evidence bodies, dispositions, projections,
completions, and diff sides are each foreign-key total. Extra provider/private
payload, changed repeated Kp field, wrong evidence preimage, or independent
encoder disagreement creates a nonempty diff and blocks. M3/R3 use the new
row-array domains/digests and repeat them byte-for-byte; their already closed
top-level field lists do not change.

## 6. Supported order, ownership, and failure behavior

The single DRIVER cutover/publication owner still performs read-only admission,
all authorized edits, final independent rescan, S/P0 freeze, provider-plan
execution, private reconciliation, D/M/R/SP construction, and registered
publication completion. R11 adds only the DRIVER-private serialized query
journal before consumer PhaseIO commit. Journal bytes never become canonical
recon data and providers cannot write them.

Provider failure, timeout, malformed output, NOT_SELECTED, and NOT_APPLICABLE
retain fixed nonempty outcome receipts and path-stable slots. Query terminal
states are journaled before publication; an unobserved crash is not relabeled
as a provider result. Document unknown form and unresolved reach remain
distinct typed debts. None can become zero success.

No manual attempt key, ArtifactLedger change, public glob/discovery, project-
root mutation, co-owned canonical output, methodology/model-role change,
provider roster/path change, audit, fixture, production, commit, push, install,
cutover, release, or readiness action is authorized.

## 7. Recall and precision

Recall is protected at three denominators: every authenticated document byte is
segmented; every recognized syntactic reference conserves every distinct reach;
and every private provider row conserves the plan's full expanded key through
completion/diff. A recognized identity is never discarded merely because its
reach is unknown. A journaled terminal envelope cannot be lost between provider
return and public commit.

Precision comes from exact reference bytes/identity, independent reach-edge
IDs, per-edge flows, typed unresolved versus unrecognized debt, canonical prior
envelope identity, and recursively bound provider/predicate/private evidence.
ABORTED_UNOBSERVED says only that no terminal bytes were durably observed; it
does not guess success, failure, or timeout.

## 8. Exact R11 test roster

The JSON object below contains exactly **192** unique literal pytest node IDs:
56 reference/reach, 56 journal/replay, 68 private-byte, and 12 regression
nodes. There are no wildcards or implied/predecessor nodes.

```json
{
  "reference_reach": [
    "tests/test_cut4_r11_reference_reach.py::test_segment_v2_exact_field_order",
    "tests/test_cut4_r11_reference_reach.py::test_segment_v2_id_prefix_domain",
    "tests/test_cut4_r11_reference_reach.py::test_raw_bytes_digest_preimage",
    "tests/test_cut4_r11_reference_reach.py::test_empty_raw_bytes_digest_nonempty",
    "tests/test_cut4_r11_reference_reach.py::test_valid_utf8_nfc_digest_preimage",
    "tests/test_cut4_r11_reference_reach.py::test_empty_utf8_nfc_digest_nonempty",
    "tests/test_cut4_r11_reference_reach.py::test_invalid_utf8_nfc_digest_empty",
    "tests/test_cut4_r11_reference_reach.py::test_invalid_utf8_digest_preimage",
    "tests/test_cut4_r11_reference_reach.py::test_no_replacement_decode",
    "tests/test_cut4_r11_reference_reach.py::test_reference_row_exact_field_order",
    "tests/test_cut4_r11_reference_reach.py::test_reference_id_prefix_domain",
    "tests/test_cut4_r11_reference_reach.py::test_reference_offsets_inside_segment",
    "tests/test_cut4_r11_reference_reach.py::test_reference_raw_digest_preimage",
    "tests/test_cut4_r11_reference_reach.py::test_zero_byte_reference_digest_nonempty",
    "tests/test_cut4_r11_reference_reach.py::test_reference_sort_joins_segment_ordinal",
    "tests/test_cut4_r11_reference_reach.py::test_reach_plan_exact_field_order",
    "tests/test_cut4_r11_reference_reach.py::test_reach_plan_id_prefix_domain",
    "tests/test_cut4_r11_reference_reach.py::test_reach_edge_id_formula",
    "tests/test_cut4_r11_reference_reach.py::test_flow_instance_id_formula",
    "tests/test_cut4_r11_reference_reach.py::test_resolved_reach_field_rules",
    "tests/test_cut4_r11_reference_reach.py::test_proved_none_reach_field_rules",
    "tests/test_cut4_r11_reference_reach.py::test_positive_identity_unresolved_reach",
    "tests/test_cut4_r11_reference_reach.py::test_unresolved_retains_identity",
    "tests/test_cut4_r11_reference_reach.py::test_unresolved_reachability_debt",
    "tests/test_cut4_r11_reference_reach.py::test_unrecognized_form_identity_empty",
    "tests/test_cut4_r11_reference_reach.py::test_parse_debt_identity_empty",
    "tests/test_cut4_r11_reference_reach.py::test_candidate_v3_exact_field_order",
    "tests/test_cut4_r11_reference_reach.py::test_candidate_v3_id_prefix_domain",
    "tests/test_cut4_r11_reference_reach.py::test_candidate_copies_reference_fields",
    "tests/test_cut4_r11_reference_reach.py::test_candidate_copies_reach_fields",
    "tests/test_cut4_r11_reference_reach.py::test_candidate_ordinal_per_reference",
    "tests/test_cut4_r11_reference_reach.py::test_semantic_class_coverage_exact",
    "tests/test_cut4_r11_reference_reach.py::test_semantic_class_model_exact",
    "tests/test_cut4_r11_reference_reach.py::test_semantic_class_tool_exact",
    "tests/test_cut4_r11_reference_reach.py::test_semantic_class_runtime_exact",
    "tests/test_cut4_r11_reference_reach.py::test_semantic_class_control_exact",
    "tests/test_cut4_r11_reference_reach.py::test_semantic_class_none_exact",
    "tests/test_cut4_r11_reference_reach.py::test_semantic_class_unresolved_exact",
    "tests/test_cut4_r11_reference_reach.py::test_semantic_class_extraction_exact",
    "tests/test_cut4_r11_reference_reach.py::test_path_role_mapping_exact",
    "tests/test_cut4_r11_reference_reach.py::test_content_role_mapping_exact",
    "tests/test_cut4_r11_reference_reach.py::test_prohibition_role_mapping_exact",
    "tests/test_cut4_r11_reference_reach.py::test_identity_empty_candidate_empty_rules",
    "tests/test_cut4_r11_reference_reach.py::test_one_reference_two_reaches_two_candidates",
    "tests/test_cut4_r11_reference_reach.py::test_one_reference_two_reaches_two_flows",
    "tests/test_cut4_r11_reference_reach.py::test_reach_source_plan_one_to_one",
    "tests/test_cut4_r11_reference_reach.py::test_reference_reach_semantic_cardinality",
    "tests/test_cut4_r11_reference_reach.py::test_multi_reach_missing_edge_detected",
    "tests/test_cut4_r11_reference_reach.py::test_multi_reach_duplicate_edge_detected",
    "tests/test_cut4_r11_reference_reach.py::test_pi_instruction_v3_exact_fields",
    "tests/test_cut4_r11_reference_reach.py::test_pi_instruction_v3_digest_domain",
    "tests/test_cut4_r11_reference_reach.py::test_pi_instruction_v3_raw_digest_tamper",
    "tests/test_cut4_r11_reference_reach.py::test_pi_instruction_v3_flow_tamper",
    "tests/test_cut4_r11_reference_reach.py::test_static_rescan_reach_multiset_equal",
    "tests/test_cut4_r11_reference_reach.py::test_runtime_reach_multiset_equal",
    "tests/test_cut4_r11_reference_reach.py::test_equal_unresolved_debt_still_fails"
  ],
  "journal_replay": [
    "tests/test_cut4_r11_journal_replay.py::test_envelope_body_v5_exact_fields",
    "tests/test_cut4_r11_journal_replay.py::test_envelope_file_v5_exact_fields",
    "tests/test_cut4_r11_journal_replay.py::test_canonical_envelope_digest_preimage",
    "tests/test_cut4_r11_journal_replay.py::test_envelope_file_bytes_one_lf",
    "tests/test_cut4_r11_journal_replay.py::test_envelope_file_size_sha_exact",
    "tests/test_cut4_r11_journal_replay.py::test_start_prior_binding_exact_empty",
    "tests/test_cut4_r11_journal_replay.py::test_nonstart_prior_binding_exact_fields",
    "tests/test_cut4_r11_journal_replay.py::test_prior_envelope_canonical_digest_recomputed",
    "tests/test_cut4_r11_journal_replay.py::test_prior_envelope_file_sha_recomputed",
    "tests/test_cut4_r11_journal_replay.py::test_prior_envelope_size_recomputed",
    "tests/test_cut4_r11_journal_replay.py::test_changed_prior_body_changes_request",
    "tests/test_cut4_r11_journal_replay.py::test_changed_prior_file_sha_changes_request",
    "tests/test_cut4_r11_journal_replay.py::test_request_v3_digest_domain",
    "tests/test_cut4_r11_journal_replay.py::test_invocation_preimage_v3_exact_fields",
    "tests/test_cut4_r11_journal_replay.py::test_invocation_preimage_binds_prior_digest",
    "tests/test_cut4_r11_journal_replay.py::test_invocation_preimage_v3_digest_domain",
    "tests/test_cut4_r11_journal_replay.py::test_attempt_session_identity_formula",
    "tests/test_cut4_r11_journal_replay.py::test_attempt_session_identity_changes_prior",
    "tests/test_cut4_r11_journal_replay.py::test_stable_session_core_unchanged",
    "tests/test_cut4_r11_journal_replay.py::test_journal_common_row_exact_fields",
    "tests/test_cut4_r11_journal_replay.py::test_journal_row_id_digest_formula",
    "tests/test_cut4_r11_journal_replay.py::test_journal_sequence_chain",
    "tests/test_cut4_r11_journal_replay.py::test_journal_empty_head_domain",
    "tests/test_cut4_r11_journal_replay.py::test_journal_torn_tail_debt",
    "tests/test_cut4_r11_journal_replay.py::test_attempt_allocated_body_exact",
    "tests/test_cut4_r11_journal_replay.py::test_attempt_id_formula",
    "tests/test_cut4_r11_journal_replay.py::test_attempt_ordinal_not_caller_supplied",
    "tests/test_cut4_r11_journal_replay.py::test_terminal_envelope_body_exact",
    "tests/test_cut4_r11_journal_replay.py::test_terminal_bytes_decode_exact",
    "tests/test_cut4_r11_journal_replay.py::test_terminal_before_public_commit",
    "tests/test_cut4_r11_journal_replay.py::test_unique_terminal_per_attempt",
    "tests/test_cut4_r11_journal_replay.py::test_unique_terminal_per_request",
    "tests/test_cut4_r11_journal_replay.py::test_publication_link_body_exact",
    "tests/test_cut4_r11_journal_replay.py::test_publication_bytes_equal_terminal",
    "tests/test_cut4_r11_journal_replay.py::test_crash_before_terminal_aborted_unobserved",
    "tests/test_cut4_r11_journal_replay.py::test_aborted_unobserved_has_no_envelope",
    "tests/test_cut4_r11_journal_replay.py::test_retry_after_abort_new_attempt_id",
    "tests/test_cut4_r11_journal_replay.py::test_no_identical_rerun_claim_after_abort",
    "tests/test_cut4_r11_journal_replay.py::test_crash_after_terminal_replays_journal_bytes",
    "tests/test_cut4_r11_journal_replay.py::test_completed_request_never_reexecutes_provider",
    "tests/test_cut4_r11_journal_replay.py::test_success_cursor_semantics",
    "tests/test_cut4_r11_journal_replay.py::test_success_empty_cursor_semantics",
    "tests/test_cut4_r11_journal_replay.py::test_partial_cursor_semantics",
    "tests/test_cut4_r11_journal_replay.py::test_timeout_terminal_envelope_journaled",
    "tests/test_cut4_r11_journal_replay.py::test_timeout_cursor_out_empty",
    "tests/test_cut4_r11_journal_replay.py::test_timeout_replay_exact_journal_bytes",
    "tests/test_cut4_r11_journal_replay.py::test_failure_cursor_out_empty",
    "tests/test_cut4_r11_journal_replay.py::test_malformed_cursor_out_empty",
    "tests/test_cut4_r11_journal_replay.py::test_debt_cursor_out_empty",
    "tests/test_cut4_r11_journal_replay.py::test_exhausted_cursor_in_rejected",
    "tests/test_cut4_r11_journal_replay.py::test_terminal_replay_uses_original_cursor_in",
    "tests/test_cut4_r11_journal_replay.py::test_invocation_v4_binds_attempt_allocation",
    "tests/test_cut4_r11_journal_replay.py::test_evidence_identity_binds_attempt",
    "tests/test_cut4_r11_journal_replay.py::test_receipt_identity_binds_attempt",
    "tests/test_cut4_r11_journal_replay.py::test_private_journal_not_public_owner",
    "tests/test_cut4_r11_journal_replay.py::test_journal_publication_reconciliation_total"
  ],
  "private_bytes": [
    "tests/test_cut4_r11_private_bytes.py::test_provider_outcome_id_prefix",
    "tests/test_cut4_r11_private_bytes.py::test_provider_outcome_id_domain",
    "tests/test_cut4_r11_private_bytes.py::test_predicate_evidence_id_prefix",
    "tests/test_cut4_r11_private_bytes.py::test_predicate_evidence_id_domain",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_id_prefix",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_id_domain",
    "tests/test_cut4_r11_private_bytes.py::test_private_evidence_id_prefix",
    "tests/test_cut4_r11_private_bytes.py::test_private_evidence_id_domain",
    "tests/test_cut4_r11_private_bytes.py::test_disposition_id_prefix",
    "tests/test_cut4_r11_private_bytes.py::test_disposition_id_domain",
    "tests/test_cut4_r11_private_bytes.py::test_row_without_id_removes_only_id",
    "tests/test_cut4_r11_private_bytes.py::test_provider_receipt_body_exact_fields",
    "tests/test_cut4_r11_private_bytes.py::test_provider_stream_empty_digest_nonempty",
    "tests/test_cut4_r11_private_bytes.py::test_provider_stream_digest_preimage",
    "tests/test_cut4_r11_private_bytes.py::test_provider_payload_roster_digest",
    "tests/test_cut4_r11_private_bytes.py::test_provider_receipt_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_provider_receipt_identity_formula",
    "tests/test_cut4_r11_private_bytes.py::test_provider_receipt_all_statuses_nonempty",
    "tests/test_cut4_r11_private_bytes.py::test_provider_outcome_v2_exact_field_order",
    "tests/test_cut4_r11_private_bytes.py::test_provider_outcome_embedded_body_equality",
    "tests/test_cut4_r11_private_bytes.py::test_applicability_registry_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_selection_registry_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_explicit_zero_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_predicate_input_body_exact_fields",
    "tests/test_cut4_r11_private_bytes.py::test_predicate_input_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_predicate_evaluation_body_exact_fields",
    "tests/test_cut4_r11_private_bytes.py::test_predicate_evaluation_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_predicate_evidence_v2_exact_field_order",
    "tests/test_cut4_r11_private_bytes.py::test_predicate_embedded_body_repetition",
    "tests/test_cut4_r11_private_bytes.py::test_provider_payload_body_exact_fields",
    "tests/test_cut4_r11_private_bytes.py::test_provider_payload_raw_sha_length",
    "tests/test_cut4_r11_private_bytes.py::test_provider_payload_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_provider_payload_identity_formula",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_v2_exact_field_order",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_embedded_payload_equality",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_kp_equals_plan",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_consumer_tamper_diff",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_flow_tamper_diff",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_predicate_tamper_diff",
    "tests/test_cut4_r11_private_bytes.py::test_provider_private_target_tamper_diff",
    "tests/test_cut4_r11_private_bytes.py::test_normalizer_body_exact_fields",
    "tests/test_cut4_r11_private_bytes.py::test_normalizer_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_normalizer_accepted_rules",
    "tests/test_cut4_r11_private_bytes.py::test_normalizer_rejected_rules",
    "tests/test_cut4_r11_private_bytes.py::test_normalizer_not_evaluated_empty",
    "tests/test_cut4_r11_private_bytes.py::test_private_evidence_v3_exact_field_order",
    "tests/test_cut4_r11_private_bytes.py::test_private_evidence_predicate_digest_join",
    "tests/test_cut4_r11_private_bytes.py::test_private_evidence_provider_digest_join",
    "tests/test_cut4_r11_private_bytes.py::test_private_evidence_normalizer_digest_join",
    "tests/test_cut4_r11_private_bytes.py::test_disposition_v3_exact_field_order",
    "tests/test_cut4_r11_private_bytes.py::test_disposition_shared_fields_equal_evidence",
    "tests/test_cut4_r11_private_bytes.py::test_diff_side_body_exact_fields",
    "tests/test_cut4_r11_private_bytes.py::test_diff_side_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_diff_empty_side_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_diff_source_body_digest_domain",
    "tests/test_cut4_r11_private_bytes.py::test_diff_kind_source_mapping_total",
    "tests/test_cut4_r11_private_bytes.py::test_diff_missing_consumer_mapping",
    "tests/test_cut4_r11_private_bytes.py::test_diff_predicate_mapping",
    "tests/test_cut4_r11_private_bytes.py::test_diff_provider_mapping",
    "tests/test_cut4_r11_private_bytes.py::test_diff_provider_private_mapping",
    "tests/test_cut4_r11_private_bytes.py::test_diff_evidence_disposition_mapping",
    "tests/test_cut4_r11_private_bytes.py::test_diff_completion_mapping",
    "tests/test_cut4_r11_private_bytes.py::test_diff_multiplicity_mapping",
    "tests/test_cut4_r11_private_bytes.py::test_diff_v3_exact_field_order",
    "tests/test_cut4_r11_private_bytes.py::test_diff_v3_id_prefix_domain",
    "tests/test_cut4_r11_private_bytes.py::test_diff_counts_repeat_side_bodies",
    "tests/test_cut4_r11_private_bytes.py::test_all_expanded_kp_multisets_equal",
    "tests/test_cut4_r11_private_bytes.py::test_private_recursive_no_orphan_total"
  ],
  "regression": [
    "tests/test_cut4_r11_regression.py::test_r10_byte_covering_segments_preserved",
    "tests/test_cut4_r11_regression.py::test_r10_negative_dispositions_preserved",
    "tests/test_cut4_r11_regression.py::test_r10_c3_authority_equality_preserved",
    "tests/test_cut4_r11_regression.py::test_r10_predicate_inclusive_kp_preserved",
    "tests/test_cut4_r11_regression.py::test_r10_m3_r3_top_levels_preserved",
    "tests/test_cut4_r11_regression.py::test_r9_neutral_not_applicable_preserved",
    "tests/test_cut4_r11_regression.py::test_r8_membership_d_order_preserved",
    "tests/test_cut4_r11_regression.py::test_r7_single_owner_preserved",
    "tests/test_cut4_r11_regression.py::test_r6_provider_roster_preserved",
    "tests/test_cut4_r11_regression.py::test_legacy_nonadoption_preserved",
    "tests/test_cut4_r11_regression.py::test_artifact_ledger_unchanged",
    "tests/test_cut4_r11_regression.py::test_no_project_root_mutation"
  ]
}
```

Execution order is reference/reach, journal/replay, private bytes, then
regressions. A future fixture worker may own only these new R11 RED fixtures
and evidence. The future implementation remains one atomic DRIVER-owned
cutover/publication change; journal implementation cannot be split into a
second canonical/public owner.
