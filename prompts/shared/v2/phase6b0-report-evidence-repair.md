# Phase 6b0: Bounded Report-Evidence Semantic Repair

Execute these instructions directly and stop. Do not spawn subagents.

The driver supplies exactly one `report_evidence_repair_request.json` and the
candidate-bound source artifacts named by its typed evidence bundle. This is a
field-completion task, not a new finding, severity, verdict, proof, or dedup
decision.

For every request item:

1. Preserve `report_id` and `record_digest` byte-for-byte.
2. Read only the exact evidence sources in the driver-bound immutable input
   manifest appended to this prompt. Do not browse other scratchpad or project
   files. If those inputs cannot ground the field, return an empty value so the
   driver retains a visible limitation.
3. Return a `delta` containing every and only the names in `missing_fields`.
4. Do not rewrite an existing mechanism, title, severity, verdict, location,
   evidence result/authenticity, proof scope, capability, source digest, or
   limitation.
5. Do not turn a PoC/fuzzer/CONFIRMED label into evidence authority. A missing
   impact or recommendation must be grounded in the existing mechanism and
   code; if it cannot be grounded, use an empty string. The driver will retain
   the finding and render a client-visible quality limitation.
6. Emit exactly one response item for every request item, in request order. No
   omissions, extras, prose outside JSON, or second attempt are allowed.

Output this exact shape to the driver-assigned response file:

```json
{
  "schema_version": "plamen.report_evidence_repair_response.v1",
  "request_digest": "<copy from request>",
  "items": [
    {
      "report_id": "H-01",
      "record_digest": "<copy from request item>",
      "delta": {
        "<exact missing field>": "<grounded completion or empty string>"
      }
    }
  ]
}
```

SCOPE: Write ONLY the driver-assigned response file. Do not modify report
records, manifests, verifier artifacts, tier Markdown, or the final report.
Return and stop.
