# Asset-representation boundary foundation

This foundation is a recall generator and trust boundary, not a wrapped-asset
classifier. It turns mechanically visible native-value/tokenized-asset seams
into exact, independently queueable `asset_representation_boundary`
obligations. Identifier and reference evidence can only add work.

## Closed provenance

Feature evidence has one of three provenance states:

| State | May add context or work? | May suppress exact application work? |
|---|---:|---:|
| `MODEL_PROPOSAL` | yes | no |
| `MECHANICAL_PROVIDER` | yes | no — reserved until a genuine out-of-tree BAKE execution receipt exists |
| `OPERATOR_ATTESTED` | yes | no — reserved until a genuinely operator-owned out-of-tree principal/receipt exists |

Recon schemas v1/v2 and v3 rows without valid provenance degrade to
`MODEL_PROPOSAL`. A `PRESENT` declaration therefore cannot self-certify or
erase classification debt. Unknown providers, stale digests, malformed paths,
and mismatched fact/occurrence bindings reopen work without halting the run.

The optional operator sidecar is
`asset_representation_operator_attestations.json`. Its exact SHA-256 must be
present in the driver-owned checkpoint's `operator_attestation_bindings` map,
but that binding is only a migration/proposal check: both files remain inside
the run's forgeable write boundary. Putting `OPERATOR_ATTESTED` prose in a
model-writable recon artifact is never terminal authority in the current
architecture.

## Provider capability matrix

`asset_representation_foundation.py` owns a closed provider matrix. Current
Slither, SCIP, and source-parse providers expose identifier/reference evidence
but do not guarantee exact asset-representation classification. The reserved
`typed-semantic-v3` entry parses occurrence, source digest, use/def/type, and
relation foundations, but remains non-terminal without an independently bound
provider execution receipt. Unknown providers resolve to `UNAVAILABLE`. The
matrix has a version and canonical digest so a capability change cannot be
silent.

The mechanical-graph v3 foundation accepts typed semantic edges for native
primitive use, type, use/def, value flow, and representation transition. A v2
graph records `EXPECTED_ABSENCE` as local migration metadata and does not
degrade the phase. Malformed v3 rows become exact
`asset_representation_edge_repair` obligations; valid siblings are retained.
No graph edge fabricates terminal coverage.

## Enumeration contract

- Candidates are generic and ecosystem-neutral; no protocol names or expected
  findings are encoded.
- Every exact subject seam receives its own stable candidate and obligation
  alias. Enumeration is not capped at 12.
- Source paths are normalized lexically (`\` to `/`, and manifest-equivalent
  `.` segments removed) so Windows and POSIX separators derive the same
  identity. Case is preserved; POSIX case-distinct paths and symbols remain
  distinct. Absolute, drive-relative, and parent-escaping semantic-edge paths
  are rejected.
- A reported finding applies to one representation alias only when its bound
  finding section carries the generated
  `PLAMEN_SECURITY_OBLIGATION_EVIDENCE` JSON marker. The marker preserves the
  exact alias, relation, subject, object/occurrence, symbol, and casing.
  Hyphens and colons are data, not token separators. Normalized prose,
  identifier overlap, or the receipt's alias claim alone cannot bind a
  sibling.
- The marker schema is closed to exactly six string fields:
  `schema_version`, `alias_id`, `subject_id`, `relation_id`, `object_id`, and
  `symbol`. Missing, extra, non-string, duplicate-key, wrong-schema, or
  conflicting rows are non-binding. Exact complete duplicates are
  idempotent.
- Finding sections follow Markdown heading scope: equal/higher headings end a
  finding, deeper subsections remain inside it, and markers inside backtick or
  tilde fences are ignored. Duplicate or case-fold-colliding finding IDs
  invalidate only that referent.
- Unsafe candidate source spellings emit one exact
  `asset_representation_edge_repair` row while the graph-bound boundary
  candidate remains queueable. The unsafe spelling is excluded from stable
  candidate/repair identity, valid siblings remain intact, and this local debt
  does not add whole-authority degradation.
- Candidates remain `UNACCOUNTED` until the normal independent application and
  verification lifecycle resolves them.
