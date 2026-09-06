"""Typed P0-AI verification-method registry, compiler, and receipts."""
from __future__ import annotations

import hashlib
import bisect
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Mapping, Sequence


REGISTRY_SCHEMA = "plamen.verification_method_registry.v1"
DISPATCH_SCHEMA = "plamen.verification_method_dispatch.v1"
CONTEXT_SCHEMA = "plamen.verification_context_packets.v1"
OPERATOR_PROPOSAL_SCHEMA = "plamen.verification_operator_application.v1"
OPERATOR_RECEIPT_SCHEMA = "plamen.verification_operator_receipt.v1"
REACHABILITY_SCHEMA = "plamen.methodology_reachability.v1"
_REGISTRY_PATH = "verification_policy/verification_method_registry.v1.json"
_REACHABILITY_PATH = "verification_policy/methodology_reachability.v1.json"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_SOURCE_PATH_RE = re.compile(
    r"(?i)(?:[A-Za-z]:[\\/])?[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+)+"
    r"\.(?:sol|rs|move|go|daml)(?::\d+(?:-\d+)?)?"
)
_GRAPH_ARTIFACTS = (
    "caller_map.md", "function_list.md", "state_variables.md", "setter_list.md",
    "xref_map.md", "type_hierarchy.md", "subsystem_map.md",
    "dependency_obligations.json",
)
_GRAPH_GLOBS = ("call_graph*.md", "scip/call_graph*.md", "scip/xref*.md")
_SPECIAL_REACHABILITY_RE = re.compile(
    r"(?i)(?:Independent Skeptic Challenge Boundary|Cross-Batch Consistency Check)"
)
MAX_PRIMARY_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_PRIMARY_ARTIFACT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REFERENCE_GRAPH_ARTIFACTS = 256
MAX_REFERENCE_GRAPH_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_REFERENCE_GRAPH_TOTAL_BYTES = 64 * 1024 * 1024
_WINDOWS_REPARSE_ATTRIBUTE = 0x400


class VerificationMethodError(ValueError):
    """A typed verification-method contract cannot be satisfied safely."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    )


def stable_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attributes & _WINDOWS_REPARSE_ATTRIBUTE)
    except OSError:
        return True


def _primary_artifact_binding(
    artifact: str,
    *,
    scratchpad: Path,
    project_root: Path,
    remaining_bytes: int,
) -> dict[str, Any]:
    """Bind one queue authority to exact local bytes without escaping roots.

    Missing/unsafe/oversized artifacts remain explicit context debt.  They are
    never read from an absolute or parent-traversing path and never silently
    omitted from the packet that determines verifier dispatch identity.
    """

    normalized = artifact.replace("\\", "/").strip()
    base = {
        "artifact": normalized,
        "scope": None,
        "status": "MISSING",
        "sha256": None,
        "size_bytes": None,
    }
    relative = PurePosixPath(normalized)
    if (
        not normalized
        or relative.is_absolute()
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        return {**base, "status": "UNSAFE_PATH"}

    roots: list[tuple[str, Path]] = []
    seen_roots: set[str] = set()
    for scope, root in (("SCRATCHPAD", scratchpad), ("PROJECT", project_root)):
        try:
            resolved_root = root.resolve(strict=True)
        except OSError:
            continue
        key = os.path.normcase(str(resolved_root))
        if key not in seen_roots:
            roots.append((scope, resolved_root))
            seen_roots.add(key)

    for scope, root in roots:
        candidate = root.joinpath(*relative.parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        cursor = root
        unsafe_component = False
        for part in relative.parts:
            cursor = cursor / part
            if _is_reparse_or_symlink(cursor):
                unsafe_component = True
                break
        if unsafe_component:
            return {**base, "scope": scope, "status": "REPARSE_POINT"}
        if not resolved.is_file():
            continue
        try:
            before = resolved.stat()
            if before.st_size > MAX_PRIMARY_ARTIFACT_BYTES:
                return {
                    **base,
                    "scope": scope,
                    "status": "OVERSIZED",
                    "size_bytes": before.st_size,
                }
            raw = resolved.read_bytes()
            after = resolved.stat()
        except OSError:
            return {**base, "scope": scope, "status": "READ_ERROR"}
        if (
            len(raw) > MAX_PRIMARY_ARTIFACT_BYTES
            or len(raw) > max(remaining_bytes, 0)
        ):
            return {
                **base,
                "scope": scope,
                "status": "OVERSIZED",
                "size_bytes": len(raw),
            }
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or after.st_size != len(raw)
        ):
            return {
                **base,
                "scope": scope,
                "status": "CHANGED_DURING_READ",
                "size_bytes": len(raw),
            }
        return {
            **base,
            "scope": scope,
            "status": "BOUND",
            "sha256": _bytes_digest(raw),
            "size_bytes": len(raw),
        }
    return base


def _require_digest(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _DIGEST_RE.fullmatch(text):
        raise VerificationMethodError(f"{field} must be a SHA-256 digest")
    return text


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VerificationMethodError(f"{field} must be non-empty text")
    return value.strip()


def _safe_id(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _SAFE_ID_RE.fullmatch(text):
        raise VerificationMethodError(f"{field} is not a safe identifier")
    return text


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationMethodError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationMethodError(f"{path} must contain a JSON object")
    return value


def _atomic_json_if_changed(path: Path, payload: Mapping[str, Any]) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        if path.read_text(encoding="utf-8", errors="strict") == rendered:
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    os.close(fd)
    temporary = Path(raw)
    try:
        temporary.write_text(rendered, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_verification_method_registry(root: Path | None = None) -> dict[str, Any]:
    base = Path(root) if root is not None else _repo_root()
    payload = _read_json_object(base / _REGISTRY_PATH)
    if payload.get("schema_version") != REGISTRY_SCHEMA:
        raise VerificationMethodError("unsupported verification method registry schema")
    operators = payload.get("operators")
    modules = payload.get("modules")
    if not isinstance(operators, list) or not operators:
        raise VerificationMethodError("verification method registry has no operators")
    if not isinstance(modules, list) or not modules:
        raise VerificationMethodError("verification method registry has no modules")
    operator_ids: set[str] = set()
    for row in operators:
        if not isinstance(row, dict):
            raise VerificationMethodError("operator registry row must be an object")
        operator_id = _safe_id(row.get("operator_id"), "operator_id")
        if operator_id in operator_ids:
            raise VerificationMethodError(f"duplicate operator: {operator_id}")
        operator_ids.add(operator_id)
        _text(row.get("instruction"), f"{operator_id}.instruction")
        if not isinstance(row.get("required_evidence_fields"), list):
            raise VerificationMethodError(f"{operator_id} evidence fields must be a list")
        if not isinstance(row.get("valid_not_applicable_predicates"), list):
            raise VerificationMethodError(f"{operator_id} predicates must be a list")
    module_ids: set[str] = set()
    for row in modules:
        if not isinstance(row, dict):
            raise VerificationMethodError("module registry row must be an object")
        module_id = _safe_id(row.get("module_id"), "module_id")
        if module_id in module_ids:
            raise VerificationMethodError(f"duplicate module: {module_id}")
        module_ids.add(module_id)
        selected = row.get("operator_ids")
        if not isinstance(selected, list) or not selected:
            raise VerificationMethodError(f"{module_id} has no operators")
        unknown = sorted(set(selected) - operator_ids)
        if unknown:
            raise VerificationMethodError(
                f"{module_id} names unknown operators: {', '.join(unknown)}"
            )
        if not isinstance(row.get("selector"), dict):
            raise VerificationMethodError(f"{module_id} selector must be an object")
    return payload


def verification_method_registry_digest(root: Path | None = None) -> str:
    return stable_digest(load_verification_method_registry(root))


def _module_hash(
    module: Mapping[str, Any], operators: Mapping[str, Mapping[str, Any]]
) -> str:
    return stable_digest({
        "module_id": module["module_id"],
        "selector": module["selector"],
        "operators": [operators[value] for value in module["operator_ids"]],
    })


def _normalize_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    work_item_id = (
        raw.get("work_item_id") or raw.get("finding id") or raw.get("finding_id")
    )
    poc_class = raw.get("poc_class") or raw.get("poc class") or "structural"
    bug_class = raw.get("bug_class") or raw.get("bug class") or "unclassified"
    constituents_raw = raw.get("constituents") or []
    if isinstance(constituents_raw, str):
        constituents_raw = [
            value for value in re.split(r"[,;|\s]+", constituents_raw) if value
        ]
    if not isinstance(constituents_raw, list):
        raise VerificationMethodError("constituents must be an array or text")
    constituents = [_safe_id(value, "constituent") for value in constituents_raw]
    if len(constituents) != len(set(constituents)):
        raise VerificationMethodError("constituents must be unique")
    locations_raw = raw.get("location_records")
    if locations_raw is None:
        location = raw.get("location") or raw.get("Location")
        locations_raw = [] if not location else [{
            "artifact": str(location), "start_line": None, "end_line": None,
            "symbol": None, "note": None,
        }]
    if not isinstance(locations_raw, list):
        raise VerificationMethodError("location_records must be an array")
    locations: list[dict[str, Any]] = []
    for value in locations_raw:
        if not isinstance(value, Mapping):
            raise VerificationMethodError("location record must be an object")
        artifact = _text(str(value.get("artifact") or ""), "location.artifact")
        start = value.get("start_line")
        end = value.get("end_line")
        if start is not None and (isinstance(start, bool) or not isinstance(start, int)):
            raise VerificationMethodError("location.start_line must be integer or null")
        if end is not None and (isinstance(end, bool) or not isinstance(end, int)):
            raise VerificationMethodError("location.end_line must be integer or null")
        locations.append({
            "artifact": artifact,
            "start_line": start,
            "end_line": end,
            "symbol": str(value.get("symbol") or "").strip() or None,
            "note": str(value.get("note") or "").strip() or None,
        })
    artifacts_raw = raw.get("primary_artifacts")
    if artifacts_raw is None:
        artifacts_raw = raw.get("primary artifact") or raw.get("primary_artifact") or []
    if isinstance(artifacts_raw, str):
        artifacts_raw = [artifacts_raw] if artifacts_raw.strip() else []
    if not isinstance(artifacts_raw, list):
        raise VerificationMethodError("primary_artifacts must be an array or text")
    semantic_claim = {
        "title": str(raw.get("title") or "").strip(),
        "constituents": constituents,
        "location_records": locations,
        "primary_artifacts": [
            _text(str(value), "primary_artifact") for value in artifacts_raw
        ],
    }
    return {
        "work_item_id": _safe_id(work_item_id, "work_item_id"),
        "poc_class": _safe_id(
            str(poc_class).replace(" ", "-"), "poc_class"
        ).lower(),
        "bug_class": _text(str(bug_class), "bug_class"),
        "semantic_claim": semantic_claim,
        "semantic_claim_digest": stable_digest(semantic_claim),
    }


def _selector_matches(
    selector: Mapping[str, Any],
    *,
    pipeline: str,
    ecosystem: str,
    row: Mapping[str, Any],
) -> bool:
    if selector.get("pipelines") is not None and pipeline not in selector["pipelines"]:
        return False
    if selector.get("ecosystems") is not None and ecosystem not in selector["ecosystems"]:
        return False
    if selector.get("poc_classes") is not None and row["poc_class"] not in selector["poc_classes"]:
        return False
    if selector.get("bug_class_terms") is not None:
        normalized = row["bug_class"].casefold()
        if not any(str(term).casefold() in normalized for term in selector["bug_class_terms"]):
            return False
    return True


def _selected_modules_for_row(
    registry: Mapping[str, Any],
    *,
    pipeline: str,
    ecosystem: str,
    row: Mapping[str, Any],
) -> list[dict[str, Any]]:
    selected = [
        module for module in registry["modules"]
        if _selector_matches(
            module["selector"], pipeline=pipeline, ecosystem=ecosystem, row=row
        )
    ]
    if not selected:
        raise VerificationMethodError(
            f"no method modules selected for {row['work_item_id']}"
        )
    return selected


def _packet_map(
    value: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    if isinstance(value, Mapping):
        if "packets" in value:
            rows = value["packets"]
            if not isinstance(rows, list):
                raise VerificationMethodError("context packets must be a list")
            return {str(row["work_item_id"]): dict(row) for row in rows}
        return {str(key): dict(row) for key, row in value.items()}
    return {str(row["work_item_id"]): dict(row) for row in value}


def _validate_context_packet(
    packet: Mapping[str, Any], work_item_id: str
) -> dict[str, Any]:
    if packet.get("work_item_id") != work_item_id:
        raise VerificationMethodError(
            f"context packet identity mismatch for {work_item_id}"
        )
    if packet.get("state") not in {"RESOLVED", "CONTEXT_UNRESOLVED"}:
        raise VerificationMethodError(
            f"invalid context packet state for {work_item_id}"
        )
    claimed = _require_digest(packet.get("packet_digest"), "packet_digest")
    unsigned = {key: value for key, value in packet.items() if key != "packet_digest"}
    if claimed != stable_digest(unsigned):
        raise VerificationMethodError(
            f"context packet digest mismatch for {work_item_id}"
        )
    candidates = packet.get("expansion_candidates")
    if (
        not isinstance(candidates, list)
        or any(not isinstance(value, str) or not value.strip() for value in candidates)
        or len(candidates) != len(set(candidates))
    ):
        raise VerificationMethodError(
            f"context expansion candidates are invalid for {work_item_id}"
        )
    bindings = packet.get("primary_artifact_bindings")
    if not isinstance(bindings, list):
        raise VerificationMethodError(
            f"primary artifact bindings are absent for {work_item_id}"
        )
    binding_statuses = {
        "BOUND", "MISSING", "UNSAFE_PATH", "REPARSE_POINT", "OVERSIZED",
        "READ_ERROR", "CHANGED_DURING_READ",
    }
    seen_artifacts: set[str] = set()
    bound_total = 0
    complete = True
    for index, binding in enumerate(bindings):
        if not isinstance(binding, Mapping) or set(binding) != {
            "artifact", "scope", "status", "sha256", "size_bytes"
        }:
            raise VerificationMethodError(
                f"primary artifact binding {index} is malformed for {work_item_id}"
            )
        artifact = str(binding.get("artifact") or "")
        if not artifact or artifact in seen_artifacts:
            raise VerificationMethodError(
                f"primary artifact binding identity is invalid for {work_item_id}"
            )
        seen_artifacts.add(artifact)
        status = binding.get("status")
        scope = binding.get("scope")
        size = binding.get("size_bytes")
        if status not in binding_statuses or scope not in {None, "SCRATCHPAD", "PROJECT"}:
            raise VerificationMethodError(
                f"primary artifact binding state is invalid for {work_item_id}"
            )
        if status == "BOUND":
            if scope is None:
                raise VerificationMethodError(
                    f"bound primary artifact has no scope for {work_item_id}"
                )
            _require_digest(binding.get("sha256"), "primary artifact sha256")
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or size > MAX_PRIMARY_ARTIFACT_BYTES
            ):
                raise VerificationMethodError(
                    f"bound primary artifact size is invalid for {work_item_id}"
                )
            bound_total += size
        else:
            complete = False
            if binding.get("sha256") is not None:
                raise VerificationMethodError(
                    f"unbound primary artifact carries a digest for {work_item_id}"
                )
            if size is not None and (
                isinstance(size, bool) or not isinstance(size, int) or size < 0
            ):
                raise VerificationMethodError(
                    f"unbound primary artifact size is invalid for {work_item_id}"
                )
    if bound_total > MAX_PRIMARY_ARTIFACT_TOTAL_BYTES:
        raise VerificationMethodError(
            f"primary artifact binding bytes exceed the aggregate bound for {work_item_id}"
        )
    if packet.get("primary_artifact_binding_complete") is not complete:
        raise VerificationMethodError(
            f"primary artifact completeness flag mismatch for {work_item_id}"
        )
    if not isinstance(packet.get("graph_binding_complete"), bool):
        raise VerificationMethodError(
            f"reference graph completeness flag is absent for {work_item_id}"
        )
    if packet.get("state") == "RESOLVED" and (
        not complete
        or not packet["graph_binding_complete"]
        or not packet.get("graph_matches")
    ):
        raise VerificationMethodError(
            f"resolved context lacks graph/primary authority for {work_item_id}"
        )
    return dict(packet)


def _render_compiled_prompt(
    *,
    dispatch_id: str,
    pipeline: str,
    ecosystem: str,
    backend: str,
    manifest_path: str,
    scratchpad_path: str,
    modules: Sequence[Mapping[str, Any]],
    operators: Mapping[str, Mapping[str, Any]],
    rows: Sequence[Mapping[str, Any]],
    output_contract: Mapping[str, Any],
) -> str:
    module_lines = [
        f"- {row['module_id']} SHA-256 {row['module_sha256']}" for row in modules
    ]
    operator_ids: list[str] = []
    for module in modules:
        for operator_id in module["operator_ids"]:
            if operator_id not in operator_ids:
                operator_ids.append(operator_id)
    operator_lines = [
        f"{index}. {operator_id}: {operators[operator_id]['instruction']}"
        for index, operator_id in enumerate(operator_ids, start=1)
    ]
    row_lines = [
        (
            f"- {row['work_item_id']} | PoC {row['poc_class']} | context "
            f"{row['context_packet_digest']} | modules "
            + ", ".join(row["module_ids"])
            + f" | semantic claim {row['semantic_claim_digest']}"
        )
        for row in rows
    ]
    semantic_rows = [
        {
            "work_item_id": row["work_item_id"],
            "semantic_claim_digest": row["semantic_claim_digest"],
            **row["semantic_claim"],
        }
        for row in rows
    ]
    fields = "\n".join(
        f"- {field}:" for field in output_contract["verifier_markdown_fields"]
    )
    return f"""# Compiled Verification Method Contract

This prompt is generated from the versioned generic verification-method
registry. Do not open or concatenate legacy ecosystem verification prompts.
Skeptic/judge and cross-batch analysis are independent phases and are not part
of this writer contract.

## Dispatch identity

- Method dispatch ID: {dispatch_id}
- Pipeline/ecosystem/backend: {pipeline} / {ecosystem} / {backend}
- Assigned manifest: {manifest_path}
- Bound context packet artifact: {scratchpad_path}/verification_context_packets.json

Selected modules:
{chr(10).join(module_lines)}

## Per-row order of operations

Apply these operators in order. Classify the claimed bug class before any
REFUTED, FALSE_POSITIVE, SAFE, or equivalent negative disposition.

{chr(10).join(operator_lines)}

For context closure, start with the bound packet. You may use one bounded
expansion selected from that packet. If the harm premise remains open, record
CONTEXT_UNRESOLVED, retain the candidate as CONTESTED, and emit evidence debt.
Missing context is never evidence of safety.

## Assigned rows and module binding

{chr(10).join(row_lines)}

Exact semantic claim records (digest-bound above):

```json
{_canonical_json(semantic_rows)}
```

Read only the assigned manifest, exact queue locations/primary artifacts, the
bound context packet, one selected expansion if needed, and the execution
protocol. Do not bulk-read unrelated verifier outputs or the scratchpad.

## Required output per row

Write verify_<ID>.md, verify_<ID>.severity_proposal.json, and
verify_<ID>.operator_application.json.

The Markdown must contain:
{fields}

It also contains the PoC Attempt and Execution Result ledgers. Rules Applied:
lists operator IDs but is not a substitute for the typed application proposal.

The operator proposal uses schema {OPERATOR_PROPOSAL_SCHEMA}. It binds this
method_dispatch_id, exact selected module hashes, context packet digest, and
every selected operator exactly once as APPLIED, NOT_APPLICABLE, or BLOCKED.
APPLIED has source/detail evidence. NOT_APPLICABLE has a registry predicate.
BLOCKED has a debt code and evidence. At most one context expansion is allowed.

New observations are proposal-only objects with title, mechanism, location,
and evidence. They have no severity or verdict authority. The driver validates
the proposal and writes verify_<ID>.operator_receipt.json. Do not write that
driver receipt. A verifier cannot self-certify a new observation, skeptic
decision, report tier, or final evidence tag.
"""


def compile_verification_method_dispatch(
    *,
    pipeline: str,
    ecosystem: str,
    backend: str,
    rows: Sequence[Mapping[str, Any]],
    context_packets: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    manifest_path: str,
    scratchpad_path: str,
    root: Path | None = None,
) -> dict[str, Any]:
    pipeline_n = _safe_id(str(pipeline).lower(), "pipeline")
    ecosystem_n = _safe_id(str(ecosystem).lower(), "ecosystem")
    backend_n = _safe_id(str(backend).lower(), "backend")
    if pipeline_n not in {"sc", "l1"}:
        raise VerificationMethodError("pipeline must be sc or l1")
    if backend_n not in {"claude", "codex"}:
        raise VerificationMethodError("backend must be claude or codex")
    if not rows:
        raise VerificationMethodError("verification method dispatch has no rows")
    registry = load_verification_method_registry(root)
    operators = {row["operator_id"]: row for row in registry["operators"]}
    normalized_rows = [_normalize_row(row) for row in rows]
    if len({row["work_item_id"] for row in normalized_rows}) != len(normalized_rows):
        raise VerificationMethodError("verification method dispatch has duplicate rows")
    packets = _packet_map(context_packets)
    module_by_id: dict[str, dict[str, Any]] = {}
    dispatch_rows: list[dict[str, Any]] = []
    for row in normalized_rows:
        packet = _validate_context_packet(
            packets.get(row["work_item_id"], {}), row["work_item_id"]
        )
        packet_artifacts = [
            binding["artifact"]
            for binding in packet["primary_artifact_bindings"]
        ]
        if packet_artifacts != row["semantic_claim"]["primary_artifacts"]:
            raise VerificationMethodError(
                "context packet primary artifact denominator mismatch for "
                + row["work_item_id"]
            )
        selected = _selected_modules_for_row(
            registry, pipeline=pipeline_n, ecosystem=ecosystem_n, row=row
        )
        module_hashes: dict[str, str] = {}
        operator_ids: list[str] = []
        for module in selected:
            module_hash = _module_hash(module, operators)
            module_hashes[module["module_id"]] = module_hash
            module_by_id[module["module_id"]] = {
                **module,
                "module_sha256": module_hash,
            }
            for operator_id in module["operator_ids"]:
                if operator_id not in operator_ids:
                    operator_ids.append(operator_id)
        dispatch_rows.append({
            **row,
            "module_ids": list(module_hashes),
            "module_hashes": module_hashes,
            "operator_ids": operator_ids,
            "context_packet_id": packet["packet_id"],
            "context_packet_digest": packet["packet_digest"],
            "context_state": packet["state"],
            "context_expansion_candidates": list(
                packet["expansion_candidates"]
            ),
        })
    selected_modules = [module_by_id[key] for key in sorted(module_by_id)]
    unsigned = {
        "schema_version": DISPATCH_SCHEMA,
        "registry_schema_version": registry["schema_version"],
        "registry_version": registry["registry_version"],
        "registry_digest": stable_digest(registry),
        "pipeline": pipeline_n,
        "ecosystem": ecosystem_n,
        "backend": backend_n,
        "manifest_path": str(
            PurePosixPath(str(manifest_path).replace("\\", "/"))
        ),
        "scratchpad_path": str(scratchpad_path),
        "selected_modules": selected_modules,
        "selected_module_ids": [row["module_id"] for row in selected_modules],
        "rows": dispatch_rows,
        "output_contract": registry["output_contract"],
    }
    dispatch_id = "VMD-" + stable_digest(unsigned).upper()
    prompt = _render_compiled_prompt(
        dispatch_id=dispatch_id,
        pipeline=pipeline_n,
        ecosystem=ecosystem_n,
        backend=backend_n,
        manifest_path=unsigned["manifest_path"],
        scratchpad_path=str(scratchpad_path),
        modules=selected_modules,
        operators=operators,
        rows=dispatch_rows,
        output_contract=registry["output_contract"],
    )
    return {
        **unsigned,
        "dispatch_id": dispatch_id,
        "prompt_sha256": _bytes_digest(prompt.encode("utf-8")),
        "prompt_size_bytes": len(prompt.encode("utf-8")),
        "prompt_markdown": prompt,
    }


def dispatch_receipt_payload(dispatch: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in dispatch.items() if key != "prompt_markdown"}


def write_or_validate_method_dispatch(
    path: Path, dispatch: Mapping[str, Any]
) -> dict[str, Any]:
    payload = dispatch_receipt_payload(dispatch)
    target = Path(path)
    if target.is_file():
        existing = _read_json_object(target)
        if existing != payload:
            raise VerificationMethodError(
                "existing method dispatch differs from current method/context"
            )
        return existing
    _atomic_json_if_changed(target, payload)
    return payload


def _row_locations(raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    records = raw.get("location_records")
    if isinstance(records, list):
        return [dict(value) for value in records if isinstance(value, Mapping)]
    location = raw.get("location") or raw.get("Location")
    if not location:
        return []
    return [{
        "artifact": str(location), "start_line": None, "end_line": None,
        "symbol": None,
    }]


def _normalized_location(record: Mapping[str, Any]) -> str:
    artifact = str(record.get("artifact") or "").strip().replace("\\", "/")
    start = record.get("start_line")
    end = record.get("end_line")
    symbol = str(record.get("symbol") or "").strip()
    suffix = ""
    if isinstance(start, int):
        suffix = f":{start}" + (f"-{end}" if isinstance(end, int) else "")
    if symbol:
        suffix += f":{symbol}"
    return artifact + suffix


def _context_tokens(
    locations: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    tokens: set[str] = set()
    for record in locations:
        artifact = str(record.get("artifact") or "").replace("\\", "/")
        name = PurePosixPath(artifact).name
        stem = PurePosixPath(name).stem
        symbol = str(record.get("symbol") or "").strip()
        for token in (name, stem, symbol):
            if len(token) >= 3:
                tokens.add(token.casefold())
    return tuple(sorted(tokens, key=lambda item: (-len(item), item)))


def _reference_graph_paths(scratchpad: Path) -> tuple[list[Path], bool]:
    """Enumerate a deterministic bounded lexical graph denominator."""

    root = Path(scratchpad)
    selected: list[tuple[str, Path]] = []
    seen: set[str] = set()
    overflow = False

    def consider(path: Path) -> None:
        nonlocal overflow
        key = path.relative_to(root).as_posix()
        folded = key.casefold()
        if folded in seen:
            return
        seen.add(folded)
        pair = (key, path)
        bisect.insort(selected, pair, key=lambda value: value[0])
        if len(selected) > MAX_REFERENCE_GRAPH_ARTIFACTS:
            selected.pop()
            overflow = True

    for name in _GRAPH_ARTIFACTS:
        path = root / name
        if path.exists() or path.is_symlink():
            consider(path)
    for pattern in _GRAPH_GLOBS:
        pure = PurePosixPath(pattern)
        directory = root.joinpath(*pure.parts[:-1])
        leaf_pattern = pure.parts[-1]
        try:
            entries = directory.iterdir()
            for path in entries:
                if fnmatch.fnmatchcase(path.name, leaf_pattern):
                    consider(path)
        except OSError:
            continue
    return [path for _key, path in selected], overflow


def _extract_expansion_candidates(text: str, *, limit: int) -> list[str]:
    values: list[str] = []
    for match in _SOURCE_PATH_RE.finditer(text):
        normalized = match.group(0).replace("\\", "/")
        normalized = re.sub(r":\d+(?:-\d+)?$", "", normalized)
        if normalized not in values:
            values.append(normalized)
        if len(values) >= limit:
            break
    return values


def build_verification_context_packets(
    *,
    rows: Sequence[Mapping[str, Any]],
    scratchpad: Path,
    project_root: Path,
    fanout_limit: int = 8,
    max_excerpt_chars: int = 240,
) -> dict[str, Any]:
    if isinstance(fanout_limit, bool) or fanout_limit < 1 or fanout_limit > 64:
        raise VerificationMethodError("fanout_limit must be in [1,64]")
    if isinstance(max_excerpt_chars, bool) or max_excerpt_chars < 40:
        raise VerificationMethodError("max_excerpt_chars must be at least 40")
    scratch = Path(scratchpad)
    project = Path(project_root)
    graph_records = []
    graph_bindings: list[dict[str, Any]] = []
    graph_paths, graph_overflow = _reference_graph_paths(scratch)
    graph_total = 0
    if graph_overflow:
        graph_bindings.append({
            "artifact": "*",
            "status": "CARDINALITY_EXCEEDED",
            "sha256": None,
            "size_bytes": None,
        })
    for path in graph_paths:
        artifact = path.relative_to(scratch).as_posix()
        binding: dict[str, Any] = {
            "artifact": artifact,
            "status": "READ_ERROR",
            "sha256": None,
            "size_bytes": None,
        }
        if _is_reparse_or_symlink(path):
            graph_bindings.append({**binding, "status": "REPARSE_POINT"})
            continue
        try:
            before = path.stat()
        except OSError:
            graph_bindings.append(binding)
            continue
        if (
            before.st_size > MAX_REFERENCE_GRAPH_ARTIFACT_BYTES
            or graph_total + before.st_size > MAX_REFERENCE_GRAPH_TOTAL_BYTES
        ):
            graph_bindings.append({
                **binding,
                "status": "OVERSIZED",
                "size_bytes": before.st_size,
            })
            continue
        try:
            raw = path.read_bytes()
            after = path.stat()
        except OSError:
            graph_bindings.append(binding)
            continue
        if (
            len(raw) > MAX_REFERENCE_GRAPH_ARTIFACT_BYTES
            or graph_total + len(raw) > MAX_REFERENCE_GRAPH_TOTAL_BYTES
        ):
            graph_bindings.append({
                **binding, "status": "OVERSIZED", "size_bytes": len(raw)
            })
            continue
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or after.st_size != len(raw)
        ):
            graph_bindings.append({
                **binding,
                "status": "CHANGED_DURING_READ",
                "size_bytes": len(raw),
            })
            continue
        digest = _bytes_digest(raw)
        graph_total += len(raw)
        graph_bindings.append({
            "artifact": artifact,
            "status": "BOUND",
            "sha256": digest,
            "size_bytes": len(raw),
        })
        graph_records.append({
            "path": path,
            "artifact": artifact,
            "sha256": digest,
            "lines": raw.decode("utf-8", errors="replace").splitlines(),
        })
    graph_binding_complete = all(
        row["status"] == "BOUND" for row in graph_bindings
    )
    packets: list[dict[str, Any]] = []
    for raw_row in rows:
        normalized_row = _normalize_row(raw_row)
        work_item_id = normalized_row["work_item_id"]
        locations = _row_locations(raw_row)
        seeds = [
            _normalized_location(record) for record in locations
            if _normalized_location(record)
        ]
        tokens = _context_tokens(locations)
        all_matches: list[dict[str, Any]] = []
        expansion_values: list[str] = []
        for graph in graph_records:
            for lineno, line in enumerate(graph["lines"], start=1):
                folded = line.casefold()
                if not tokens or not any(token in folded for token in tokens):
                    continue
                excerpt = re.sub(r"\s+", " ", line).strip()[:max_excerpt_chars]
                all_matches.append({
                    "artifact": graph["artifact"],
                    "artifact_sha256": graph["sha256"],
                    "line": lineno,
                    "excerpt": excerpt,
                })
                for value in _extract_expansion_candidates(
                    line, limit=fanout_limit
                ):
                    if value not in expansion_values:
                        expansion_values.append(value)
        # A bounded sibling set provides the one-expansion candidates when the
        # graph is sparse. It never changes the packet from unresolved to
        # resolved; only an actual reference-graph match does that.
        for record in locations:
            artifact = str(record.get("artifact") or "").replace("\\", "/")
            candidate = project / artifact
            if not candidate.is_file():
                continue
            try:
                siblings = sorted(
                    value for value in candidate.parent.iterdir()
                    if value.is_file() and value.suffix.lower()
                    in {".sol", ".rs", ".move", ".go", ".daml"}
                )
            except OSError:
                siblings = []
            for sibling in siblings:
                try:
                    relative = sibling.relative_to(project).as_posix()
                except ValueError:
                    continue
                if relative != artifact and relative not in expansion_values:
                    expansion_values.append(relative)
                if len(expansion_values) >= fanout_limit:
                    break
        matches = all_matches[:fanout_limit]
        primary_bindings: list[dict[str, Any]] = []
        bound_bytes = 0
        for artifact in normalized_row["semantic_claim"]["primary_artifacts"]:
            binding = _primary_artifact_binding(
                artifact,
                scratchpad=scratch,
                project_root=project,
                remaining_bytes=MAX_PRIMARY_ARTIFACT_TOTAL_BYTES - bound_bytes,
            )
            primary_bindings.append(binding)
            if binding["status"] == "BOUND":
                bound_bytes += int(binding["size_bytes"])
        binding_complete = all(
            row["status"] == "BOUND" for row in primary_bindings
        )
        unsigned_packet = {
            "packet_id": f"VCTX-{work_item_id}",
            "work_item_id": work_item_id,
            "state": (
                "RESOLVED"
                if matches and binding_complete and graph_binding_complete
                else "CONTEXT_UNRESOLVED"
            ),
            "seed_locations": seeds,
            "graph_matches": matches,
            "expansion_candidates": expansion_values[:fanout_limit],
            "hub_truncated": len(all_matches) > fanout_limit,
            "fanout_limit": fanout_limit,
            "primary_artifact_bindings": primary_bindings,
            "primary_artifact_binding_complete": binding_complete,
            "graph_binding_complete": graph_binding_complete,
        }
        packets.append({
            **unsigned_packet, "packet_digest": stable_digest(unsigned_packet)
        })
    unsigned = {
        "schema_version": CONTEXT_SCHEMA,
        "project_root": str(project.resolve()),
        "scratchpad": str(scratch.resolve()),
        "graph_artifacts": [
            {"artifact": row["artifact"], "sha256": row["sha256"]}
            for row in graph_records
        ],
        "graph_artifact_bindings": graph_bindings,
        "graph_binding_complete": graph_binding_complete,
        "packet_count": len(packets),
        "packets": packets,
    }
    return {**unsigned, "context_digest": stable_digest(unsigned)}


def write_or_validate_context_packets(
    path: Path, payload: Mapping[str, Any]
) -> dict[str, Any]:
    if payload.get("schema_version") != CONTEXT_SCHEMA:
        raise VerificationMethodError("unsupported context packet schema")
    claimed = _require_digest(payload.get("context_digest"), "context_digest")
    unsigned = {key: value for key, value in payload.items() if key != "context_digest"}
    if claimed != stable_digest(unsigned):
        raise VerificationMethodError("context packet aggregate digest mismatch")
    target = Path(path)
    if target.is_file():
        existing = _read_json_object(target)
        if existing != dict(payload):
            raise VerificationMethodError(
                "existing context packets differ from current graph/rows"
            )
        return existing
    _atomic_json_if_changed(target, payload)
    return dict(payload)


def _dispatch_row(
    dispatch: Mapping[str, Any], work_item_id: str
) -> dict[str, Any]:
    matches = [
        row for row in dispatch.get("rows", [])
        if row.get("work_item_id") == work_item_id
    ]
    if len(matches) != 1:
        raise VerificationMethodError(
            f"dispatch does not contain exactly one row for {work_item_id}"
        )
    return dict(matches[0])


def validate_operator_application_proposal(
    proposal: Mapping[str, Any],
    *,
    dispatch: Mapping[str, Any],
    verdict: str = "CONTESTED",
    root: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(proposal, Mapping):
        raise VerificationMethodError(
            "operator application proposal must be an object"
        )
    if proposal.get("schema_version") != OPERATOR_PROPOSAL_SCHEMA:
        raise VerificationMethodError(
            "unsupported operator application proposal schema"
        )
    work_item_id = _safe_id(proposal.get("work_item_id"), "work_item_id")
    if proposal.get("method_dispatch_id") != dispatch.get("dispatch_id"):
        raise VerificationMethodError("method dispatch ID mismatch")
    row = _dispatch_row(dispatch, work_item_id)
    if proposal.get("selected_module_hashes") != row["module_hashes"]:
        raise VerificationMethodError("selected module hash binding mismatch")
    if proposal.get("context_packet_digest") != row["context_packet_digest"]:
        raise VerificationMethodError("context packet digest binding mismatch")
    context_status = proposal.get("context_status")
    if context_status not in {
        "RESOLVED", "EXPANDED_RESOLVED", "CONTEXT_UNRESOLVED",
    }:
        raise VerificationMethodError("invalid context_status")
    expansion = proposal.get("context_expansion")
    limit = int(dispatch["output_contract"]["context_expansion_limit"])
    if not isinstance(expansion, list) or len(expansion) > limit:
        raise VerificationMethodError("context expansion exceeds the bounded limit")
    if any(
        not isinstance(value, str)
        or value not in row["context_expansion_candidates"]
        for value in expansion
    ):
        raise VerificationMethodError(
            "context expansion was not issued by the bound context packet"
        )
    if context_status == "EXPANDED_RESOLVED" and len(expansion) != 1:
        raise VerificationMethodError(
            "expanded context must name exactly one expansion"
        )
    # The proposal is model-authored and therefore cannot upgrade a context
    # packet whose mechanically bound graph or primary artifacts were
    # incomplete.  A bounded expansion name alone is not evidence that the
    # selected file was read, byte-bound, and restored the missing
    # prerequisite.  A future expansion workflow may produce a newly compiled
    # packet/dispatch after performing those checks; until then the original
    # dispatch remains unresolved and terminal-negative authority is withheld.
    if (
        row["context_state"] == "CONTEXT_UNRESOLVED"
        and context_status != "CONTEXT_UNRESOLVED"
    ):
        raise VerificationMethodError(
            "operator proposal cannot upgrade mechanically unresolved context"
        )
    if (
        context_status == "CONTEXT_UNRESOLVED"
        and row["context_state"] == "RESOLVED"
        and not expansion
    ):
        raise VerificationMethodError(
            "resolved packet requires bounded expansion before CONTEXT_UNRESOLVED"
        )
    operator_rows = proposal.get("operators")
    if not isinstance(operator_rows, list):
        raise VerificationMethodError("operators must be a list")
    ids = [
        item.get("operator_id")
        for item in operator_rows
        if isinstance(item, Mapping)
    ]
    if ids != row["operator_ids"]:
        raise VerificationMethodError(
            "operator denominator/order differs from method dispatch"
        )
    registry = load_verification_method_registry(root)
    definitions = {item["operator_id"]: item for item in registry["operators"]}
    allowed_debts = set(registry["debt_codes"])
    checked_operators: list[dict[str, Any]] = []
    debts: list[dict[str, Any]] = []
    for item in operator_rows:
        if not isinstance(item, Mapping):
            raise VerificationMethodError(
                "operator application row must be an object"
            )
        operator_id = item["operator_id"]
        status = item.get("status")
        evidence = item.get("evidence")
        predicate = item.get("predicate")
        debt_code = item.get("debt_code")
        blocker_evidence = item.get("blocker_evidence")
        if status not in {"APPLIED", "NOT_APPLICABLE", "BLOCKED"}:
            raise VerificationMethodError(
                f"{operator_id} has invalid application status"
            )
        if not isinstance(evidence, list) or not isinstance(
            blocker_evidence, list
        ):
            raise VerificationMethodError(
                f"{operator_id} evidence fields must be lists"
            )
        if status == "APPLIED":
            if not evidence:
                raise VerificationMethodError(
                    f"{operator_id} APPLIED requires evidence"
                )
            required = set(
                definitions[operator_id]["required_evidence_fields"]
            )
            for record in evidence:
                if (
                    not isinstance(record, Mapping)
                    or any(
                        not str(record.get(field) or "").strip()
                        for field in required
                    )
                ):
                    raise VerificationMethodError(
                        f"{operator_id} APPLIED evidence is incomplete"
                    )
            if predicate is not None or debt_code is not None or blocker_evidence:
                raise VerificationMethodError(
                    f"{operator_id} APPLIED has incompatible fields"
                )
        elif status == "NOT_APPLICABLE":
            allowed = set(
                definitions[operator_id]["valid_not_applicable_predicates"]
            )
            if predicate not in allowed:
                raise VerificationMethodError(
                    f"{operator_id} NOT_APPLICABLE predicate is invalid"
                )
            if evidence or debt_code is not None or blocker_evidence:
                raise VerificationMethodError(
                    f"{operator_id} NOT_APPLICABLE has incompatible fields"
                )
        else:
            if debt_code not in allowed_debts:
                raise VerificationMethodError(
                    f"{operator_id} BLOCKED debt code is invalid"
                )
            if (
                not blocker_evidence
                or any(not str(value or "").strip() for value in blocker_evidence)
            ):
                raise VerificationMethodError(
                    f"{operator_id} BLOCKED requires blocker evidence"
                )
            if evidence or predicate is not None:
                raise VerificationMethodError(
                    f"{operator_id} BLOCKED has incompatible fields"
                )
            debts.append({
                "operator_id": operator_id,
                "debt_code": debt_code,
                "blocker_evidence": list(blocker_evidence),
                "report_visible": True,
                "terminal_authority": False,
            })
        checked_operators.append(dict(item))
    observations = proposal.get("new_observations")
    if not isinstance(observations, list):
        raise VerificationMethodError("new_observations must be a list")
    checked_observations: list[dict[str, Any]] = []
    for item in observations:
        if not isinstance(item, Mapping):
            raise VerificationMethodError("new observation must be an object")
        observation = {
            key: _text(item.get(key), f"new_observation.{key}")
            for key in ("title", "mechanism", "location", "evidence")
        }
        if any(
            key in item for key in ("verdict", "severity", "evidence_tag")
        ):
            raise VerificationMethodError(
                "new observation cannot self-certify verdict/severity"
            )
        checked_observations.append({
            **observation,
            "candidate_state": "PROPOSED",
            "terminal_authority": False,
            "source_work_item_id": work_item_id,
        })
    terminal = set(
        dispatch["output_contract"].get(
            "terminal_negative_tokens",
            ["REFUTED", "FALSE_POSITIVE", "SAFE", "DISMISSED"],
        )
    )
    verdict_n = str(verdict or "").strip().upper().replace(" ", "_")
    if (
        debts or context_status == "CONTEXT_UNRESOLVED"
    ) and verdict_n in terminal:
        raise VerificationMethodError(
            "terminal negative is forbidden while method/context debt remains"
        )
    return {
        "schema_version": OPERATOR_PROPOSAL_SCHEMA,
        "work_item_id": work_item_id,
        "method_dispatch_id": dispatch["dispatch_id"],
        "selected_module_hashes": dict(row["module_hashes"]),
        "context_packet_digest": row["context_packet_digest"],
        "context_status": context_status,
        "context_expansion": list(expansion),
        "operators": checked_operators,
        "new_observations": checked_observations,
        "has_blocked_operators": bool(debts),
        "debts": debts,
    }


def bind_operator_application_receipt(
    *,
    proposal_path: Path,
    verify_path: Path,
    receipt_path: Path,
    dispatch: Mapping[str, Any],
    launch_digest: str,
    verdict: str,
    root: Path | None = None,
) -> dict[str, Any]:
    proposal_bytes = Path(proposal_path).read_bytes()
    verify_bytes = Path(verify_path).read_bytes()
    try:
        proposal = json.loads(proposal_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationMethodError(
            f"operator proposal is invalid JSON: {exc}"
        ) from exc
    checked = validate_operator_application_proposal(
        proposal, dispatch=dispatch, verdict=verdict, root=root
    )
    unsigned = {
        "schema_version": OPERATOR_RECEIPT_SCHEMA,
        "work_item_id": checked["work_item_id"],
        "method_dispatch_id": dispatch["dispatch_id"],
        "dispatch_receipt_digest": stable_digest(
            dispatch_receipt_payload(dispatch)
        ),
        "launch_digest": _require_digest(launch_digest, "launch_digest"),
        "proposal_sha256": _bytes_digest(proposal_bytes),
        "verifier_sha256": _bytes_digest(verify_bytes),
        "selected_module_hashes": checked["selected_module_hashes"],
        "context_packet_digest": checked["context_packet_digest"],
        "context_status": checked["context_status"],
        "operators": checked["operators"],
        "debts": checked["debts"],
        "new_observations": checked["new_observations"],
        "application_authority": "APPLICATION_EVIDENCE_ONLY",
        "terminal_authority": False,
    }
    payload = {**unsigned, "receipt_digest": stable_digest(unsigned)}
    target = Path(receipt_path)
    if target.is_file():
        existing = _read_json_object(target)
        if existing != payload:
            raise VerificationMethodError(
                "existing operator receipt is stale or differs"
            )
        return existing
    _atomic_json_if_changed(target, payload)
    return payload


def load_bound_operator_receipt(
    *,
    receipt_path: Path,
    proposal_path: Path,
    verify_path: Path,
    dispatch: Mapping[str, Any],
    launch_digest: str,
) -> dict[str, Any]:
    receipt = _read_json_object(Path(receipt_path))
    if receipt.get("schema_version") != OPERATOR_RECEIPT_SCHEMA:
        raise VerificationMethodError("unsupported operator receipt schema")
    claimed = _require_digest(receipt.get("receipt_digest"), "receipt_digest")
    unsigned = {
        key: value for key, value in receipt.items()
        if key != "receipt_digest"
    }
    if claimed != stable_digest(unsigned):
        raise VerificationMethodError("operator receipt digest mismatch")
    if receipt.get("proposal_sha256") != _bytes_digest(
        Path(proposal_path).read_bytes()
    ):
        raise VerificationMethodError("operator receipt proposal bytes changed")
    if receipt.get("verifier_sha256") != _bytes_digest(
        Path(verify_path).read_bytes()
    ):
        raise VerificationMethodError("operator receipt verifier bytes changed")
    if receipt.get("method_dispatch_id") != dispatch.get("dispatch_id"):
        raise VerificationMethodError("operator receipt dispatch changed")
    if receipt.get("dispatch_receipt_digest") != stable_digest(
        dispatch_receipt_payload(dispatch)
    ):
        raise VerificationMethodError("operator receipt dispatch bytes changed")
    if receipt.get("launch_digest") != _require_digest(
        launch_digest, "launch_digest"
    ):
        raise VerificationMethodError("operator receipt launch changed")
    return receipt


def validate_methodology_reachability(
    root: Path | None = None,
) -> dict[str, Any]:
    base = Path(root) if root is not None else _repo_root()
    manifest_path = base / _REACHABILITY_PATH
    manifest = _read_json_object(manifest_path)
    issues: list[dict[str, Any]] = []
    if manifest.get("schema_version") != REACHABILITY_SCHEMA:
        return {
            "schema_version": REACHABILITY_SCHEMA,
            "ok": False,
            "entries": [],
            "issues": [{
                "code": "INVALID_REACHABILITY_SCHEMA",
                "path": str(manifest_path),
            }],
        }
    entries = manifest.get("entries")
    scan_paths = manifest.get("scan_paths")
    if not isinstance(entries, list) or not isinstance(scan_paths, list):
        raise VerificationMethodError(
            "reachability manifest entries/scan_paths must be lists"
        )
    registry_root = (
        base if (base / _REGISTRY_PATH).is_file() else _repo_root()
    )
    compiled_modules = {
        row["module_id"]
        for row in load_verification_method_registry(registry_root)["modules"]
    }
    compiled_patterns: list[
        tuple[dict[str, Any], re.Pattern[str]]
    ] = []
    seen_rule_ids: set[str] = set()
    allowed_dispositions = {
        "ACTIVE_IN_VERIFIER",
        "MOVED_TO_INDEPENDENT_CONSUMER",
        "RETIRED_WITH_RATIONALE",
    }
    for entry in entries:
        if not isinstance(entry, dict):
            issues.append({"code": "INVALID_REACHABILITY_ENTRY"})
            continue
        rule_id = str(entry.get("rule_id") or "")
        if not rule_id or rule_id in seen_rule_ids:
            issues.append({
                "code": "INVALID_OR_DUPLICATE_RULE_ID",
                "rule_id": rule_id,
            })
        seen_rule_ids.add(rule_id)
        disposition = entry.get("disposition")
        if disposition not in allowed_dispositions:
            issues.append({
                "code": "INVALID_DISPOSITION", "rule_id": rule_id,
            })
        try:
            pattern = re.compile(
                str(entry.get("source_pattern") or ""), re.IGNORECASE
            )
        except re.error as exc:
            issues.append({
                "code": "INVALID_SOURCE_PATTERN",
                "rule_id": rule_id,
                "detail": str(exc),
            })
            continue
        compiled_patterns.append((entry, pattern))
        test_path = entry.get("test_path")
        if not isinstance(test_path, str) or not (base / test_path).is_file():
            issues.append({
                "code": "MISSING_REACHABILITY_TEST", "rule_id": rule_id,
            })
        if disposition == "ACTIVE_IN_VERIFIER":
            module = entry.get("compiled_module")
            if module not in compiled_modules:
                issues.append({
                    "code": "MISSING_COMPILED_MODULE",
                    "rule_id": rule_id,
                    "module": module,
                })
            consumer = entry.get("consumer_path")
            if (
                not isinstance(consumer, str)
                or not (base / consumer).is_file()
            ):
                issues.append({
                    "code": "MISSING_ACTIVE_CONSUMER", "rule_id": rule_id,
                })
            if not entry.get("schema_field"):
                issues.append({
                    "code": "MISSING_ACTIVE_SCHEMA_FIELD", "rule_id": rule_id,
                })
        elif disposition == "MOVED_TO_INDEPENDENT_CONSUMER":
            consumer = entry.get("consumer_path")
            if (
                not isinstance(consumer, str)
                or not (base / consumer).is_file()
            ):
                issues.append({
                    "code": "MISSING_INDEPENDENT_CONSUMER",
                    "rule_id": rule_id,
                })
            if not entry.get("owner") or not entry.get("schema_field"):
                issues.append({
                    "code": "INCOMPLETE_INDEPENDENT_CONSUMER",
                    "rule_id": rule_id,
                })
        else:
            if not str(entry.get("rationale") or "").strip():
                issues.append({
                    "code": "MISSING_RETIREMENT_RATIONALE",
                    "rule_id": rule_id,
                })
            if entry.get("compiled_module") is not None:
                issues.append({
                    "code": "RETIRED_RULE_STILL_COMPILED",
                    "rule_id": rule_id,
                })
    matched_rules: set[str] = set()
    scanned_markers = 0
    for relative in scan_paths:
        path = base / str(relative)
        if not path.is_file():
            issues.append({
                "code": "MISSING_REACHABILITY_SOURCE",
                "path": str(relative),
            })
            continue
        lines = path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        for lineno, line in enumerate(lines, start=1):
            if (
                not re.search(r"(?i)MANDATORY", line)
                and not _SPECIAL_REACHABILITY_RE.search(line)
            ):
                continue
            scanned_markers += 1
            matches = [
                entry for entry, pattern in compiled_patterns
                if pattern.search(line)
            ]
            if not matches:
                issues.append({
                    "code": "ORPHAN_MANDATORY_RULE",
                    "path": str(relative),
                    "line": lineno,
                    "text": line.strip(),
                })
            elif len(matches) > 1:
                issues.append({
                    "code": "AMBIGUOUS_MANDATORY_RULE",
                    "path": str(relative),
                    "line": lineno,
                    "rule_ids": [entry["rule_id"] for entry in matches],
                })
            else:
                matched_rules.add(matches[0]["rule_id"])
    for entry, _pattern in compiled_patterns:
        if entry.get("rule_id") not in matched_rules:
            issues.append({
                "code": "UNREACHABLE_MANIFEST_ENTRY",
                "rule_id": entry.get("rule_id"),
            })
    return {
        "schema_version": REACHABILITY_SCHEMA,
        "ok": not issues,
        "manifest_sha256": _bytes_digest(manifest_path.read_bytes()),
        "scanned_marker_count": scanned_markers,
        "matched_rule_count": len(matched_rules),
        "entries": entries,
        "issues": issues,
    }


__all__ = [
    "REGISTRY_SCHEMA", "DISPATCH_SCHEMA", "CONTEXT_SCHEMA",
    "OPERATOR_PROPOSAL_SCHEMA", "OPERATOR_RECEIPT_SCHEMA",
    "REACHABILITY_SCHEMA", "VerificationMethodError", "stable_digest",
    "load_verification_method_registry",
    "verification_method_registry_digest",
    "compile_verification_method_dispatch", "dispatch_receipt_payload",
    "write_or_validate_method_dispatch",
    "build_verification_context_packets",
    "write_or_validate_context_packets",
    "validate_operator_application_proposal",
    "bind_operator_application_receipt", "load_bound_operator_receipt",
    "validate_methodology_reachability",
]
