"""Normalized cross-ecosystem parameter and boundary facts.

The provider is mechanical and candidate-only.  It does not decide whether a
boundary is vulnerable; it enumerates type-valid analysis obligations and
marks unsupported types UNKNOWN instead of applying a universal boundary set.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

TYPE_IR_SCHEMA = "plamen.enumeration_parameter_type.v1"
FUNCTION_SIGNATURE_SCHEMA = "plamen.function_signature_fact.v1"

_STORAGE_WORDS = frozenset({"memory", "calldata", "storage", "payable"})


def _split_top_level(text: str) -> list[str]:
    rows: list[str] = []
    start = 0
    stack: list[str] = []
    pairs = {"<": ">", "(": ")", "[": "]", "{": "}"}
    closers = set(pairs.values())
    for index, char in enumerate(text or ""):
        if char in pairs:
            stack.append(pairs[char])
        elif char in closers and stack and char == stack[-1]:
            stack.pop()
        elif char == "," and not stack:
            value = text[start:index].strip()
            if value:
                rows.append(value)
            start = index + 1
    value = (text or "")[start:].strip()
    if value:
        rows.append(value)
    return rows


def collect_type_facts(ecosystem: str, source_text: str) -> dict[str, dict[str, Any]]:
    ecosystem = str(ecosystem or "").lower()
    text = source_text or ""
    facts: dict[str, dict[str, Any]] = {}
    alias_patterns = {
        "sol": r"(?m)\btype\s+(\w+)\s+is\s+([^;]+);",
        "rust": r"(?m)\btype\s+(\w+)\s*=\s*([^;]+);",
        "go": r"(?m)^\s*type\s+(\w+)\s+([^\n{]+)\s*$",
    }
    pattern = alias_patterns.get(ecosystem)
    if pattern:
        for match in re.finditer(pattern, text):
            target = re.sub(r"\s+", " ", match.group(2)).strip()
            if ecosystem == "go":
                target = target.removeprefix("=").strip()
            facts[match.group(1)] = {
                "kind": "alias",
                "target": target,
            }
    for match in re.finditer(r"(?s)\benum\s+(\w+)[^{]*\{([^}]*)\}", text):
        members = [
            token.strip().split("(", 1)[0].strip()
            for token in _split_top_level(match.group(2))
            if token.strip()
        ]
        facts[match.group(1)] = {
            "kind": "enum",
            "target": "",
            "members": members,
        }
    if ecosystem == "move":
        for match in re.finditer(
            r"(?m)\bstruct\s+(\w+)(?:\s*<[^>]+>)?\s+has\s+([^\{]+)\{", text
        ):
            abilities = {part.strip().lower() for part in match.group(2).split(",")}
            if "key" in abilities:
                facts[match.group(1)] = {"kind": "resource", "target": ""}
    return facts


def _parse_decl(ecosystem: str, declaration: str) -> tuple[str, str] | None:
    declaration = re.sub(r"\s+", " ", declaration.strip())
    if not declaration:
        return None
    if ecosystem in {"rust", "move"}:
        match = re.match(r"^(?:mut\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$", declaration)
        if not match or match.group(1) in {"self", "_self"}:
            return None
        return match.group(1), match.group(2).strip()
    if ecosystem == "sol":
        words = declaration.split()
        if len(words) < 2:
            return None
        name = words[-1]
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            return None
        type_words = [word for word in words[:-1] if word.lower() not in _STORAGE_WORDS]
        return name, " ".join(type_words)
    if ecosystem == "go":
        match = re.match(r"^([A-Za-z_]\w*)\s+(.+)$", declaration)
        if not match:
            return None
        return match.group(1), match.group(2).strip()
    return None


def _base_identity(raw_type: str) -> str:
    value = re.sub(r"^(?:&\s*(?:mut\s+)?)|^\*", "", raw_type.strip())
    value = re.sub(r"<.*$", "", value).strip()
    return value.split("::")[-1].split(".")[-1].strip()


def _resolve_alias(
    raw_type: str, type_facts: dict[str, dict[str, Any]]
) -> tuple[str, dict[str, Any] | None]:
    resolved = raw_type
    seen: set[str] = set()
    last_fact: dict[str, Any] | None = None
    for _ in range(8):
        base = _base_identity(resolved)
        if base in seen:
            break
        seen.add(base)
        fact = type_facts.get(base)
        if not isinstance(fact, dict):
            break
        last_fact = fact
        if str(fact.get("kind")) != "alias":
            break
        target = str(fact.get("target") or "").strip()
        if not target:
            break
        resolved = target
    return resolved, last_fact


def _family(
    ecosystem: str,
    name: str,
    raw_type: str,
    resolved_type: str,
    type_fact: dict[str, Any] | None,
) -> tuple[str, bool | None, int | None, list[str]]:
    compact = re.sub(r"\s+", "", resolved_type)
    lower = compact.lower()
    base_lower = _base_identity(resolved_type).lower()
    kind = str((type_fact or {}).get("kind") or "").lower()
    members = [str(value) for value in (type_fact or {}).get("members", [])]
    if kind == "enum":
        return "enum", None, None, members
    if kind == "resource":
        return "resource", None, None, []
    if re.search(r"(?:^|::)(?:option|Option)<", compact):
        return "option", None, None, []
    if re.search(r"(?:^|::)(?:result|Result)<", compact):
        return "result", None, None, []
    if lower == "bool":
        return "boolean", None, None, []
    if re.fullmatch(r"u(?:8|16|32|64|128|256|size)?", lower) or re.fullmatch(
        r"uint(?:8|16|32|64|128|256)?", lower
    ):
        width_match = re.search(r"(8|16|32|64|128|256)$", lower)
        return "unsigned_integer", False, int(width_match.group(1)) if width_match else None, []
    if re.fullmatch(r"i(?:8|16|32|64|128|size)", lower) or re.fullmatch(
        r"int(?:8|16|32|64|128|256)?", lower
    ):
        width_match = re.search(r"(8|16|32|64|128|256)$", lower)
        return "signed_integer", True, int(width_match.group(1)) if width_match else None, []
    identity_tokens = {
        "address", "pubkey", "accountid", "accountinfo", "signer",
        "common.address", "key", "publickey",
    }
    if (
        lower in identity_tokens
        or base_lower in identity_tokens
        or re.search(r"(?:address|pubkey|publickey|accountkey)$", lower)
    ):
        return "address_identity", None, None, []
    if (
        re.search(r"bytesn<\d+>", lower)
        or re.fullmatch(r"bytes(?:[1-9]|[12]\d|3[0-2])", lower)
        or re.fullmatch(r"\[u8;\d+\]", lower)
        or re.fullmatch(r"\[\d+\]byte", lower)
    ):
        width = re.search(r"\d+", lower)
        return "fixed_bytes", None, int(width.group(0)) if width else None, []
    if lower in {"bytes", "string", "str", "[]byte", "vec<u8>", "&[u8]"}:
        return "dynamic_bytes", None, None, []
    if re.search(r"(?:^|::)vector<", lower) or re.match(r"(?:vec|list|slice)<", lower):
        return "vector", None, None, []
    if (
        lower.startswith("[]")
        or lower.startswith("...")
        or re.match(r"\[[^;\]]*\]", lower)
        or re.search(r"\[[^\]]*\]$", lower)
    ):
        return "list", None, None, []
    if lower.startswith("map[") or re.match(r"(?:hashmap|btreemap)<", lower):
        return "map", None, None, []
    base = _base_identity(raw_type)
    if re.search(r"(?:^|_)id$", name, re.IGNORECASE) or re.search(
        r"(?:Id|ID)$", base
    ):
        return "domain_id", None, None, []
    return "unknown", None, None, []


def normalize_parameter_ir(
    ecosystem: str,
    raw_parameters: str,
    *,
    type_facts: dict[str, dict[str, Any]] | None = None,
    authority: str = "DECLARATION_TEXT",
    fidelity: str = "EXACT_DECLARATION",
) -> list[dict[str, Any]]:
    ecosystem = str(ecosystem or "").strip().lower()
    facts = dict(type_facts or {})
    out: list[dict[str, Any]] = []
    declarations = _split_top_level(raw_parameters)
    if ecosystem == "go" and authority == "COMPILER_PROVIDER":
        # Go permits grouped names (`first, second uint64`).  SCIP's signature
        # is a compiler fact, so carrying the explicitly declared trailing type
        # backward across that one grammar production is exact.  The regex
        # fallback deliberately does not do this: without provider authority,
        # a lone identifier is retained as ambiguous UNKNOWN.
        expanded: list[str] = []
        pending_names: list[str] = []
        for declaration in declarations:
            compact = re.sub(r"\s+", " ", declaration.strip())
            if re.fullmatch(r"[A-Za-z_]\w*", compact):
                pending_names.append(compact)
                continue
            parsed = _parse_decl("go", compact)
            if parsed and pending_names:
                _name, grouped_type = parsed
                expanded.extend(
                    f"{pending_name} {grouped_type}"
                    for pending_name in pending_names
                )
                pending_names.clear()
            elif pending_names:
                expanded.extend(pending_names)
                pending_names.clear()
            expanded.append(compact)
        expanded.extend(pending_names)
        declarations = expanded
    for declaration in declarations:
        parsed = _parse_decl(ecosystem, declaration)
        if not parsed:
            compact_decl = re.sub(r"\s+", " ", declaration).strip()
            if ecosystem in {"rust", "move"} and re.match(
                r"^(?:&\s*(?:mut\s+)?)?(?:self|_self)\b", compact_decl
            ):
                continue
            parsed = (f"__param_{len(out)}", compact_decl)
        name, raw_type = parsed
        if not name:
            name = f"__param_{len(out)}"
        resolved_type, type_fact = _resolve_alias(raw_type, facts)
        family, signed, width, members = _family(
            ecosystem, name, raw_type, resolved_type, type_fact
        )
        row_fidelity = (
            "REGEX_AMBIGUOUS_UNKNOWN"
            if authority == "REGEX_FALLBACK" and name.startswith("__param_")
            else "UNPARSED_DECLARATION"
            if name.startswith("__param_") and resolved_type == raw_type
            else fidelity
        )
        out.append({
            "schema": TYPE_IR_SCHEMA,
            "index": len(out),
            "name": name,
            "ecosystem": ecosystem,
            "declaration": declaration,
            "raw_type": raw_type,
            "resolved_type": resolved_type,
            "family": family,
            "signed": signed,
            "width": width,
            "members": members,
            "authority": authority,
            "fidelity": row_fidelity,
        })
    return out


def normalize_source_binding_path(path: str) -> str:
    """Normalize a provider's repository-relative path across host OSes.

    This is intentionally lexical.  It never resolves a path against the host
    filesystem (which would bake drive letters or case rules into an artifact).
    Parent segments are retained so a consumer can reject them at its own trust
    boundary rather than silently changing the provider's binding.
    """
    value = re.sub(r"/+", "/", str(path or "").replace("\\", "/").strip())
    while value.startswith("./"):
        value = value[2:]
    return value.rstrip("/")


def _canonical_signature_text(signature: str) -> str:
    value = str(signature or "").replace("\r\n", "\n").replace("\r", "\n")
    value = re.sub(r"^\s*```[^\n]*\n|\n```\s*$", "", value.strip())
    return re.sub(r"\s+", " ", value).strip()


def _balanced_group(text: str, start: int, opener: str, closer: str) -> tuple[str, int] | None:
    if start < 0 or start >= len(text) or text[start] != opener:
        return None
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            # Rust lifetimes (`'a`) are not quoted strings.  Only treat a
            # single quote as a quote when it has a closing mate before a
            # delimiter; double quotes cover the provider signatures that can
            # contain actual string literals (for example extern ABI names).
            if char == '"':
                quote = char
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            # A Rust return arrow inside a generic callable bound is not the
            # end of the surrounding ``<...>`` group (for example
            # ``F: Fn(u64) -> bool``).  Treating it as one shifts the selected
            # parameter group to the callable bound and silently loses the
            # function's real parameters.
            if opener == "<" and index > start and text[index - 1] in {"-", "="}:
                continue
            depth -= 1
            if depth == 0:
                return text[start + 1:index], index
    return None


def _signature_shape(ecosystem: str, bare_name: str, signature: str) -> dict[str, str]:
    """Extract lossless structural fields from provider signature text.

    Failure is explicit (`parse_status=UNKNOWN`).  The raw/canonical provider
    signature remains preserved even when this small structural extractor does
    not understand a future language feature.
    """
    ecosystem = str(ecosystem or "").strip().lower()
    canonical = _canonical_signature_text(signature)
    result = {
        "canonical_signature": canonical,
        "raw_parameters": "",
        "receiver": "",
        "visibility": "",
        "mutability": "",
        "generics": "",
        "returns": "",
        "parse_status": "UNKNOWN",
    }
    if not canonical or not bare_name:
        return result

    name_matches = list(re.finditer(rf"(?<![A-Za-z0-9_]){re.escape(bare_name)}(?![A-Za-z0-9_])", canonical))
    if not name_matches:
        return result
    # The declaration name is normally the last occurrence before its parameter
    # group.  Trying candidates from right to left avoids matching a receiver
    # type which happens to share the method name.
    chosen = None
    open_index = -1
    generic_text = ""
    for match in reversed(name_matches):
        cursor = match.end()
        while cursor < len(canonical) and canonical[cursor].isspace():
            cursor += 1
        candidate_generics = ""
        generic_delimiters = (
            ("[", "]") if ecosystem == "go" else ("<", ">")
        )
        if cursor < len(canonical) and canonical[cursor] == generic_delimiters[0]:
            generic = _balanced_group(
                canonical, cursor, generic_delimiters[0], generic_delimiters[1]
            )
            if generic is None:
                continue
            candidate_generics = canonical[cursor:generic[1] + 1]
            cursor = generic[1] + 1
            while cursor < len(canonical) and canonical[cursor].isspace():
                cursor += 1
        # Exact provider authority requires the declaration parameter group to
        # immediately follow the function name and optional generic clause.
        # Searching forward for any parenthesis can capture ``Fn(...)`` or a
        # method inside a Go constraint instead.
        if cursor < len(canonical) and canonical[cursor] == "(":
            group = _balanced_group(canonical, cursor, "(", ")")
            if group is not None:
                chosen = (match, group)
                open_index = cursor
                generic_text = candidate_generics
                break
    if chosen is None:
        return result
    name_match, (raw_parameters, close_index) = chosen
    result["generics"] = generic_text

    if ecosystem == "go":
        prefix = canonical[:name_match.start()]
        func_pos = prefix.find("func")
        recv_open = prefix.find("(", func_pos + 4) if func_pos >= 0 else -1
        if recv_open >= 0:
            recv = _balanced_group(prefix, recv_open, "(", ")")
            if recv is not None:
                result["receiver"] = recv[0].strip()
        result["visibility"] = "EXPORTED" if bare_name[:1].isupper() else "PACKAGE"
        result["returns"] = canonical[close_index + 1:].strip()
    else:
        visibility = re.search(
            r"(?:^|\s)(pub(?:\s*\([^)]*\))?|public(?:\s*\([^)]*\))?|external|internal|private|entry)(?:\s|$)",
            canonical[:name_match.start()],
        )
        if visibility:
            result["visibility"] = re.sub(r"\s+", "", visibility.group(1))
        suffix = canonical[close_index + 1:].strip()
        if suffix.startswith("->"):
            result["returns"] = suffix[2:].strip()
        elif ecosystem == "sol" and re.search(r"\breturns\s*\(", suffix):
            result["returns"] = suffix

    parameters = _split_top_level(raw_parameters)
    if ecosystem == "rust" and parameters:
        first = re.sub(r"\s+", " ", parameters[0]).strip()
        if re.search(r"(?:^|\s)(?:&\s*(?:'\w+\s*)?(?:mut\s+)?)?self\b", first):
            result["receiver"] = first
            if "mut self" in first or first.startswith("&mut"):
                result["mutability"] = "MUTABLE_RECEIVER"
            parameters = parameters[1:]
            raw_parameters = ", ".join(parameters)
    result["raw_parameters"] = raw_parameters.strip()
    result["parse_status"] = "EXACT"
    return result


def build_function_signature_fact(
    *,
    ecosystem: str,
    provider: str,
    function_identity: str,
    bare_name: str,
    provider_symbol: str,
    raw_signature: str,
    source_path: str,
    source_line: int,
    source_sha256: str,
    kind: str,
    raw_parameters: str | None = None,
    visibility: str = "",
    mutability: str = "",
    receiver: str = "",
    generics: str = "",
    returns: str = "",
    authority: str = "COMPILER_PROVIDER",
) -> dict[str, Any]:
    """Build one hash-stable provider-derived signature/type fact.

    Callers may supply fields exposed directly by a compiler API (Slither); any
    absent field is structurally extracted from the provider's own signature
    documentation (SCIP).  Source text never upgrades this fact's authority.
    """
    ecosystem = str(ecosystem or "").strip().lower()
    provider = str(provider or "").strip().lower()
    shape = _signature_shape(ecosystem, str(bare_name or ""), raw_signature)
    canonical = shape["canonical_signature"]
    if raw_parameters is not None:
        shape["raw_parameters"] = str(raw_parameters).strip()
        shape["parse_status"] = "EXACT"
    overrides = {
        "visibility": visibility,
        "mutability": mutability,
        "receiver": receiver,
        "generics": generics,
        "returns": returns,
    }
    for field, value in overrides.items():
        if str(value or "").strip():
            shape[field] = re.sub(r"\s+", " ", str(value)).strip()

    effective_authority = str(authority or "").strip().upper()
    if effective_authority == "COMPILER_PROVIDER" and not canonical and raw_parameters is None:
        effective_authority = "PROVIDER_IDENTITY_ONLY"
    parameter_authority = (
        "COMPILER_PROVIDER"
        if effective_authority == "COMPILER_PROVIDER"
        else "REGEX_FALLBACK"
    )
    parameter_facts = (
        normalize_parameter_ir(
            ecosystem,
            shape["raw_parameters"],
            authority=parameter_authority,
            fidelity=(
                "PROVIDER_SIGNATURE"
                if parameter_authority == "COMPILER_PROVIDER"
                else "REGEX_FALLBACK"
            ),
        )
        if shape["parse_status"] == "EXACT"
        else []
    )
    path = normalize_source_binding_path(source_path)
    binding = {
        "path": path,
        "line": max(0, int(source_line or 0)),
        "source_sha256": str(source_sha256 or "").strip().lower(),
    }
    binding["status"] = (
        "EXACT"
        if binding["path"]
        and binding["line"] > 0
        and re.fullmatch(r"[0-9a-f]{64}", binding["source_sha256"])
        else "UNKNOWN"
    )
    digest_payload = {
        "function_identity": str(function_identity or ""),
        "bare_name": str(bare_name or ""),
        "ecosystem": ecosystem,
        "provider": provider,
        "authority": effective_authority,
        "provider_symbol": str(provider_symbol or ""),
        "canonical_signature": canonical,
        "kind": str(kind or ""),
        "parse_status": shape["parse_status"],
        "raw_parameters": shape["raw_parameters"],
        "receiver": shape["receiver"],
        "visibility": shape["visibility"],
        "mutability": shape["mutability"],
        "generics": shape["generics"],
        "returns": shape["returns"],
        "source_binding": binding,
    }
    fact = {
        "schema": FUNCTION_SIGNATURE_SCHEMA,
        "function_identity": str(function_identity or ""),
        "bare_name": str(bare_name or ""),
        "ecosystem": ecosystem,
        "provider": provider,
        "authority": effective_authority,
        "provider_symbol": str(provider_symbol or ""),
        "raw_signature": str(raw_signature or ""),
        "canonical_signature": canonical,
        "signature_sha256": hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest() if canonical else "",
        "provider_fact_sha256": hashlib.sha256(
            json.dumps(
                digest_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest(),
        "kind": str(kind or ""),
        "parse_status": shape["parse_status"],
        "raw_parameters": shape["raw_parameters"],
        "parameter_facts": parameter_facts,
        "receiver": shape["receiver"],
        "visibility": shape["visibility"],
        "mutability": shape["mutability"],
        "generics": shape["generics"],
        "returns": shape["returns"],
        "source_binding": binding,
    }
    return fact


def build_fallback_signature_fact(
    *, function_identity: str, bare_name: str, provider: str,
    source_path: str, source_line: int, ecosystem: str = "",
) -> dict[str, Any]:
    """Describe a source-regex graph row without laundering it as AST fact."""
    return build_function_signature_fact(
        ecosystem=ecosystem,
        provider=provider,
        function_identity=function_identity,
        bare_name=bare_name,
        provider_symbol="",
        raw_signature="",
        source_path=source_path,
        source_line=source_line,
        source_sha256="",
        kind="",
        authority="REGEX_FALLBACK",
    )


def _parameter_shape(rows: list[dict[str, Any]]) -> list[tuple[str, str]]:
    return [
        (
            str(row.get("name") or "").casefold(),
            re.sub(r"\s+", "", str(row.get("raw_type") or "")).casefold(),
        )
        for row in rows
    ]


def _provider_fact_digest_payload(fact: dict[str, Any]) -> dict[str, Any]:
    binding = fact.get("source_binding") if isinstance(fact.get("source_binding"), dict) else {}
    return {
        "function_identity": str(fact.get("function_identity") or ""),
        "bare_name": str(fact.get("bare_name") or ""),
        "ecosystem": str(fact.get("ecosystem") or "").strip().lower(),
        "provider": str(fact.get("provider") or "").strip().lower(),
        "authority": str(fact.get("authority") or "").strip().upper(),
        "provider_symbol": str(fact.get("provider_symbol") or ""),
        "canonical_signature": str(fact.get("canonical_signature") or ""),
        "kind": str(fact.get("kind") or ""),
        "parse_status": str(fact.get("parse_status") or ""),
        "raw_parameters": str(fact.get("raw_parameters") or ""),
        "receiver": str(fact.get("receiver") or ""),
        "visibility": str(fact.get("visibility") or ""),
        "mutability": str(fact.get("mutability") or ""),
        "generics": str(fact.get("generics") or ""),
        "returns": str(fact.get("returns") or ""),
        "source_binding": {
            "path": normalize_source_binding_path(str(binding.get("path") or "")),
            "line": max(0, int(binding.get("line") or 0)),
            "source_sha256": str(binding.get("source_sha256") or "").strip().lower(),
            "status": str(binding.get("status") or ""),
        },
    }


def validate_function_signature_fact(fact: dict[str, Any]) -> list[str]:
    """Return exact structural/integrity issues for one signature fact."""
    if not isinstance(fact, dict):
        return ["signature fact is not an object"]
    issues: list[str] = []
    if fact.get("schema") != FUNCTION_SIGNATURE_SCHEMA:
        issues.append("signature fact schema mismatch")
    canonical = _canonical_signature_text(str(fact.get("raw_signature") or ""))
    if canonical != str(fact.get("canonical_signature") or ""):
        issues.append("canonical signature does not match raw provider signature")
    expected_signature_digest = (
        hashlib.sha256(canonical.encode("utf-8")).hexdigest() if canonical else ""
    )
    if str(fact.get("signature_sha256") or "") != expected_signature_digest:
        issues.append("signature digest mismatch")
    try:
        expected_fact_digest = hashlib.sha256(
            json.dumps(
                _provider_fact_digest_payload(fact),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError):
        issues.append("provider fact fields are malformed")
    else:
        if str(fact.get("provider_fact_sha256") or "") != expected_fact_digest:
            issues.append("provider fact digest mismatch")
    return issues


def select_function_parameter_ir(
    *,
    ecosystem: str,
    provider_fact: dict[str, Any] | None,
    fallback_raw_parameters: str,
    type_facts: dict[str, dict[str, Any]] | None,
    source_path: str,
    source_line: int,
    source_sha256: str,
    function_identity: str = "",
) -> dict[str, Any]:
    """Select provider parameter facts, or an explicitly weaker regex fallback.

    Provider/compiler facts win only while their exact source binding is live.
    A provider/source-regex disagreement is retained as visible completeness
    debt while the bound provider fact remains authoritative.  A stale or
    malformed provider fact cannot override the current source.
    """
    ecosystem = str(ecosystem or "").strip().lower()
    facts = dict(type_facts or {})
    fallback = normalize_parameter_ir(
        ecosystem,
        fallback_raw_parameters,
        type_facts=facts,
        authority="REGEX_FALLBACK",
        fidelity="REGEX_FALLBACK",
    )
    debts: list[dict[str, str]] = []
    provider_usable = False
    fact = provider_fact if isinstance(provider_fact, dict) else {}
    if not fact:
        debts.append({
            "kind": "PROVIDER_SIGNATURE_UNAVAILABLE",
            "detail": "no typed compiler/provider signature fact is available; regex fallback retained",
        })
    elif validate_function_signature_fact(fact):
        debts.append({
            "kind": "PROVIDER_SIGNATURE_INVALID",
            "detail": "typed provider signature fact failed structural/integrity validation; regex fallback retained",
        })
    elif str(fact.get("ecosystem") or "").strip().lower() != ecosystem:
        debts.append({
            "kind": "PROVIDER_ECOSYSTEM_MISMATCH",
            "detail": "typed provider signature belongs to a different ecosystem; regex fallback retained",
        })
    elif function_identity and str(fact.get("function_identity") or "") != str(function_identity):
        debts.append({
            "kind": "PROVIDER_FUNCTION_IDENTITY_MISMATCH",
            "detail": "typed provider signature is bound to a different graph function identity; regex fallback retained",
        })
    elif str(fact.get("authority") or "") != "COMPILER_PROVIDER":
        debts.append({
            "kind": "PROVIDER_SIGNATURE_UNAVAILABLE",
            "detail": "function graph carries identity/fallback evidence but no compiler/provider signature",
        })
    else:
        binding = fact.get("source_binding") if isinstance(fact.get("source_binding"), dict) else {}
        live_binding = {
            "path": normalize_source_binding_path(source_path),
            "line": max(0, int(source_line or 0)),
            "source_sha256": str(source_sha256 or "").strip().lower(),
        }
        bound = (
            str(binding.get("status") or "") == "EXACT"
            and
            normalize_source_binding_path(str(binding.get("path") or "")) == live_binding["path"]
            and int(binding.get("line") or 0) == live_binding["line"]
            and bool(live_binding["source_sha256"])
            and str(binding.get("source_sha256") or "").strip().lower()
            == live_binding["source_sha256"]
        )
        if not bound:
            debts.append({
                "kind": "PROVIDER_SOURCE_BINDING_MISMATCH",
                "detail": "provider signature source path/line/content binding is stale or mismatched; regex fallback retained",
            })
        elif str(fact.get("parse_status") or "") != "EXACT":
            debts.append({
                "kind": "PROVIDER_SIGNATURE_PARSE_UNKNOWN",
                "detail": "provider signature is preserved but its parameter structure is unsupported; regex fallback retained",
            })
        else:
            provider_usable = True

    if provider_usable:
        provider_rows = normalize_parameter_ir(
            ecosystem,
            str(fact.get("raw_parameters") or ""),
            type_facts=facts,
            authority="COMPILER_PROVIDER",
            fidelity="PROVIDER_SIGNATURE",
        )
        if _parameter_shape(provider_rows) != _parameter_shape(fallback):
            debts.append({
                "kind": "PROVIDER_REGEX_DISAGREEMENT",
                "detail": "bound provider parameter facts disagree with the source-regex extraction; provider facts retained",
            })
        return {
            "authority": "COMPILER_PROVIDER",
            "parameters": provider_rows,
            "debts": debts,
            "provider": str(fact.get("provider") or ""),
            "provider_fact_sha256": str(fact.get("provider_fact_sha256") or ""),
        }
    return {
        "authority": "REGEX_FALLBACK",
        "parameters": fallback,
        "debts": debts,
        "provider": str(fact.get("provider") or ""),
        "provider_fact_sha256": str(fact.get("provider_fact_sha256") or ""),
    }


_BASE_BOUNDARIES: dict[str, tuple[str, ...]] = {
    "unsigned_integer": ("zero", "one", "max"),
    "signed_integer": ("min", "negative_one", "zero", "one", "max"),
    "address_identity": ("default_identity", "self_or_local", "unknown_or_unregistered"),
    "boolean": ("false", "true"),
    "fixed_bytes": ("all_zero", "all_ones"),
    "dynamic_bytes": ("empty", "singleton"),
    "vector": ("empty", "singleton"),
    "list": ("empty", "singleton"),
    "map": ("empty", "singleton"),
    "option": ("none", "some_default"),
    "result": ("ok", "error"),
    "resource": ("absent", "present"),
    "domain_id": ("default_id", "unknown_id"),
}


def _threshold_expression(parameter: str, source_body: str) -> str:
    token = re.escape(parameter)
    rhs = r"(?:-?\d+|[A-Za-z_]\w*(?:::\w+|\.\w+)*)"
    direct = re.search(rf"\b{token}\b\s*(<=|>=|<|>)\s*({rhs})", source_body or "")
    if direct:
        return f"{parameter} {direct.group(1)} {direct.group(2)}"
    reverse = re.search(rf"({rhs})\s*(<=|>=|<|>)\s*\b{token}\b", source_body or "")
    if reverse:
        return f"{reverse.group(1)} {reverse.group(2)} {parameter}"
    return ""


def boundary_specs_for_parameter(
    parameter: dict[str, Any], *, source_body: str = ""
) -> list[dict[str, str]]:
    family = str(parameter.get("family") or "unknown")
    if family == "unknown":
        return [{
            "boundary": "unsupported_type",
            "class": "UNKNOWN",
            "status": "UNKNOWN",
            "evidence": str(parameter.get("raw_type") or "unknown"),
        }]
    members = [str(value) for value in parameter.get("members") or []]
    if family == "enum":
        boundaries = []
        if members:
            boundaries.append("first_variant")
            if len(members) > 1:
                boundaries.append("last_variant")
        else:
            boundaries.append("declared_variant_set")
    else:
        boundaries = list(_BASE_BOUNDARIES.get(family, ()))
    rows = [
        {
            "boundary": boundary,
            "class": family.upper(),
            "status": "REQUIRED",
            "evidence": str(parameter.get("resolved_type") or parameter.get("raw_type") or ""),
        }
        for boundary in boundaries
    ]
    threshold = ""
    if family in {"unsigned_integer", "signed_integer"}:
        threshold = _threshold_expression(str(parameter.get("name") or ""), source_body)
    if threshold:
        rows.extend(
            {
                "boundary": boundary,
                "class": "THRESHOLD_ADJACENT",
                "status": "REQUIRED",
                "evidence": threshold,
            }
            for boundary in ("threshold_below", "threshold_at", "threshold_above")
        )
    return rows


_BOUNDARY_CUES: dict[str, str] = {
    "zero": r"\b(?:zero|0)\b",
    "one": r"\b(?:one|1)\b",
    "min": r"\bmin(?:imum)?\b",
    "max": r"\bmax(?:imum)?\b",
    "negative_one": r"(?:\bnegative\s+one\b|(?<!\w)-1(?!\w))",
    "default_identity": r"\b(?:default|zero)\s+(?:address|account|key|identity)\b",
    "self_or_local": r"\b(?:self|local|own|this\s+contract)\b",
    "unknown_or_unregistered": r"\b(?:unknown|unregistered|foreign)\b",
    "false": r"\bfalse\b",
    "true": r"\btrue\b",
    "all_zero": r"\ball[-\s]?zero\b",
    "all_ones": r"\ball[-\s]?ones\b",
    "empty": r"\bempty\b",
    "singleton": r"\b(?:singleton|one[-\s]element)\b",
    "none": r"\bnone\b",
    "some_default": r"\bsome\b",
    "ok": r"\bok\b",
    "error": r"\b(?:err|error)\b",
    "absent": r"\babsent\b",
    "present": r"\bpresent\b",
    "default_id": r"\bdefault\s+(?:domain\s+)?id\b",
    "unknown_id": r"\bunknown\s+(?:domain\s+)?id\b",
    "first_variant": r"\bfirst\s+variant\b",
    "last_variant": r"\blast\s+variant\b",
    "declared_variant_set": r"\ball\s+(?:declared\s+)?variants\b",
    "threshold_below": r"\b(?:below|under|threshold\s*-\s*1)\b",
    "threshold_at": r"\b(?:at|equal(?:s|\s+to)?|threshold)\b",
    "threshold_above": r"\b(?:above|over|threshold\s*\+\s*1)\b",
}


def boundary_is_addressed(finding_text: str, parameter_name: str, boundary: str) -> bool:
    cue = _BOUNDARY_CUES.get(boundary)
    if not cue:
        return False
    name = (
        r"(?<![A-Za-z0-9_])" + re.escape(parameter_name)
        + r"(?![A-Za-z0-9_])"
    )
    # Do not let a boundary named for one parameter suppress an obligation for
    # another parameter merely because both occur in the same paragraph.  A
    # mechanical "addressed" decision needs a short, clause-local relation in
    # either direction; punctuation terminates that relation.
    bridge = r"[^\n.;]{0,48}"
    return bool(
        re.search(rf"(?:{name}{bridge}{cue}|{cue}{bridge}{name})", finding_text or "", re.IGNORECASE)
    )


__all__ = [
    "TYPE_IR_SCHEMA",
    "FUNCTION_SIGNATURE_SCHEMA",
    "collect_type_facts",
    "normalize_parameter_ir",
    "normalize_source_binding_path",
    "build_function_signature_fact",
    "build_fallback_signature_fact",
    "validate_function_signature_fact",
    "select_function_parameter_ir",
    "boundary_specs_for_parameter",
    "boundary_is_addressed",
]
