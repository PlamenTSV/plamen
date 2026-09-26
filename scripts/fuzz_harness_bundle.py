"""Strict MODEL-to-DRIVER transport for generated fuzz harness bytes.

Fuzz workers have one PhaseIO-owned Markdown output.  They therefore cannot
also publish an open-ended set of source files without destroying the exact
output denominator.  This module treats fenced source blocks in that Markdown
as data: the driver validates the complete bundle and materializes the exact
harness bytes into the already isolated fuzz workspace.  A Medusa JSON file is
an execution proposal rather than source evidence: the driver projects its
build-root binding to the known isolated Foundry root before materialization.

The transport is deliberately narrower than Markdown in general.  Ambiguous,
duplicate, aliased, oversized, or role-incompatible paths are rejected before
any file is created.  Re-entry is compare-only, which makes worker retry and
driver resume safe without silently blessing changed harness bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Sequence


_HEADING = "## Driver Fuzz Harness Bundle"
_CAMPAIGN_HEADING = "## Driver Fuzz Campaign"
_FILE_RE = re.compile(
    # The worker contract names the heading and its backtick path but does not
    # require punctuation between them.  Accept the two canonical Markdown
    # spellings (with or without one colon) while keeping every other token,
    # fence and byte boundary strict.
    r"^### Generated File(?:[ \t]*:)?[ \t]+`([^`]+)`[ \t]*\n"
    r"```([A-Za-z0-9_+.-]+)\s*\n(.*?)\n```\s*$",
    re.MULTILINE | re.DOTALL,
)
_FIELD_RE = re.compile(
    r"^\*\*(Tool|CWD|Arguments JSON|Assertions JSON|Expected Cases)\*\*:\s*(.*?)\s*$",
    re.MULTILINE,
)
_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_MAX_FILES = 16
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_BYTES = 12 * 1024 * 1024
_MAX_MARKDOWN_BYTES = 24 * 1024 * 1024
_SOLIDITY_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
_SOLIDITY_FUNCTION_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
    r"(?P<arguments>[^)]*)\)(?P<attributes>[^;{}]*)\{",
    re.DOTALL,
)
_MEDUSA_PROPERTY_NAME_RE = re.compile(r"\bproperty_[A-Za-z0-9_]+\b")
_MEDUSA_PROXY_CONTRACT_CAST_RE = re.compile(
    r"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*"
    r"(?P<address>address)\s*\(\s*new\s+"
    r"(?P<proxy>[A-Za-z_][A-Za-z0-9_]*Proxy)\s*\("
)
_PROXY_VARIABLE_CONTRACT_CAST_RE = re.compile(
    r"\b(?P<target>[A-Z][A-Za-z0-9_]*)\s*\(\s*"
    r"(?P<address>address)\s*\(\s*"
    r"(?P<proxy>(?:[A-Za-z_][A-Za-z0-9_]*)?[Pp]roxy)\s*\)"
)


class FuzzHarnessBundleError(ValueError):
    """The model bundle is not an unambiguous executable denominator."""


@dataclass(frozen=True)
class GeneratedFile:
    relative_path: str
    language: str
    content: bytes
    source_sha256: str = ""
    projection: str = "IDENTITY"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    @property
    def effective_source_sha256(self) -> str:
        return self.source_sha256 or self.sha256


@dataclass(frozen=True)
class FuzzHarnessBundle:
    role: str
    files: tuple[GeneratedFile, ...]
    tool: str
    cwd_relative: str
    argv: tuple[str, ...]
    assertion_ids: tuple[str, ...]
    expected_cases: int

    @property
    def manifest(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "plamen.fuzz-harness-bundle.v2",
            "role": self.role,
            "files": [
                {
                    "relative_path": row.relative_path,
                    "language": row.language,
                    "size": len(row.content),
                    "sha256": row.sha256,
                    "source_sha256": row.effective_source_sha256,
                    "projection": row.projection,
                }
                for row in self.files
            ],
            "campaign": {
                "tool": self.tool,
                "cwd_relative": self.cwd_relative,
                "argv": list(self.argv),
                "assertion_ids": list(self.assertion_ids),
                "expected_cases": self.expected_cases,
            },
        }
        encoded = json.dumps(
            payload, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        payload["payload_digest"] = hashlib.sha256(encoded).hexdigest()
        return payload


def _one_section(text: str, heading: str, *, end_heading: str | None = None) -> str:
    if text.count(heading) != 1:
        raise FuzzHarnessBundleError(f"expected exactly one {heading!r} section")
    start = text.index(heading) + len(heading)
    if end_heading is not None:
        end = text.find(end_heading, start)
        if end < 0:
            raise FuzzHarnessBundleError(f"missing {end_heading!r} section")
        return text[start:end]
    next_h2 = re.search(r"^##\s+", text[start:], flags=re.MULTILINE)
    return text[start:start + next_h2.start()] if next_h2 else text[start:]


def _canonical_relative(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise FuzzHarnessBundleError("generated path is empty or non-portable")
    path = Path(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(_SAFE_COMPONENT_RE.fullmatch(part) is None for part in path.parts)
    ):
        raise FuzzHarnessBundleError(f"generated path is not canonical: {value!r}")
    return value


def _path_allowed(role: str, relative: str) -> bool:
    path = Path(relative)
    if role == "invariant_fuzz":
        return (
            relative.endswith(".t.sol")
            and (
                path.parts[:2] == ("test", "invariant")
                or path.parts[:1] == (".plamen-generated",)
            )
        )
    if role == "medusa_fuzz":
        return (
            path.parts[:1] == (".medusa-tests",)
            and path.suffix.casefold() in {".sol", ".json"}
        )
    return False


def _json_list(raw: str, label: str) -> tuple[str, ...]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FuzzHarnessBundleError(f"{label} is not strict JSON") from exc
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 256
        or any(type(item) is not str or not item or "\x00" in item for item in value)
    ):
        raise FuzzHarnessBundleError(f"{label} must be a non-empty string array")
    return tuple(value)


def _solidity_code_projection(source: str) -> str:
    """Blank comments and strings before inspecting generated declarations.

    This is intentionally a small lexical projection, not a Solidity parser.
    It preserves byte positions/newlines and prevents comments or string
    literals from manufacturing a property oracle.  The admitted property
    grammar itself is deliberately narrow and needs no expression parsing.
    """

    chars = list(source)
    index = 0
    state = "CODE"
    quote = ""
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "CODE":
            if current == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                state = "LINE_COMMENT"
                index += 2
                continue
            if current == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                state = "BLOCK_COMMENT"
                index += 2
                continue
            if current in {'"', "'"}:
                quote = current
                chars[index] = " "
                state = "STRING"
        elif state == "LINE_COMMENT":
            if current == "\n":
                state = "CODE"
            else:
                chars[index] = " "
        elif state == "BLOCK_COMMENT":
            if current == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                state = "CODE"
                index += 2
                continue
            if current != "\n":
                chars[index] = " "
        else:
            if current == "\\" and following:
                chars[index] = " "
                if following != "\n":
                    chars[index + 1] = " "
                index += 2
                continue
            if current == quote:
                state = "CODE"
            if current != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)


def _medusa_property_declarations(
    files: Sequence[GeneratedFile],
) -> list[tuple[str, str, str, str, str]]:
    declarations: list[tuple[str, str, str, str, str]] = []
    for row in files:
        if not row.relative_path.endswith(".sol"):
            continue
        try:
            source = row.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        projected = _solidity_code_projection(source)
        for contract_match in _SOLIDITY_CONTRACT_RE.finditer(projected):
            opening = projected.find("{", contract_match.end())
            if opening < 0:
                continue
            depth = 1
            cursor = opening + 1
            while cursor < len(projected) and depth:
                if projected[cursor] == "{":
                    depth += 1
                elif projected[cursor] == "}":
                    depth -= 1
                cursor += 1
            if depth:
                continue
            body = projected[opening + 1:cursor - 1]
            for match in _SOLIDITY_FUNCTION_HEADER_RE.finditer(body):
                name = match.group("name")
                if not name.startswith("property_"):
                    continue
                declarations.append((
                    row.relative_path,
                    contract_match.group(1),
                    name,
                    match.group("arguments").strip(),
                    " ".join(match.group("attributes").split()),
                ))
    return declarations


def medusa_harness_property_names(
    files: Sequence[GeneratedFile],
) -> tuple[str, ...]:
    return tuple(sorted({row[2] for row in _medusa_property_declarations(files)}))


def medusa_harness_semantic_issues(
    files: Sequence[GeneratedFile],
    *,
    assertion_ids: Sequence[str] = (),
) -> tuple[str, ...]:
    """Return closed semantic-oracle defects for a generated Medusa bundle.

    Medusa assertion tests fail only on a panic/assertion, whereas property
    tests interpret a boolean return.  A public ``fuzz_* returns (bool)``
    function therefore executes without testing its return value.  Bind the
    generated harness, projected config, and campaign roster to one explicit
    property-test grammar before any campaign may claim evidence.
    """

    issues: list[str] = []
    declarations = _medusa_property_declarations(files)
    if not declarations:
        issues.append(
            "generated Solidity defines no property_ boolean property function"
        )
    names = [row[2] for row in declarations]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        issues.append("duplicate Medusa property names: " + ", ".join(duplicates))
    for relative, _contract, name, arguments, attributes in declarations:
        words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", attributes))
        return_match = re.search(
            r"\breturns\s*\(\s*bool\s*\)", attributes
        )
        residual_returns = re.sub(
            r"\breturns\s*\(\s*bool\s*\)", "", attributes
        )
        if arguments:
            issues.append(f"{relative}:{name} property arguments must be empty")
        if _MEDUSA_PROPERTY_NAME_RE.fullmatch(name) is None:
            issues.append(f"{relative}:{name} is not a complete property name")
        if not ({"public", "external"} & words):
            issues.append(f"{relative}:{name} must be public or external")
        if not ({"view", "pure"} & words):
            issues.append(f"{relative}:{name} must be view or pure")
        if return_match is None or re.search(r"\breturns\b", residual_returns):
            issues.append(f"{relative}:{name} must return exactly one bool")

    configs = [
        row for row in files
        if row.relative_path == ".medusa-tests/medusa.json"
    ]
    config: object = None
    if len(configs) != 1:
        issues.append("projected Medusa config denominator is not singular")
    else:
        try:
            config = json.loads(configs[0].content.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            issues.append("projected Medusa config is not strict UTF-8 JSON")
    fuzzing = config.get("fuzzing") if isinstance(config, dict) else None
    if not isinstance(fuzzing, dict):
        issues.append("projected Medusa fuzzing block is absent")
    else:
        targets = fuzzing.get("targetContracts")
        property_contracts = {row[1] for row in declarations}
        if (
            not isinstance(targets, list)
            or any(type(item) is not str for item in targets)
            or len(targets) != len(set(targets))
            or set(targets) != property_contracts
        ):
            issues.append(
                "Medusa targetContracts must exactly name property contracts: "
                + ", ".join(sorted(property_contracts))
            )
        testing = fuzzing.get("testing")
        if not isinstance(testing, dict):
            issues.append("projected Medusa fuzzing.testing block is absent")
            testing = {}
        property_testing = testing.get("propertyTesting")
        if not (
            isinstance(property_testing, dict)
            and property_testing.get("enabled") is True
            and property_testing.get("testPrefixes") == ["property_"]
        ):
            issues.append(
                "Medusa propertyTesting must enable exact prefix property_"
            )
        assertion_testing = testing.get("assertionTesting")
        if not (
            isinstance(assertion_testing, dict)
            and assertion_testing.get("enabled") is True
        ):
            issues.append("Medusa assertionTesting must remain enabled")
        if testing.get("testViewMethods") is not True:
            issues.append("Medusa testViewMethods must be true")
        if testing.get("stopOnNoTests") is not True:
            issues.append("Medusa stopOnNoTests must be true")
        if testing.get("stopOnFailedTest") is not False:
            issues.append("Medusa stopOnFailedTest must be false")

    if assertion_ids:
        declared = set(names)
        referenced: list[str] = []
        for assertion_id in assertion_ids:
            matches = _MEDUSA_PROPERTY_NAME_RE.findall(assertion_id)
            if len(matches) != 1:
                issues.append(
                    f"assertion ID must name exactly one property function: "
                    f"{assertion_id}"
                )
                continue
            referenced.append(matches[0])
        duplicate_refs = sorted({
            name for name in referenced if referenced.count(name) > 1
        })
        if duplicate_refs:
            issues.append(
                "campaign property roster contains duplicates: "
                + ", ".join(duplicate_refs)
            )
        missing = sorted(declared - set(referenced))
        unknown = sorted(set(referenced) - declared)
        if missing:
            issues.append(
                "campaign roster omits properties: " + ", ".join(missing)
            )
        if unknown:
            issues.append(
                "campaign roster names unknown properties: " + ", ".join(unknown)
            )
    return tuple(sorted(set(issues)))


def _project_medusa_files(
    files: Sequence[GeneratedFile],
) -> tuple[GeneratedFile, ...]:
    """Compile the model config proposal into a build-root-bound config.

    Medusa's own compilation contract says a framework project must use the
    project root (``.``) as the crytic-compile target.  A generated harness is
    still selected through ``fuzzing.targetContracts``; using its file path as
    the compilation target loses Foundry dependency/remapping semantics and,
    in some crytic-compile versions, is resolved against the wrong cwd.
    """

    configs = [row for row in files if row.relative_path == ".medusa-tests/medusa.json"]
    if len(configs) != 1:
        raise FuzzHarnessBundleError(
            "Medusa bundle must contain exactly one .medusa-tests/medusa.json"
        )
    config_row = configs[0]
    try:
        value = json.loads(config_row.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FuzzHarnessBundleError("Medusa config is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise FuzzHarnessBundleError("Medusa config root must be an object")

    fuzzing = value.get("fuzzing")
    if not isinstance(fuzzing, dict):
        raise FuzzHarnessBundleError("Medusa config fuzzing block must be an object")
    targets = fuzzing.get("targetContracts")
    if targets is None or targets == []:
        candidates: set[str] = set()
        for row in files:
            if not row.relative_path.endswith(".sol"):
                continue
            try:
                source = row.content.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise FuzzHarnessBundleError(
                    f"generated Solidity is not UTF-8: {row.relative_path}"
                ) from exc
            projected = _solidity_code_projection(source)
            if _MEDUSA_PROPERTY_NAME_RE.search(projected):
                candidates.update(_SOLIDITY_CONTRACT_RE.findall(projected))
        if len(candidates) != 1:
            raise FuzzHarnessBundleError(
                "Medusa targetContracts is absent/empty and the generated "
                "fuzz contract is not uniquely derivable"
            )
        fuzzing["targetContracts"] = [next(iter(candidates))]
    elif (
        not isinstance(targets, list)
        or not targets
        or any(
            type(item) is not str
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) is None
            for item in targets
        )
        or len(targets) != len(set(targets))
    ):
        raise FuzzHarnessBundleError(
            "Medusa targetContracts must be a non-empty contract-name array"
        )

    compilation = value.get("compilation")
    if compilation is None:
        compilation = {}
        value["compilation"] = compilation
    if not isinstance(compilation, dict):
        raise FuzzHarnessBundleError("Medusa compilation block must be an object")
    platform_config = compilation.get("platformConfig")
    if platform_config is None:
        platform_config = {}
        compilation["platformConfig"] = platform_config
    if not isinstance(platform_config, dict):
        raise FuzzHarnessBundleError(
            "Medusa compilation.platformConfig must be an object"
        )
    compilation["platform"] = "crytic-compile"
    platform_config["target"] = "."
    testing = fuzzing.get("testing")
    if testing is None:
        testing = {}
        fuzzing["testing"] = testing
    if not isinstance(testing, dict):
        raise FuzzHarnessBundleError(
            "Medusa fuzzing.testing must be an object"
        )
    # These are TestingConfig fields, not top-level FuzzingConfig fields. Drop
    # model-proposed misplaced copies before projecting the canonical shape.
    for misplaced in (
        "propertyTesting", "assertionTesting", "testViewMethods",
        "stopOnNoTests", "stopOnFailedTest",
    ):
        fuzzing.pop(misplaced, None)
    property_testing = testing.get("propertyTesting")
    if property_testing is None:
        property_testing = {}
        testing["propertyTesting"] = property_testing
    if not isinstance(property_testing, dict):
        raise FuzzHarnessBundleError(
            "Medusa fuzzing.testing.propertyTesting must be an object"
        )
    property_testing["enabled"] = True
    property_testing["testPrefixes"] = ["property_"]
    assertion_testing = testing.get("assertionTesting")
    if assertion_testing is None:
        assertion_testing = {}
        testing["assertionTesting"] = assertion_testing
    if not isinstance(assertion_testing, dict):
        raise FuzzHarnessBundleError(
            "Medusa fuzzing.testing.assertionTesting must be an object"
        )
    assertion_testing["enabled"] = True
    testing["testViewMethods"] = True
    testing["stopOnNoTests"] = True
    testing["stopOnFailedTest"] = False
    effective = (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("ascii")
    projected: list[GeneratedFile] = []
    for row in files:
        if row.relative_path == config_row.relative_path:
            projected.append(
                GeneratedFile(
                    row.relative_path,
                    row.language,
                    effective,
                    source_sha256=row.sha256,
                    projection="DRIVER_MEDUSA_FOUNDRY_ROOT_V1",
                )
            )
        else:
            projected.append(row)
    return tuple(projected)


def _matching_parenthesis(source: str, opening: int) -> int | None:
    """Return the close for one parenthesis in a comment/string-free view."""

    if opening < 0 or opening >= len(source) or source[opening] != "(":
        return None
    depth = 1
    for index in range(opening + 1, len(source)):
        token = source[index]
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _project_medusa_payable_proxy_casts(
    files: Sequence[GeneratedFile],
) -> tuple[GeneratedFile, ...]:
    """Canonicalize proxy-address casts for payable implementation types.

    Solidity 0.8 intentionally makes ``address(instance)`` non-payable.  A
    generated harness that deploys an upgradeable proxy and immediately casts
    its address to an implementation contract with a payable receive/fallback
    therefore fails to compile.  The address bits and deployed object do not
    change when the intermediate value is made explicitly payable, so this is
    a type-surface projection rather than a semantic harness rewrite.

    Keep the language deliberately narrow: only a direct outer contract cast
    around ``address(new *Proxy(...))`` is projected.  Comments, strings,
    already-payable expressions, arbitrary address conversions, and production
    sources are untouched.  The manifest retains the model byte digest as
    ``source_sha256`` and binds the exact projected bytes separately.
    """

    projected_files: list[GeneratedFile] = []
    for row in files:
        if not row.relative_path.endswith(".sol"):
            projected_files.append(row)
            continue
        try:
            source = row.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            projected_files.append(row)
            continue
        lexical = _solidity_code_projection(source)
        insertions: list[tuple[int, str]] = []
        for match in _MEDUSA_PROXY_CONTRACT_CAST_RE.finditer(lexical):
            if match.group("target") == "payable":
                continue
            address_start = match.start("address")
            address_open = lexical.find("(", match.end("address"))
            address_close = _matching_parenthesis(lexical, address_open)
            if address_close is None:
                continue
            following = address_close + 1
            while following < len(lexical) and lexical[following].isspace():
                following += 1
            # Require the address expression to be the complete argument of
            # the outer contract cast.  This excludes function calls whose
            # first argument merely happens to deploy a proxy.
            if following >= len(lexical) or lexical[following] != ")":
                continue
            insertions.append((address_start, "payable("))
            insertions.append((address_close + 1, ")"))
        if not insertions:
            projected_files.append(row)
            continue
        effective = source
        for index, value in sorted(insertions, reverse=True):
            effective = effective[:index] + value + effective[index:]
        encoded = effective.encode("utf-8")
        projected_files.append(GeneratedFile(
            row.relative_path,
            row.language,
            encoded,
            source_sha256=row.effective_source_sha256,
            projection="DRIVER_MEDUSA_PAYABLE_PROXY_CAST_V1",
        ))
    return tuple(projected_files)


def _project_payable_proxy_variable_casts(
    files: Sequence[GeneratedFile],
) -> tuple[GeneratedFile, ...]:
    """Preserve proxy address bits while satisfying payable contract casts.

    Invariant workers commonly bind a deployed proxy to a local variable and
    then cast ``Target(address(proxy))``. Solidity rejects that conversion
    when Target has a payable fallback. Only a complete PascalCase contract
    cast of a proxy-named variable is projected; source and assertion bodies
    remain otherwise byte-identical, with the model hash retained.
    """

    projected_files: list[GeneratedFile] = []
    for row in files:
        if not row.relative_path.endswith(".sol"):
            projected_files.append(row)
            continue
        try:
            source = row.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            projected_files.append(row)
            continue
        lexical = _solidity_code_projection(source)
        insertions: list[tuple[int, str]] = []
        for match in _PROXY_VARIABLE_CONTRACT_CAST_RE.finditer(lexical):
            following = match.end()
            while following < len(lexical) and lexical[following].isspace():
                following += 1
            if following >= len(lexical) or lexical[following] != ")":
                continue
            address_start = match.start("address")
            address_close = match.end() - 1
            insertions.append((address_start, "payable("))
            insertions.append((address_close + 1, ")"))
        if not insertions:
            projected_files.append(row)
            continue
        effective = source
        for index, value in sorted(insertions, reverse=True):
            effective = effective[:index] + value + effective[index:]
        projected_files.append(GeneratedFile(
            row.relative_path,
            row.language,
            effective.encode("utf-8"),
            source_sha256=row.effective_source_sha256,
            projection="DRIVER_PAYABLE_PROXY_VARIABLE_CAST_V1",
        ))
    return tuple(projected_files)


def parse_fuzz_harness_bundle(markdown: bytes | str, *, role: str) -> FuzzHarnessBundle:
    """Parse one exact generated-file bundle and campaign request."""

    if isinstance(markdown, bytes):
        if not markdown or len(markdown) > _MAX_MARKDOWN_BYTES:
            raise FuzzHarnessBundleError("worker Markdown is empty or oversized")
        try:
            text = markdown.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FuzzHarnessBundleError("worker Markdown is not UTF-8") from exc
    elif isinstance(markdown, str):
        text = markdown
        if not text or len(text.encode("utf-8")) > _MAX_MARKDOWN_BYTES:
            raise FuzzHarnessBundleError("worker Markdown is empty or oversized")
    else:
        raise FuzzHarnessBundleError("worker Markdown has unsupported type")

    role_n = str(role).strip().casefold()
    if role_n not in {"invariant_fuzz", "medusa_fuzz"}:
        raise FuzzHarnessBundleError(f"unsupported fuzz role: {role!r}")
    source_section = _one_section(text, _HEADING, end_heading=_CAMPAIGN_HEADING)
    matches = list(_FILE_RE.finditer(source_section.strip()))
    if not matches or len(matches) > _MAX_FILES:
        raise FuzzHarnessBundleError("generated-file count is outside its bound")
    # Nothing except whitespace may occur between declared file envelopes.
    cursor = 0
    for match in matches:
        if source_section.strip()[cursor:match.start()].strip():
            raise FuzzHarnessBundleError("undeclared text appears in harness bundle")
        cursor = match.end()
    if source_section.strip()[cursor:].strip():
        raise FuzzHarnessBundleError("trailing undeclared text appears in harness bundle")

    files: list[GeneratedFile] = []
    seen: set[str] = set()
    total = 0
    for match in matches:
        relative = _canonical_relative(match.group(1).strip())
        portable = relative.casefold()
        if portable in seen:
            raise FuzzHarnessBundleError(f"duplicate/aliased generated path: {relative}")
        seen.add(portable)
        if not _path_allowed(role_n, relative):
            raise FuzzHarnessBundleError(
                f"generated path is outside the {role_n} lane: {relative}"
            )
        language = match.group(2).strip().casefold()
        expected_language = "json" if relative.endswith(".json") else "solidity"
        if language not in ({"json"} if expected_language == "json" else {"solidity", "sol"}):
            raise FuzzHarnessBundleError(
                f"language fence does not match generated path: {relative}"
            )
        content = (match.group(3) + "\n").encode("utf-8")
        if len(content) > _MAX_FILE_BYTES:
            raise FuzzHarnessBundleError(f"generated file is oversized: {relative}")
        total += len(content)
        if total > _MAX_TOTAL_BYTES:
            raise FuzzHarnessBundleError("generated bundle exceeds total byte bound")
        if relative.endswith(".json"):
            try:
                json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise FuzzHarnessBundleError(
                    f"generated JSON is malformed: {relative}"
                ) from exc
        files.append(GeneratedFile(relative, language, content))

    if role_n == "medusa_fuzz":
        files = list(_project_medusa_files(files))
        files = list(_project_medusa_payable_proxy_casts(files))
    files = list(_project_payable_proxy_variable_casts(files))

    campaign = _one_section(text, _CAMPAIGN_HEADING)
    fields: dict[str, str] = {}
    for match in _FIELD_RE.finditer(campaign):
        if match.group(1) in fields:
            raise FuzzHarnessBundleError(f"duplicate campaign field: {match.group(1)}")
        fields[match.group(1)] = match.group(2).strip()
    expected_fields = {"Tool", "CWD", "Arguments JSON", "Assertions JSON", "Expected Cases"}
    if set(fields) != expected_fields:
        raise FuzzHarnessBundleError("campaign field denominator differs")
    tool = fields["Tool"].casefold()
    argv = _json_list(fields["Arguments JSON"], "Arguments JSON")
    assertions = _json_list(fields["Assertions JSON"], "Assertions JSON")
    if argv[0].casefold() != tool:
        raise FuzzHarnessBundleError("campaign tool and argv[0] differ")
    if len(assertions) != len(set(assertions)):
        raise FuzzHarnessBundleError("campaign assertion IDs are duplicated")
    cwd = fields["CWD"]
    if cwd != ".":
        cwd = _canonical_relative(cwd)
    try:
        expected_cases = int(fields["Expected Cases"], 10)
    except ValueError as exc:
        raise FuzzHarnessBundleError("Expected Cases is not an integer") from exc
    if expected_cases < 1 or expected_cases > 10_000_000:
        raise FuzzHarnessBundleError("Expected Cases is outside its bound")
    if role_n == "invariant_fuzz":
        required = (
            tool == "forge"
            and argv == (
                "forge", "test", "--match-contract", "InvariantFuzz", "-vv",
            )
            and expected_cases == 6400
        )
    else:
        required = (
            tool == "medusa"
            and argv == (
                "medusa", "fuzz", "--config", ".medusa-tests/medusa.json",
                "--timeout", "600", "--test-limit", "50000",
            )
            and expected_cases == 50000
        )
    if not required:
        raise FuzzHarnessBundleError("campaign argv is not the assigned fuzz campaign")
    if role_n == "medusa_fuzz":
        oracle_issues = medusa_harness_semantic_issues(
            files, assertion_ids=assertions
        )
        if oracle_issues:
            raise FuzzHarnessBundleError(
                "Medusa property oracle is not bound: " + "; ".join(oracle_issues)
            )
    return FuzzHarnessBundle(
        role=role_n,
        files=tuple(files),
        tool=tool,
        cwd_relative=cwd,
        argv=argv,
        assertion_ids=assertions,
        expected_cases=expected_cases,
    )


def _assert_safe_parent(root: Path, parent: Path) -> None:
    root_resolved = root.resolve(strict=True)
    parent.mkdir(parents=True, exist_ok=True)
    cursor = parent
    while True:
        observed = cursor.lstat()
        if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
            raise FuzzHarnessBundleError(f"unsafe generated parent: {cursor}")
        if cursor == root_resolved:
            return
        if cursor.parent == cursor:
            raise FuzzHarnessBundleError("generated parent escaped workspace")
        cursor = cursor.parent


def materialize_fuzz_harness_bundle(
    bundle: FuzzHarnessBundle, *, active_root: Path
) -> Path:
    """Compare-only materialization into an isolated fuzz active tree.

    Returns the canonical bundle-manifest path, which is a stable subject for
    the typed compatibility executor.
    """

    root = Path(os.path.abspath(os.fspath(active_root)))
    if not root.is_dir() or root.is_symlink():
        raise FuzzHarnessBundleError("active fuzz root is unavailable or aliased")
    root = root.resolve(strict=True)
    manifest = bundle.manifest
    manifest_bytes = (
        json.dumps(
            manifest, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
    ).encode("ascii")
    rows = [*bundle.files, GeneratedFile(
        ".plamen-generated/plamen-fuzz-bundle.json", "json", manifest_bytes
    )]
    for row in rows:
        target = root / row.relative_path
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise FuzzHarnessBundleError("generated path escaped active root") from exc
        _assert_safe_parent(root, target.parent)
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_file():
                raise FuzzHarnessBundleError(f"generated target is unsafe: {target}")
            if target.read_bytes() != row.content:
                raise FuzzHarnessBundleError(
                    f"compare-only generated target drifted: {row.relative_path}"
                )
            continue
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o600)
        try:
            view = memoryview(row.content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise FuzzHarnessBundleError(
                        f"short generated write: {row.relative_path}"
                    )
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return root / ".plamen-generated/plamen-fuzz-bundle.json"


__all__ = [
    "FuzzHarnessBundle",
    "FuzzHarnessBundleError",
    "GeneratedFile",
    "materialize_fuzz_harness_bundle",
    "medusa_harness_property_names",
    "medusa_harness_semantic_issues",
    "parse_fuzz_harness_bundle",
]
