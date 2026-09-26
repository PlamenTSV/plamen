"""Extract and materialize verifier-authored PoC source without project writes.

Verification workers own Markdown artifacts in the scratchpad; they do not own
the audited checkout.  A verifier that names ``test/Foo.t.sol`` therefore has
not created an executable test merely by mentioning that path.  This module
defines the explicit bridge: one canonical fenced source section is extracted
from the authenticated verifier artifact and published into the driver's
disposable mechanical workspace.

The bridge is intentionally presentation-strict.  Executable source is an
authority boundary, not ordinary report prose: ambiguity, multiple sections,
unsafe paths, lossy text, and conflicting replay all fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import NoReturn


MAX_SOURCE_BYTES = 2 * 1024 * 1024


class MechanicalPoCSourceError(ValueError):
    """The verifier artifact cannot authorize one executable source file."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


@dataclass(frozen=True)
class MechanicalPoCSource:
    relative_path: str
    language: str
    fence_language: str
    source: bytes
    source_sha256: str
    source_size: int


_HEADING_RE = re.compile(
    r"^[ \t]{0,3}#{1,6}[ \t]+Mechanical[ \t]+PoC[ \t]+Source[ \t]*#*[ \t]*$",
    re.IGNORECASE,
)
_ANY_HEADING_RE = re.compile(r"^[ \t]{0,3}#{1,6}[ \t]+")
_FENCE_OPEN_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})([A-Za-z0-9_+.-]*)[ \t]*$")

_LANGUAGE_ALIASES = {
    "evm": frozenset({"solidity", "sol"}),
    "solana": frozenset({"rust", "rs"}),
    "soroban": frozenset({"rust", "rs"}),
    "l1_rust": frozenset({"rust", "rs"}),
    "aptos": frozenset({"move"}),
    "sui": frozenset({"move"}),
    "l1_go": frozenset({"go", "golang"}),
}
_EXTENSIONS = {
    "evm": (".t.sol",),
    "solana": (".rs",),
    "soroban": (".rs",),
    "l1_rust": (".rs",),
    "aptos": (".move",),
    "sui": (".move",),
    "l1_go": ("_test.go",),
}


def _fail(code: str, detail: str) -> NoReturn:
    raise MechanicalPoCSourceError(code, detail)


def normalize_language(language: str) -> str:
    value = str(language or "").strip().lower()
    if value == "go":
        return "l1_go"
    if value == "rust":
        return "l1_rust"
    if value not in _LANGUAGE_ALIASES:
        _fail("POC_SOURCE_LANGUAGE", f"unsupported language {language!r}")
    return value


def canonical_test_path(value: str, language: str) -> str:
    lang = normalize_language(language)
    raw = str(value or "").strip().replace("\\", "/")
    path = Path(raw)
    if (
        not raw
        or "\x00" in raw
        or path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _fail("POC_SOURCE_PATH", f"unsafe or non-canonical test path {value!r}")
    if not any(raw.endswith(suffix) for suffix in _EXTENSIONS[lang]):
        _fail(
            "POC_SOURCE_PATH",
            f"test path {raw!r} has no {lang} test extension",
        )
    if lang == "evm" and path.parts[0] not in {"test", "tests"}:
        _fail("POC_SOURCE_PATH", "EVM PoC source must be under test/ or tests/")
    return raw


def _extract_fenced_source(text: str) -> tuple[str, bytes]:
    lines = text.splitlines(keepends=True)
    headings = [index for index, line in enumerate(lines) if _HEADING_RE.match(line.rstrip("\r\n"))]
    if len(headings) != 1:
        _fail(
            "POC_SOURCE_SECTION",
            f"expected exactly one Mechanical PoC Source heading, observed {len(headings)}",
        )
    start = headings[0] + 1
    opener_index: int | None = None
    opener: re.Match[str] | None = None
    for index in range(start, len(lines)):
        surface = lines[index].rstrip("\r\n")
        if not surface.strip():
            continue
        if _ANY_HEADING_RE.match(surface):
            _fail("POC_SOURCE_FENCE", "source section contains no immediate fenced block")
        opener = _FENCE_OPEN_RE.match(surface)
        if opener is None:
            _fail("POC_SOURCE_FENCE", "source section must begin with one fenced block")
        opener_index = index
        break
    if opener_index is None or opener is None:
        _fail("POC_SOURCE_FENCE", "source fence is absent")
    delimiter = opener.group(1)
    marker = delimiter[0]
    minimum = len(delimiter)
    close_re = re.compile(rf"^[ \t]{{0,3}}{re.escape(marker)}{{{minimum},}}[ \t]*$")
    close_index: int | None = None
    for index in range(opener_index + 1, len(lines)):
        if close_re.match(lines[index].rstrip("\r\n")):
            close_index = index
            break
    if close_index is None:
        _fail("POC_SOURCE_FENCE", "source fence is unterminated")
    # The fenced bytes, not surrounding commentary, are the executable
    # authority.  Verifiers commonly append proof-scope prose below the
    # fence without starting another heading.  That prose cannot change the
    # extracted source; reject only a second fence, which would make the
    # executable choice ambiguous.
    for line in lines[close_index + 1:]:
        surface = line.rstrip("\r\n")
        if _ANY_HEADING_RE.match(surface):
            break
        if _FENCE_OPEN_RE.match(surface):
            _fail("POC_SOURCE_SECTION", "source section contains a second fenced block")
    body_text = "".join(lines[opener_index + 1:close_index])
    try:
        body = body_text.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise MechanicalPoCSourceError(
            "POC_SOURCE_ENCODING", "source cannot be represented as UTF-8"
        ) from exc
    if not body or not body.strip():
        _fail("POC_SOURCE_EMPTY", "fenced source is empty")
    if len(body) > MAX_SOURCE_BYTES:
        _fail("POC_SOURCE_SIZE", "fenced source exceeds the 2 MiB bound")
    if b"\x00" in body:
        _fail("POC_SOURCE_ENCODING", "fenced source contains NUL")
    return opener.group(2).casefold(), body


def extract_mechanical_poc_source(
    verify_path: Path,
    *,
    language: str,
    test_path: str,
    test_function: str | None,
) -> MechanicalPoCSource:
    path = Path(verify_path)
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise MechanicalPoCSourceError(
            "POC_SOURCE_READ", f"verifier artifact is unreadable: {exc}"
        ) from exc
    lang = normalize_language(language)
    relative = canonical_test_path(test_path, lang)
    fence_language, source = _extract_fenced_source(text)
    if fence_language not in _LANGUAGE_ALIASES[lang]:
        _fail(
            "POC_SOURCE_LANGUAGE",
            f"fence language {fence_language!r} does not match {lang}",
        )
    function_label = str(test_function or "").strip()
    if function_label:
        # Verifiers sometimes name both the deterministic harm test and its
        # fuzz companion in this display field.  The executor selects the
        # first identifier; authenticate *both* against the fenced source so
        # the extra label cannot silently claim a nonexistent fuzz test.
        decoded = source.decode("utf-8", errors="strict")
        shorthand = (
            re.fullmatch(r"test_([A-Za-z0-9_]+)_and_fuzz_\1", function_label)
            if lang == "evm"
            else None
        )
        if (
            shorthand is not None
            and re.search(
                rf"\bfunction\s+{re.escape(function_label)}\s*\(", decoded,
            ) is None
        ):
            # A common display shorthand names the primary test plus a fuzz
            # companion without spelling either actual Solidity declaration.
            # Accept only the exact shared-ID form and verify both declarations.
            functions = [
                f"test_{shorthand.group(1)}",
                f"testFuzz_{shorthand.group(1)}",
            ]
        else:
            functions = re.split(r"\s+and\s+", function_label)
        if len(functions) > 2:
            _fail("POC_SOURCE_FUNCTION", "too many test function identities")
        for function in functions:
            if lang == "evm":
                # Foundry reports a signature for parameterized fuzz tests,
                # whereas declarations and --match-test use the bare name.
                signature = re.fullmatch(
                    r"([A-Za-z_][A-Za-z0-9_]*)\([A-Za-z0-9_, \t\[\]]*\)",
                    function,
                )
                if signature is not None:
                    function = signature.group(1)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function) is None:
                _fail("POC_SOURCE_FUNCTION", "test function identity is malformed")
            declarations = {
                "evm": rf"\bfunction\s+{re.escape(function)}\s*\(",
                "l1_go": rf"\bfunc\s+{re.escape(function)}\s*\(",
                "aptos": rf"\bfun\s+{re.escape(function)}\s*\(",
                "sui": rf"\bfun\s+{re.escape(function)}\s*\(",
                "solana": rf"\bfn\s+{re.escape(function)}\s*(?:<[^>]*>\s*)?\(",
                "soroban": rf"\bfn\s+{re.escape(function)}\s*(?:<[^>]*>\s*)?\(",
                "l1_rust": rf"\bfn\s+{re.escape(function)}\s*(?:<[^>]*>\s*)?\(",
            }
            if re.search(declarations[lang], decoded) is None:
                _fail(
                    "POC_SOURCE_FUNCTION",
                    f"fenced source does not declare {function}",
                )
    return MechanicalPoCSource(
        relative_path=relative,
        language=lang,
        fence_language=fence_language,
        source=source,
        source_sha256=hashlib.sha256(source).hexdigest(),
        source_size=len(source),
    )


def materialize_mechanical_poc_source(
    workspace_root: Path,
    source: MechanicalPoCSource,
) -> Path:
    """Publish exact source bytes below a disposable workspace, replay-safely."""

    try:
        root = Path(workspace_root).resolve(strict=True)
        observed = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise MechanicalPoCSourceError(
            "POC_SOURCE_WORKSPACE", f"workspace is unavailable: {exc}"
        ) from exc
    if not stat.S_ISDIR(observed.st_mode):
        _fail("POC_SOURCE_WORKSPACE", "workspace is not a directory")
    relative = canonical_test_path(source.relative_path, source.language)
    current = root
    for part in Path(relative).parts[:-1]:
        current = current / part
        try:
            row = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o700)
                row = current.lstat()
            except OSError as exc:
                raise MechanicalPoCSourceError(
                    "POC_SOURCE_WORKSPACE",
                    f"cannot create source directory {part!r}: {exc}",
                ) from exc
        if stat.S_ISLNK(row.st_mode) or not stat.S_ISDIR(row.st_mode):
            _fail("POC_SOURCE_WORKSPACE", "source parent is aliased or not a directory")
    destination = root / relative
    try:
        lexical = destination.lstat()
    except FileNotFoundError:
        lexical = None
    if lexical is not None:
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or int(lexical.st_nlink) != 1
        ):
            _fail("POC_SOURCE_REPLAY", "existing source destination is unsafe")
        try:
            existing = destination.read_bytes()
        except OSError as exc:
            raise MechanicalPoCSourceError(
                "POC_SOURCE_REPLAY", f"existing source is unreadable: {exc}"
            ) from exc
        if existing != source.source:
            _fail("POC_SOURCE_REPLAY", "existing source differs from verifier bytes")
        return destination
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(source.source)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise MechanicalPoCSourceError(
            "POC_SOURCE_PUBLICATION", f"source publication failed: {exc}"
        ) from exc
    if destination.read_bytes() != source.source:
        _fail("POC_SOURCE_PUBLICATION", "published source bytes changed")
    return destination


__all__ = [
    "MAX_SOURCE_BYTES",
    "MechanicalPoCSource",
    "MechanicalPoCSourceError",
    "canonical_test_path",
    "extract_mechanical_poc_source",
    "materialize_mechanical_poc_source",
    "normalize_language",
]
