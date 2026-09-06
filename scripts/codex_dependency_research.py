"""Typed Codex web-search evidence gate for dependency research."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urljoin, urlsplit

import rooted_path_io as rooted_io


CONTEXT_SCHEMA = "plamen.codex_dependency_research_staged_gate.v1"
FETCH_RECEIPT_SCHEMA = "plamen.codex_dependency_fetch_receipt.v1"
FETCH_RECEIPT_FILE = "codex_dependency_fetch_receipt.json"
_URL_RE = re.compile(r"https://[^\s<>\]\[(){}|\"']+")


def _load_json(path: Path) -> dict[str, Any]:
    return _load_json_bytes(path.read_bytes(), label=str(path))


def _load_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=pairs,
    )
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {label}")
    return value


def _rooted_context_file(root: Path, value: Any, *, label: str) -> Path:
    """Bind one persisted absolute filename beneath ``root`` lexically."""

    candidate = rooted_io.absolute_path(str(value))
    try:
        relative = os.path.relpath(os.fspath(candidate), os.fspath(root))
    except ValueError as exc:
        raise ValueError(f"{label} escapes the scratchpad root") from exc
    return rooted_io.safe_descendant(
        root,
        Path(relative).as_posix(),
        allow_missing=False,
        label=label,
    )


def _valid_https(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.port in {None, 443}
        and not parsed.fragment
    )


def _table_rows(raw: bytes) -> list[list[str]]:
    text = raw.decode("utf-8", errors="strict")
    lines = [line.strip() for line in text.splitlines() if line.strip().startswith("|")]
    header_index = next(
        (
            index for index, line in enumerate(lines)
            if "Obligation ID" in line and "Fetch Status" in line
        ),
        -1,
    )
    if header_index < 0 or header_index + 1 >= len(lines):
        raise ValueError("dependency report header is missing")
    header = [cell.strip() for cell in lines[header_index].strip("|").split("|")]
    expected = [
        "Obligation ID", "Dependency", "Integration Surface",
        "Assumed Behavior", "Real Behavior", "Source", "Conformance",
        "Fetch Status",
    ]
    if header != expected:
        raise ValueError("dependency report columns differ")
    rows: list[list[str]] = []
    for line in lines[header_index + 2:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != len(expected):
            continue
        rows.append(cells)
    return rows


def _web_search_objects(stdout: bytes) -> list[Mapping[str, Any]]:
    objects: list[Mapping[str, Any]] = []
    for line in stdout.decode("utf-8", errors="strict").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            continue
        item = event.get("item")
        if isinstance(item, dict) and item.get("type") == "web_search":
            objects.append(item)
        elif event.get("type") == "web_search":
            objects.append(event)
    return objects


def _urls_in(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.update(match.rstrip(".,;:") for match in _URL_RE.findall(value))
    elif isinstance(value, Mapping):
        for child in value.values():
            found.update(_urls_in(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_urls_in(child))
    return found


def _provider_stdout(context: Mapping[str, Any]) -> bytes:
    root = rooted_io.checked_directory(
        str(context["scratchpad_root"]),
        label="Codex dependency scratchpad",
    )
    completion = _rooted_context_file(
        root,
        context["attempt_completion"],
        label="Codex dependency attempt completion",
    )
    attempt = _load_json_bytes(
        rooted_io.read_bytes(
            completion,
            label="Codex dependency attempt completion",
        ),
        label=str(completion),
    )
    provider_relative = str(attempt.get("provider_completion_relative_path") or "")
    provider_candidate = rooted_io.safe_descendant(
        root,
        provider_relative,
        allow_missing=True,
        label="Codex dependency provider completion",
    )
    deadline = time.monotonic() + 2.0
    while not rooted_io.lexists(provider_candidate):
        if time.monotonic() >= deadline:
            raise FileNotFoundError(provider_candidate)
        # Windows low-integrity publication can make the content-addressed
        # receipt visible a few scheduler ticks after attempt completion.
        # This is local durability observation, not a web/MCP retry.
        time.sleep(0.02)
    provider_path = rooted_io.safe_descendant(
        root,
        provider_relative,
        allow_missing=False,
        label="Codex dependency provider completion",
    )
    provider = _load_json_bytes(
        rooted_io.read_bytes(
            provider_path,
            label="Codex dependency provider completion",
        ),
        label=str(provider_path),
    )
    blob = provider.get("stdout_blob")
    if not isinstance(blob, Mapping) or set(blob) != {"relative_path", "sha256", "size"}:
        raise ValueError("Codex stdout blob authority is malformed")
    provider_parent = Path(provider_relative.replace("\\", "/")).parent
    blob_relative = (provider_parent / str(blob["relative_path"])).as_posix()
    blob_path = rooted_io.safe_descendant(
        root,
        blob_relative,
        allow_missing=False,
        label="Codex dependency stdout blob",
    )
    raw = rooted_io.read_bytes(
        blob_path,
        label="Codex dependency stdout blob",
    )
    if len(raw) != blob["size"] or hashlib.sha256(raw).hexdigest() != blob["sha256"]:
        raise ValueError("Codex stdout blob bytes drifted")
    observation = provider.get("stream_observation")
    if not isinstance(observation, Mapping) or observation.get("stdout_overflow") is not False:
        raise ValueError("Codex stdout evidence is incomplete or overflowed")
    return raw


def staged_codex_dependency_research_validator(
    staged_outputs: Mapping[str, bytes],
    context: Mapping[str, Any],
) -> Sequence[str]:
    """Require report rows to join to typed Codex ``web_search`` events.

    This proves provider-side search/result provenance.  A distinct DRIVER
    fetch transaction subsequently retrieves and hashes every claimed HTTPS
    source before the report can become downstream dependency authority.
    """

    required = {
        "schema", "scratchpad_root", "attempt_completion",
        "obligations_path", "research_output",
    }
    try:
        if set(context) != required or context.get("schema") != CONTEXT_SCHEMA:
            raise ValueError("Codex dependency gate context differs")
        matching = [
            raw for identity, raw in staged_outputs.items()
            if str(identity).removeprefix("scratchpad:")
            == str(context["research_output"])
        ]
        if len(matching) != 1:
            raise ValueError("Codex dependency output denominator differs")
        root = rooted_io.checked_directory(
            str(context["scratchpad_root"]),
            label="Codex dependency scratchpad",
        )
        obligations_path = _rooted_context_file(
            root,
            context["obligations_path"],
            label="Codex dependency obligations",
        )
        obligations = _load_json_bytes(
            rooted_io.read_bytes(
                obligations_path,
                label="Codex dependency obligations",
            ),
            label=str(obligations_path),
        ).get("obligations")
        if not isinstance(obligations, list):
            raise ValueError("dependency obligation rows are malformed")
        expected_ids = {
            str(row.get("obligation_id") or "")
            for row in obligations if isinstance(row, Mapping)
        }
        if "" in expected_ids or not expected_ids:
            raise ValueError("dependency obligation identity set is empty")
        rows = _table_rows(matching[0])
        seen: set[str] = set()
        researched_urls: set[str] = set()
        for cells in rows:
            obligation_id, source, status = cells[0], cells[5], cells[7]
            if obligation_id not in expected_ids or obligation_id in seen:
                raise ValueError("dependency obligation row identity differs")
            seen.add(obligation_id)
            urls = set(_URL_RE.findall(source))
            if status not in {
                "RESEARCHED", "FETCH_FAILED", "NEEDS_DEPENDENCY_RESEARCH",
            }:
                raise ValueError("dependency report fetch status is invalid")
            if status == "RESEARCHED":
                if not urls or any(not _valid_https(url) for url in urls):
                    raise ValueError("RESEARCHED dependency lacks canonical HTTPS source")
                researched_urls.update(urls)
            elif urls:
                raise ValueError("unresearched dependency claims a source URL")
        if seen != expected_ids:
            raise ValueError("dependency report omits obligation rows")
        web_objects = _web_search_objects(_provider_stdout(context))
        if researched_urls and not web_objects:
            raise ValueError("RESEARCHED rows lack typed Codex web_search events")
        event_urls = set().union(*(_urls_in(item) for item in web_objects)) if web_objects else set()
        missing = sorted(researched_urls - event_urls)
        if missing:
            raise ValueError(
                "dependency sources are absent from typed Codex web_search events: "
                + ", ".join(missing)
            )
        return []
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return [f"Codex dependency web-search authority is invalid: {exc}"]


def claimed_researched_sources(report_raw: bytes) -> dict[str, list[str]]:
    claims: dict[str, list[str]] = {}
    for cells in _table_rows(report_raw):
        obligation_id, source, status = cells[0], cells[5], cells[7]
        urls = sorted(set(_URL_RE.findall(source)))
        if status == "RESEARCHED":
            if not urls or any(not _valid_https(url) for url in urls):
                raise ValueError(
                    f"RESEARCHED obligation has invalid HTTPS source: {obligation_id}"
                )
            claims[obligation_id] = urls
        elif urls:
            raise ValueError(
                f"unresearched obligation claims source: {obligation_id}"
            )
    return claims


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, *, timeout: float):
        super().__init__(hostname, port=443, timeout=timeout)
        self._pinned_address = address

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._pinned_address, 443), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _public_addresses(hostname: str) -> list[str]:
    rows = socket.getaddrinfo(
        hostname, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    addresses = sorted({str(row[4][0]) for row in rows})
    if not addresses:
        raise ValueError("DNS_EMPTY")
    if any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise ValueError("DNS_NON_PUBLIC")
    return addresses


def _fetch_https(url: str, *, max_bytes: int = 2 * 1024 * 1024) -> dict[str, Any]:
    current = url
    redirects: list[str] = []
    for _hop in range(4):
        if not _valid_https(current):
            raise ValueError("URL_POLICY")
        parsed = urlsplit(current)
        hostname = str(parsed.hostname)
        addresses = _public_addresses(hostname)
        connection = _PinnedHTTPSConnection(hostname, addresses[0], timeout=20.0)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": hostname,
                    "User-Agent": "Plamen-Dependency-Research/1.0",
                    "Accept": "text/html,application/json,text/plain,*/*;q=0.1",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            status = int(response.status)
            if status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                response.read(min(max_bytes, 65536))
                if not location:
                    raise ValueError("REDIRECT_WITHOUT_LOCATION")
                successor = urljoin(current, location)
                if successor in redirects or successor == current:
                    raise ValueError("REDIRECT_LOOP")
                redirects.append(successor)
                current = successor
                continue
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError("RESPONSE_OVERSIZE")
            if not 200 <= status < 300:
                raise ValueError(f"HTTP_{status}")
            return {
                "status": "FETCHED",
                "requested_url": url,
                "final_url": current,
                "redirects": redirects,
                "resolved_addresses": addresses,
                "http_status": status,
                "content_type": str(response.getheader("Content-Type") or "")[:256],
                "content_sha256": hashlib.sha256(raw).hexdigest(),
                "content_size": len(raw),
                "error_code": "",
            }
        finally:
            connection.close()
    raise ValueError("REDIRECT_LIMIT")


def build_fetch_receipt(report_raw: bytes) -> dict[str, Any]:
    claims = claimed_researched_sources(report_raw)
    obligations_by_url: dict[str, list[str]] = {}
    for obligation_id, urls in claims.items():
        for url in urls:
            obligations_by_url.setdefault(url, []).append(obligation_id)
    entries: list[dict[str, Any]] = []
    for url, obligation_ids in sorted(obligations_by_url.items()):
        try:
            row = _fetch_https(url)
        except (OSError, ValueError, socket.timeout, ssl.SSLError) as exc:
            row = {
                "status": "FAILED",
                "requested_url": url,
                "final_url": "",
                "redirects": [],
                "resolved_addresses": [],
                "http_status": 0,
                "content_type": "",
                "content_sha256": "",
                "content_size": 0,
                "error_code": str(exc)[:256],
            }
        entries.append({**row, "obligation_ids": sorted(obligation_ids)})
    payload: dict[str, Any] = {
        "schema_version": FETCH_RECEIPT_SCHEMA,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "report_sha256": hashlib.sha256(report_raw).hexdigest(),
        "entries": entries,
    }
    unsigned = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["payload_digest"] = hashlib.sha256(unsigned).hexdigest()
    return payload


def write_fetch_receipt(report_path: Path, receipt_path: Path) -> None:
    payload = build_fetch_receipt(Path(report_path).read_bytes())
    Path(receipt_path).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def validate_fetch_receipt(report_path: Path, receipt_path: Path) -> list[str]:
    try:
        report_raw = Path(report_path).read_bytes()
        claims = claimed_researched_sources(report_raw)
        expected = {
            (obligation_id, url)
            for obligation_id, urls in claims.items()
            for url in urls
        }
        payload = _load_json(Path(receipt_path))
        if payload.get("schema_version") != FETCH_RECEIPT_SCHEMA:
            raise ValueError("fetch receipt schema differs")
        digest = payload.get("payload_digest")
        unsigned = {key: value for key, value in payload.items() if key != "payload_digest"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        if digest != hashlib.sha256(canonical).hexdigest():
            raise ValueError("fetch receipt digest differs")
        if payload.get("report_sha256") != hashlib.sha256(report_raw).hexdigest():
            raise ValueError("fetch receipt report binding differs")
        rows = payload.get("entries")
        if not isinstance(rows, list):
            raise ValueError("fetch receipt entries are malformed")
        observed: set[tuple[str, str]] = set()
        for row in rows:
            if not isinstance(row, Mapping):
                raise ValueError("fetch receipt row is malformed")
            url = str(row.get("requested_url") or "")
            obligation_ids = row.get("obligation_ids")
            if not isinstance(obligation_ids, list):
                raise ValueError("fetch receipt obligation set is malformed")
            observed.update((str(value), url) for value in obligation_ids)
            if row.get("status") != "FETCHED":
                raise ValueError(f"dependency source fetch failed: {url}")
            if (
                not _valid_https(url)
                or not _valid_https(str(row.get("final_url") or ""))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("content_sha256") or ""))
                or not isinstance(row.get("content_size"), int)
                or not 0 <= int(row["content_size"]) <= 2 * 1024 * 1024
                or not 200 <= int(row.get("http_status") or 0) < 300
            ):
                raise ValueError(f"dependency fetch evidence is malformed: {url}")
        if observed != expected:
            raise ValueError("fetch receipt claim denominator differs")
        return []
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return [f"Codex dependency fetch authority is invalid: {exc}"]
