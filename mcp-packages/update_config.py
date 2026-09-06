"""Converge Claude MCP config on the authenticated immutable Plamen front."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


MCP_JSON = Path.home() / ".claude" / "mcp.json"
PUBLIC_FRONT = Path.home() / ".local" / "bin" / (
    "plamen.cmd" if os.name == "nt" else "plamen"
)


def _selection() -> dict:
    result = subprocess.run(
        [str(PUBLIC_FRONT), "mcp-selection", "--json", "--backend", "claude"],
        capture_output=True, timeout=60,
    )
    if result.returncode != 0 or result.stderr:
        raise RuntimeError("authenticated MCP selection admission failed")
    value = json.loads(result.stdout.decode("utf-8"))
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if result.stdout != canonical:
        raise RuntimeError("authenticated MCP selection output is noncanonical")
    return value


def _launcher_args(selection: dict, server: str) -> list[str]:
    if server not in selection["server_launches"]:
        raise RuntimeError("MCP server is absent from authenticated selection")
    return [
        "mcp-launch", "--backend", "claude", "--server", server,
        "--generation", selection["generation_id"],
        "--receipt-sha256", selection["receipt_sha256"],
        "--census-sha256", selection["census_sha256"],
        "--request-sha256", selection["request_sha256"],
        "--policy-sha256", selection["generation_policy_sha256"],
    ]


def main() -> int:
    if not MCP_JSON.is_file() or not PUBLIC_FRONT.is_file():
        print("ERROR: run 'plamen install' first.", file=sys.stderr)
        return 1
    selection = _selection()
    config = json.loads(MCP_JSON.read_text(encoding="utf-8"))
    servers = config.setdefault("mcpServers", {})
    for name in sorted(selection["server_launches"]):
        prior = servers.get(name) if isinstance(servers.get(name), dict) else {}
        row = {"command": str(PUBLIC_FRONT), "args": _launcher_args(selection, name)}
        if isinstance(prior.get("env"), dict):
            row["env"] = prior["env"]
        servers[name] = row
    descriptor, temporary = tempfile.mkstemp(
        prefix=".mcp.json.", suffix=".tmp", dir=MCP_JSON.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(config, stream, indent=2); stream.write("\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, MCP_JSON)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
    print(f"DONE: {len(selection['server_launches'])} authenticated MCP routes updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
