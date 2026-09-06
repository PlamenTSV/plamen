# MCP Servers

MCP is a narrow audit transport in Plamen, not a general installation or
backend abstraction. The deterministic analyzers and chain toolchains run
locally. Model backends are launched from the authenticated immutable runtime,
not through MCP.

## Audit transport policy

| Audit route | MCP availability | Research behavior |
|---|---|---|
| Claude headless `rag_sweep` | Receipt-bound `unified-vuln-db`, only when host containment is admitted | Contained local RAG; governed Web/local fallback when unavailable |
| Claude headless, other roles | None | Governed Web/local sources as allowed by the phase |
| Claude PTY workers | None | Governed Web/local sources |
| Codex (`codex exec --ignore-user-config`) | None | Governed Web/local sources |

Consequently, user-level `mcp.json`, Codex MCP tables, and ambient MCP
processes do not become audit authority. Plamen does not promise that a server
available in an interactive Claude or Codex session is available to an audit
subprocess.

## Immutable selection and launch

`plamen install` materializes MCP payloads with managed Node.js 24.20.0 and
npm 11.19.0. It never uses ambient `node`, `npm`, `npx`, npm wrappers, or a
global package directory. The install also materializes exact Claude Code
2.1.252 and Codex 0.152.0 backends; backend stdio is never routed through the
MCP sanitizer.

The committed signed current selection binds the generation and its receipt,
census, request, policy, executable resource closures, and exact server launch
descriptors. A public MCP launch must match that selection byte-for-byte. The
installed front revalidates package and generation authority, keeps the
generation locked for the process lifetime, and applies the schema sanitizer
before any server protocol traffic. Stale selection, path substitution,
unexpected arguments, extra environment, updater debris, or closure drift is
denied before spawn.

Do not edit generated MCP configuration, invoke files below the generation
store directly, or copy paths from the selection into a manual command. A new
MCP or backend version becomes current only through `plamen install` from a
complete governed source release.

## Containment by operating system

- Windows admits the contained route with a non-breakaway Job object and
  verifies descendant-process teardown.
- Linux admits it only through the delegated cgroup v2 plus Landlock policy
  when the required kernel and delegation capabilities are present.
- Unsupported Linux configurations and macOS fail closed before MCP spawn.

Failing closed affects only contained MCP RAG. The audit itself remains
supported on Windows, Linux, and macOS and continues with the governed Web or
local research fallback. Claude PTY and Codex do not attempt MCP containment.

## Servers and API keys

The only server admitted to the current audit path is the bundled
`unified-vuln-db` service for Claude-headless `rag_sweep`. Its index can be
built with:

```bash
plamen rag
```

Some data sources require an API key such as `SOLODIT_API_KEY`. Store secrets
through the documented Plamen/provider environment configuration, never in
generated selection files or command arguments. The signed server descriptor
contains only the exact allowed environment-variable names; it does not store
secret values.

The source tree also contains analyzer integrations and historical MCP
components. Their presence does not make them audit-executable. Production
availability is determined solely by the current signed selection and route
policy described above.

## Diagnostics

Run:

```bash
plamen doctor
```

Doctor authenticates the installed receipt, managed runtime, current
selection, and containment prerequisites without starting a model or MCP
server. It does not consult global Node/npm/npx, Claude, or Codex installs.
