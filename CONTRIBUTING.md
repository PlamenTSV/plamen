# Contributing to Plamen

Thank you for your interest in contributing to Plamen! This guide will help you get started.

## How Plamen Works

Plamen is a multi-agent security auditing pipeline built on Claude Code. It consists of:

- **Orchestration rules** (`rules/`) - Phase definitions, scoring models, report templates
- **Language prompts** (`prompts/{evm,solana,aptos,sui}/`) - Per-chain agent prompts and templates
- **Skills** (`agents/skills/`) - Methodology files that agents read at audit time
- **Agent definitions** (`agents/depth-*.md`) - Depth agent role definitions
- **MCP servers** (`custom-mcp/`) - Tool servers (RAG database, static analyzers)
- **CLI wrapper** (`plamen.py`) - Terminal UI that launches audits

## Ways to Contribute

### 1. New Skills (Most Wanted)

Skills are methodology files that teach agents HOW to analyze specific vulnerability classes. They live in `agents/skills/`.

**Types:**
- **Regular skills** (`agents/skills/{language}/{skill-name}/`) - Flag-triggered, loaded when code patterns are detected
- **Injectable skills** (`agents/skills/injectable/{skill-name}/`) - Protocol-type-triggered, loaded for specific protocol categories
- **Niche agents** (`agents/skills/niche/{skill-name}/`) - Standalone agents for focused analysis

**Skill quality bar:**
- Teaches methodology (HOW to look), not patterns (WHAT to find)
- Has clear trigger conditions (when should it activate?)
- Includes a step execution checklist
- Includes common false positives section
- Under 300 lines (hard cap - context budget)
- Has been tested on at least one real codebase

**Format:** Each skill lives in a named folder: `agents/skills/{language}/{skill-name}/SKILL.md`. For skills over 500 lines, split into `SKILL.md` (core workflow) + reference files (`templates.md`, `advanced.md`) that `SKILL.md` points to. See any existing skill in `agents/skills/evm/` for the template.

### 2. Scanner Checks

Scanner templates (`prompts/{language}/phase4b-scanner-templates.md`) contain checklist-style checks. New checks should be:
- Universal (applies to ALL contracts, not protocol-specific)
- Under 5 lines
- Low false positive rate

### 3. Bug Reports

Found a bug in the pipeline? File an issue with:
- Audit mode used (Core/Thorough)
- Language/chain
- What went wrong (missed finding, false positive, crash, etc.)
- Relevant scratchpad artifacts if possible

### 4. UI/Wrapper Improvements

The CLI wrapper (`plamen.py`) and launch scripts are always open for UX improvements.

### 5. MCP Server Improvements

The unified-vuln-db MCP server (`custom-mcp/unified-vuln-db/`) powers RAG search. Contributions welcome for:
- New vulnerability data sources
- Better search/ranking algorithms
- Performance improvements

## Development Setup

### Prerequisites

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) installed
- Python 3.10+ (for CLI wrapper and MCP servers)
- Node.js 18+ (for Claude Code)

### Local Setup

```bash
# Clone the repo
git clone https://github.com/PlamenTSV/plamen.git ~/.claude

# Install CLI wrapper dependencies
pip install rich InquirerPy

# Install MCP server dependencies
cd ~/.claude/custom-mcp/unified-vuln-db
pip install -e .

# Run the CLI
plamen.bat  # Windows
./plamen.sh # Linux/macOS
```

### Testing Your Changes

**Skills:** Run a Core audit on a relevant test project and check the scratchpad for your skill's output.

**Scanner checks:** Run a Core audit and grep the blind_spot scanner output for your check ID.

**Wrapper:** Run `python plamen.py` and walk through the interactive flow.

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main` (`git checkout -b feature/my-skill`)
3. **Make your changes** following the guidelines above
4. **Test** on at least one real codebase
5. **Open a PR** using the PR template

### PR Requirements

- [ ] Changes are under the appropriate file size caps (see `rules/post-audit-improvement-protocol.md` Appendix A)
- [ ] New skills include a step execution checklist and false positives section
- [ ] No secrets, API keys, or credentials in the diff
- [ ] Changes don't break existing skill triggers or agent definitions
- [ ] Description explains WHY this change improves audit quality

### Review Process

1. Maintainer reviews for methodology quality and pipeline fit
2. If skill/check: tested on a real codebase to verify detection rate and false positive rate
3. Merged after approval

## DCO (Developer Certificate of Origin)

By contributing to this project, you certify that your contribution is your own work and you have the right to submit it under the MIT license. Sign off your commits:

```
git commit -s -m "Add new vault accounting skill"
```

This adds a `Signed-off-by: Your Name <your@email.com>` line to your commit message.

## File Size Caps

To prevent context bloat, these caps are enforced:

| File Category | Cap |
|---------------|-----|
| Individual skills | 300 lines |
| Scanner templates | 600 lines |
| Depth templates | 250 lines |
| Generic security rules | 1000 lines |
| Recon prompt | 1100 lines |

## Questions?

Open a Discussion on GitHub or file an issue tagged `question`.
