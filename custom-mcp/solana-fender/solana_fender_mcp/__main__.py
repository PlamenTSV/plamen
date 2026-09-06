#!/usr/bin/env python3
"""
Solana Fender MCP Server - Python wrapper around the solana_fender CLI.

Exposes two MCP tools:
  - security_check_program: Analyze an entire Solana program directory
  - security_check_file: Analyze a single Solana source file
"""

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


FENDER_BINARY = "solana_fender"


def find_fender() -> Optional[str]:
    """Locate the solana_fender binary."""
    path = shutil.which(FENDER_BINARY)
    if path:
        return path
    # Fallback: check common cargo bin location on Windows
    cargo_bin = Path.home() / ".cargo" / "bin" / "solana_fender.exe"
    if cargo_bin.is_file():
        return str(cargo_bin)
    return None


async def security_check_program(program_path: str) -> str:
    """Run solana_fender on a program directory."""
    fender = find_fender()
    if not fender:
        return (
            "Error: solana_fender is not installed. "
            "Install it with: cargo install solana_fender"
        )

    path = Path(program_path)
    if not path.is_dir():
        return f"Error: Program directory not found: {program_path}"

    try:
        result = subprocess.run(
            [fender, "-p", str(path), "--markdown"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = result.stdout.strip()
        # Fender deliberately exits 1 when it found vulnerabilities.  Treat
        # that as a successful scan result; only operational failures (>1)
        # should be converted into an MCP error.
        if result.returncode not in (0, 1):
            error = result.stderr.strip() or output or f"Exit code {result.returncode}"
            return f"Fender analysis failed:\n{error}"
        return output if output else "No findings detected."
    except subprocess.TimeoutExpired:
        return "Error: solana_fender timed out (300s limit)"
    except Exception as e:
        return f"Error running solana_fender: {e}"


async def security_check_file(file_path: str) -> str:
    """Run solana_fender on a single file."""
    fender = find_fender()
    if not fender:
        return (
            "Error: solana_fender is not installed. "
            "Install it with: cargo install solana_fender"
        )

    path = Path(file_path)
    if not path.is_file():
        return f"Error: File not found: {file_path}"

    try:
        result = subprocess.run(
            [fender, "-f", str(path), "--markdown"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = result.stdout.strip()
        # Exit 1 means "findings present", not scanner failure.
        if result.returncode not in (0, 1):
            error = result.stderr.strip() or output or f"Exit code {result.returncode}"
            return f"Fender analysis failed:\n{error}"
        return output if output else "No findings detected."
    except subprocess.TimeoutExpired:
        return "Error: solana_fender timed out (300s limit)"
    except Exception as e:
        return f"Error running solana_fender: {e}"


def get_tool_definitions() -> List[Tool]:
    """Return the MCP tool definitions."""
    return [
        Tool(
            name="security_check_program",
            description=(
                "Run Solana Fender static analysis on a Solana program directory. "
                "Fender checks for 19 vulnerability patterns including missing signer checks, "
                "account validation, integer overflow, PDA verification, and more."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the Solana program directory to analyze",
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="security_check_file",
            description=(
                "Run Solana Fender static analysis on a single Solana source file (.rs). "
                "Checks for vulnerability patterns including missing signer checks, "
                "account validation, integer overflow, and PDA verification."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to a single Solana program file (.rs) to analyze",
                    },
                },
                "required": ["path"],
            },
        ),
    ]


async def execute_tool(name: str, arguments: Dict[str, Any]) -> str:
    """Dispatch to the correct tool handler."""
    path = arguments.get("path", "")

    if name == "security_check_program":
        return await security_check_program(path)

    if name == "security_check_file":
        return await security_check_file(path)

    return f"Unknown tool: {name}"


async def main():
    """Main entry point for the MCP server."""
    server = Server("solana-fender")
    tools = get_tool_definitions()

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            result = await execute_tool(name, arguments)
            return [TextContent(type="text", text=result)]
        except Exception as exc:
            return [TextContent(type="text", text=f"Error: {exc}")]

    async with stdio_server() as (read_stream, write_stream):
        print("Solana Fender MCP Server running on stdio", file=sys.stderr)
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def run():
    """Entry point for console script."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
