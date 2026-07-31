"""
M6 concept demo - Vulnerable MCP Server: command injection
Demonstrates: shell=True in an MCP tool -> command injection via tool arguments.
Similar in shape to CVE-2025-53818 (GitHub Kanban MCP).

*** FOR EDUCATIONAL USE ONLY - CONTAINS INTENTIONAL VULNERABILITIES ***

This is a normal-looking "file manager" MCP server: search files, count lines,
list a directory. Every tool builds a shell string from the caller's arguments
and runs it with subprocess(shell=True). shell=True is kept ON PURPOSE - it is
the vulnerability M6 teaches. Note the args are wrapped in double quotes
(e.g. ls -la "{directory}"), so the injection must BREAK OUT of the quotes:
    directory=." ; whoami ; ls "
which the shell runs as:  ls -la "." ; whoami ; ls ""  (see README, Demo A).

Genericized from the Windows original: dir/PowerShell -> find/wc/ls (macOS/Linux).

Transport: stdio. Drive it with test_client.py, or wire it into Claude Desktop /
MCP Inspector (see README - those are manual, GUI-only steps).
"""
import asyncio
import subprocess

from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("file-manager")


@server.list_tools()
async def list_tools():
    """Expose available tools to MCP clients."""
    return [
        Tool(
            name="search_files",
            description="Search for files matching a pattern in a directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "e.g. *.py, *.txt"},
                    "directory": {"type": "string", "description": "Directory to search"},
                },
                "required": ["pattern", "directory"],
            },
        ),
        Tool(
            name="count_lines",
            description="Count total lines across files matching a pattern.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "e.g. *.py"},
                    "directory": {"type": "string", "description": "Directory to search"},
                },
                "required": ["pattern", "directory"],
            },
        ),
        Tool(
            name="list_directory",
            description="List the contents of a directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory to list"},
                },
                "required": ["directory"],
            },
        ),
    ]


def _run(cmd: str) -> str:
    """The vulnerable core: shell=True on a string built from user input."""
    print(f"[DEBUG] Executing: {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
    return r.stdout or r.stderr or "(no output)"


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """
    Execute tool calls from MCP clients.

    *** VULNERABILITY: builds shell commands from untrusted arguments and runs
        them with shell=True -> command injection. ***
    """
    if name == "search_files":
        pattern = arguments["pattern"]
        directory = arguments["directory"]
        cmd = f'find "{directory}" -name "{pattern}"'
        return [TextContent(type="text", text=_run(cmd))]

    if name == "count_lines":
        pattern = arguments["pattern"]
        directory = arguments["directory"]
        cmd = f'find "{directory}" -name "{pattern}" -type f -exec cat {{}} + | wc -l'
        return [TextContent(type="text", text=_run(cmd))]

    if name == "list_directory":
        directory = arguments["directory"]
        cmd = f'ls -la "{directory}"'
        return [TextContent(type="text", text=_run(cmd))]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
