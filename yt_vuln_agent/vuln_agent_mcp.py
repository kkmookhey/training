"""
Vulnerable MCP Server - File Manager (Windows Version)
Demonstrates: Command injection via subprocess with shell=True
CVE-Similar to: CVE-2025-53818 (GitHub Kanban MCP)

⚠️ FOR EDUCATIONAL PURPOSES ONLY - CONTAINS INTENTIONAL VULNERABILITIES
"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import subprocess
import asyncio
import os

server = Server("file-manager")

@server.list_tools()
async def list_tools():
    """
    Expose available tools to MCP clients.
    Returns tool definitions with schemas.
    """
    return [
        Tool(
            name="search_files",
            description="Search for files by pattern in a directory",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "File pattern to search for (e.g., *.py, *.txt)"
                    },
                    "directory": {
                        "type": "string",
                        "description": "Directory path to search in"
                    }
                },
                "required": ["pattern", "directory"]
            }
        ),
        Tool(
            name="count_lines",
            description="Count total lines of code in files matching a pattern",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "File pattern (e.g., *.py)"
                    },
                    "directory": {
                        "type": "string",
                        "description": "Directory to search"
                    }
                },
                "required": ["pattern", "directory"]
            }
        ),
        Tool(
            name="list_directory",
            description="List contents of a directory (Windows)",
            inputSchema={
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Directory path to list"
                    }
                },
                "required": ["directory"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """
    Execute tool calls from MCP clients.
    
    ⚠️ VULNERABILITY: Uses subprocess with shell=True
    This allows command injection via the arguments.
    """
    
    if name == "search_files":
        pattern = arguments["pattern"]
        directory = arguments["directory"]
        
        # VULNERABLE: Building shell command with user input
        cmd = f'dir /s /b "{directory}\\{pattern}"'
        
        print(f"[DEBUG] Executing: {cmd}")
        
        # CRITICAL VULNERABILITY: shell=True with untrusted input
        result = subprocess.run(
            cmd,
            shell=True,  # ⚠️ Allows command injection
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            output = result.stdout if result.stdout else "No files found"
            return [TextContent(type="text", text=output)]
        else:
            return [TextContent(
                type="text",
                text=f"Error: {result.stderr if result.stderr else 'Command failed'}"
            )]
    
    elif name == "count_lines":
        pattern = arguments["pattern"]
        directory = arguments["directory"]
        
        # VULNERABLE: Another command injection point
        # Windows version using PowerShell
        cmd = f'powershell -Command "Get-ChildItem -Path \'{directory}\' -Filter \'{pattern}\' -Recurse | Get-Content | Measure-Object -Line"'
        
        print(f"[DEBUG] Executing: {cmd}")
        
        result = subprocess.run(
            cmd,
            shell=True,  # ⚠️ Vulnerable
            capture_output=True,
            text=True,
            timeout=10
        )
        
        return [TextContent(
            type="text",
            text=result.stdout if result.stdout else "No files found"
        )]
    
    elif name == "list_directory":
        directory = arguments["directory"]
        
        # VULNERABLE: Command injection point
        cmd = f'dir "{directory}"'
        
        print(f"[DEBUG] Executing: {cmd}")
        
        result = subprocess.run(
            cmd,
            shell=True,  # ⚠️ Vulnerable
            capture_output=True,
            text=True,
            timeout=10
        )
        
        return [TextContent(
            type="text",
            text=result.stdout if result.stdout else "Directory not found"
        )]
    
    return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    """Run the MCP server using stdio transport."""
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())