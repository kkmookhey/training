"""
M6 concept demo - a minimal MCP stdio client.

Lets you drive the demo servers WITHOUT Claude Desktop or the MCP Inspector:
it launches a server as a subprocess over stdio, lists its tools, and calls one.
This is also how the servers are verified end-to-end.

Usage:
    # command-injection server: prove a benign arg works, then inject
    python test_client.py server_cmdinjection.py list
    python test_client.py server_cmdinjection.py call list_directory directory=.
    python test_client.py server_cmdinjection.py call list_directory 'directory=. ; whoami'

    # hidden-instructions server: print the raw (poisoned) descriptions
    python test_client.py server_hidden_instructions.py list

Argument form for `call`:  toolname key=value key=value ...
"""
import sys
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run(server_script: str, action: str, rest: list[str]):
    params = StdioServerParameters(command=sys.executable, args=[server_script])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            if action == "list":
                resp = await session.list_tools()
                print(f"=== {len(resp.tools)} tool(s) advertised by {server_script} ===\n")
                for t in resp.tools:
                    print(f"# {t.name}")
                    print(t.description)
                    print("-" * 60)
                return

            if action == "call":
                tool_name = rest[0]
                args = {}
                for kv in rest[1:]:
                    key, _, value = kv.partition("=")
                    args[key] = value
                print(f"=== calling {tool_name}({args}) on {server_script} ===\n")
                result = await session.call_tool(tool_name, args)
                for item in result.content:
                    print(getattr(item, "text", item))
                return

    print("Unknown action. Use 'list' or 'call'.")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    server_script, action, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    asyncio.run(run(server_script, action, rest))


if __name__ == "__main__":
    main()
