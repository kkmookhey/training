import asyncio
import subprocess
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# WARNING: This code uses shell=True which poses security risks.
# Only use this in controlled environments for authorized security testing.

server = Server("security-tools")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available security scanning tools."""
    return [
        types.Tool(
            name="ping",
            description="Check if a host is reachable. Sends ICMP packets to verify connectivity. Non-invasive basic check.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "The hostname or IP address to ping",
                    },
                },
                "required": ["host"],
            },
        ),
        types.Tool(
            name="nmap_scan",
            description="Perform detailed port and service scanning using Nmap. Discovers open ports and running services. More invasive than ping.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "The hostname or IP address to scan",
                    },
                },
                "required": ["host"],
            },
        ),
        types.Tool(
            name="dns_enumeration",
            description="Perform DNS enumeration using DNSRecon. Discovers DNS records, subdomains, and DNS server information for a domain.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The domain name to enumerate (e.g., example.com)",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Type of DNS scan: 'std' (standard), 'axfr' (zone transfer), 'brt' (brute force subdomains)",
                        "enum": ["std", "axfr", "brt"],
                        "default": "std"
                    },
                },
                "required": ["domain"],
            },
        ),
        types.Tool(
            name="web_security_scan",
            description="Perform web application security scanning using Wapiti. Detects vulnerabilities like XSS, SQL injection, file inclusion, etc.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The target URL to scan (must include http:// or https://)",
                    },
                    "scan_level": {
                        "type": "string",
                        "description": "Scan depth level: 'low' (faster), 'medium', or 'high' (thorough but slower)",
                        "enum": ["low", "medium", "high"],
                        "default": "medium"
                    },
                },
                "required": ["url"],
            },
        ),
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution requests."""
    
    if name == "ping":
        host = arguments.get("host")
        if not host:
            raise ValueError("Host parameter is required")
        
        try:
            # NOTE: shell=True is a security risk. For authorized testing only.
            result = subprocess.run(
                f"ping -n 4 {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout if result.returncode == 0 else result.stderr
            return [types.TextContent(type="text", text=output)]
        except subprocess.TimeoutExpired:
            return [types.TextContent(type="text", text=f"Ping to {host} timed out")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Ping failed: {str(e)}")]
    
    elif name == "nmap_scan":
        host = arguments.get("host")
        if not host:
            raise ValueError("Host parameter is required")
        
        nmap_executable = r"C:\Program Files (x86)\Nmap\nmap.exe"
        command = f'"{nmap_executable}" -sS -sV {host}'
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            output = result.stdout if result.returncode == 0 else result.stderr
            return [types.TextContent(type="text", text=output)]
        except subprocess.TimeoutExpired:
            return [types.TextContent(type="text", text=f"Nmap scan of {host} timed out")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Nmap scan failed: {str(e)}")]
    
    elif name == "dns_enumeration":
        domain = arguments.get("domain")
        scan_type = arguments.get("scan_type", "std")
        
        if not domain:
            raise ValueError("Domain parameter is required")
        
        # DNSRecon command structure
        command = f"dnsrecon -d {domain} -t {scan_type}"
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120
            )
            output = result.stdout if result.stdout else result.stderr
            return [types.TextContent(type="text", text=output)]
        except subprocess.TimeoutExpired:
            return [types.TextContent(type="text", text=f"DNS enumeration of {domain} timed out")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"DNS enumeration failed: {str(e)}")]
    
    elif name == "web_security_scan":
        url = arguments.get("url")
        scan_level = arguments.get("scan_level", "medium")
        
        if not url:
            raise ValueError("URL parameter is required")
        
        # Wapiti scan levels mapping
        level_map = {
            "low": "1",
            "medium": "2",
            "high": "3"
        }
        depth = level_map.get(scan_level, "2")
        
        # Wapiti command
        command = f"wapiti -u {url} --depth {depth} -f txt"
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=600
            )
            output = result.stdout if result.stdout else result.stderr
            return [types.TextContent(type="text", text=output)]
        except subprocess.TimeoutExpired:
            return [types.TextContent(type="text", text=f"Web security scan of {url} timed out")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Web security scan failed: {str(e)}")]
    
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    """Run the MCP server."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="security-tools",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())