"""
Vulnerable MCP Server - Resource Path Traversal (Windows) - FastMCP Version
Demonstrates: Improper URI validation allowing path traversal
MCP-Specific: Exploits Resource URI scheme
CVE-Similar: Path traversal vulnerabilities (CWE-22)

⚠️ FOR EDUCATIONAL PURPOSES ONLY
"""

from mcp.server.fastmcp import FastMCP
import logging

# Set up logging
logging.basicConfig(
    filename='C:\\users\\kkmookhey\\yt_vuln_agent\\path_traversal_debug.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastMCP server
mcp = FastMCP("workspace-resources")

# Define static resources (the legitimate ones)
@mcp.resource("file:///C:/tools/mcp_test/config.txt")
def get_config():
    """Application Configuration"""
    logger.info("Reading config.txt")
    try:
        with open("C:\\tools\\mcp_test\\config.txt", 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"

@mcp.resource("file:///C:/tools/mcp_test/assets.csv")
def get_assets():
    """Project Data"""
    logger.info("Reading assets.csv")
    try:
        with open("C:\\tools\\mcp_test\\assets.csv", 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"

@mcp.resource("file:///C:/tools/mcp_test/README.md")
def get_readme():
    """Project Documentation"""
    logger.info("Reading README.md")
    try:
        with open("C:\\tools\\mcp_test\\README.md", 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"

# THE VULNERABLE RESOURCE TEMPLATE
@mcp.resource("file:///C:/tools/mcp_test/{filepath}")
def read_workspace_file(filepath: str):
    """
    Access any file in workspace by path
    
    ⚠️ VULNERABILITY: No path validation!
    Allows path traversal via the filepath parameter
    """
    
    # Decode URL encoding (this is what makes it vulnerable!)
    import urllib.parse
    filepath = urllib.parse.unquote(filepath)
    
    # Build the full path
    full_path = f"C:\\tools\\mcp_test\\{filepath}"
    
    # Convert forward slashes to backslashes
    full_path = full_path.replace('/', '\\')
    
    logger.info(f"Resource read request for: {filepath}")
    logger.info(f"Resolved to: {full_path}")
    print(f"[DEBUG] Resource request: {filepath}")
    print(f"[DEBUG] Full path: {full_path}")
    
    # CRITICAL VULNERABILITIES:
    # ❌ No validation that path is within allowed directory
    # ❌ No check for ".." sequences (path traversal)
    # ❌ No canonicalization of paths
    
    # Check for path traversal (logging only, not blocking!)
    if ".." in filepath:
        logger.warning(f"⚠️  PATH TRAVERSAL DETECTED: {filepath}")
        print(f"[ALERT] Path traversal in: {filepath}")
    
    if not full_path.startswith("C:\\tools"):
        logger.warning(f"⚠️  ACCESS OUTSIDE WORKSPACE: {full_path}")
        print(f"[ALERT] Access outside workspace: {full_path}")
    
    # Read the file - NO SECURITY CHECKS!
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        logger.info(f"✅ Successfully read {len(content)} bytes")
        print(f"[DEBUG] Read {len(content)} bytes successfully")
        
        return content
        
    except FileNotFoundError:
        error = f"File not found: {full_path}"
        logger.error(error)
        return error
    except PermissionError:
        error = f"Permission denied: {full_path}"
        logger.error(error)
        return error
    except Exception as e:
        error = f"Error: {str(e)}"
        logger.error(error)
        return error

if __name__ == "__main__":
    logger.info("="*60)
    logger.info("VULNERABLE MCP SERVER STARTING (FastMCP)")
    logger.info("⚠️  Contains path traversal vulnerabilities")
    logger.info("⚠️  FOR EDUCATIONAL DEMONSTRATION ONLY")
    logger.info("="*60)
    
    # Run the server
    mcp.run()