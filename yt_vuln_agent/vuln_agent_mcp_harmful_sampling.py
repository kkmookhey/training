"""
Harmless Sampling Request Demo - MCP Server
Demonstrates: Server requesting LLM sampling (benign version)
Shows: Bidirectional communication vulnerability concept

This version uses harmless sampling requests that ask Claude to:
- Generate a creative security tip
- Write a fun poem about the task
- Provide interesting trivia

Perfect for demonstrating how servers can "talk back" to the LLM.
"""

from mcp.server import Server
from mcp.types import Tool, TextContent, SamplingMessage, TextContent as SamplingTextContent
import asyncio
import logging

# Set up file logging
logging.basicConfig(
    filename='C:\\users\\kkmookhey\\yt_vuln_agent\\sampling_debug.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)

server = Server("creative-analyzer")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="analyze_directory",
            description="Analyze a directory structure and provide insights",
            inputSchema={
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Directory path to analyze"
                    },
                    "analysis_type": {
                        "type": "string",
                        "description": "Type of analysis: basic, detailed, or creative",
                        "enum": ["basic", "detailed", "creative"]
                    }
                },
                "required": ["directory"]
            }
        ),
        Tool(
            name="create_report",
            description="Create a formatted report about system analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "report_type": {
                        "type": "string",
                        "enum": ["summary", "detailed", "creative"]
                    },
                    "topic": {
                        "type": "string",
                        "description": "What the report is about"
                    }
                },
                "required": ["report_type"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """
    Tool execution with HARMLESS sampling requests.
    
    🎭 DEMO: Shows how servers can request LLM to generate content
    This is the same mechanism that could be abused, but used benignly.
    """
    
    if name == "analyze_directory":
        directory = arguments.get("directory")
        analysis_type = arguments.get("analysis_type", "basic")
        
        # Perform actual directory analysis (safe)
        import os
        try:
            if os.path.exists(directory):
                files = os.listdir(directory)
                file_count = len(files)
                basic_info = f"Directory: {directory}\nFiles found: {file_count}\nContains: {', '.join(files[:5])}"
            else:
                basic_info = f"Directory not found: {directory}"
        except Exception as e:
            basic_info = f"Error accessing directory: {str(e)}"
        
        # HARMLESS SAMPLING REQUEST: Ask Claude to generate a creative tip
        try:
            logger.info ("Server is asking Claude a question via sampling...")
            print(f"[DEBUG] Server is asking Claude a question via sampling...")
            
            sampling_response = await server.request_sampling(
                messages=[
                    SamplingMessage(
                        role="user",
                        content=SamplingTextContent(
                            type="text",
                            text=f"""Based on the directory analysis task the user asked about, 
                            please write a SHORT creative tip about file organization or 
                            digital security (2-3 sentences max). 
                            
                            Make it fun and educational! Start with "💡 Pro Tip:"
                            
                            Keep it brief and relevant to file management."""
                        )
                    )
                ],
                maxTokens=150,
                temperature=0.7
            )
            
            # Claude just responded to the SERVER's question!
            creative_tip = sampling_response.content.text
            
            logger.info ("Claude's response to server: {creative_tip}")
            print(f"[DEBUG] Claude's response to server: {creative_tip}")
            
            # Combine analysis with the server-requested content
            result = f"{basic_info}\n\n{creative_tip}"
            
        except Exception as e:
            logger.info ("Sampling request failed: {e}")
            print(f"[DEBUG] Sampling request failed: {e}")
            result = basic_info
        
        return [TextContent(type="text", text=result)]
    
    elif name == "create_report":
        report_type = arguments.get("report_type", "summary")
        topic = arguments.get("topic", "system analysis")
        
        # ANOTHER HARMLESS SAMPLING: Ask Claude to write a poem
        try:
            logger.info ("Server requesting creative content from Claude...")
            print(f"[DEBUG] Server requesting creative content from Claude...")
            
            sampling_response = await server.request_sampling(
                messages=[
                    SamplingMessage(
                        role="user",
                        content=SamplingTextContent(
                            type="text",
                            text=f"""Please write a SHORT, fun haiku about "{topic}".
                            
                            Make it whimsical and tech-related. Just the haiku, nothing else.
                            Add a single emoji at the end."""
                        )
                    )
                ],
                maxTokens=100,
                temperature=0.8
            )
            
            poem = sampling_response.content.text
            logger.info ("Claude's poem: {poem}")
            print(f"[DEBUG] Claude's poem: {poem}")
            
            # Create report with server-generated content
            result = f"📊 {report_type.title()} Report: {topic}\n\n"
            result += f"Status: Complete\n"
            result += f"Generated: {report_type} analysis finished\n\n"
            result += f"🎭 Server's Creative Addition:\n{poem}"
            
        except Exception as e:
            logger.info ("Sampling failed: {e}")
            print(f"[DEBUG] Sampling failed: {e}")
            result = f"📊 {report_type.title()} Report: {topic}\n\nStatus: Complete"
        
        return [TextContent(type="text", text=result)]
    
    return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())