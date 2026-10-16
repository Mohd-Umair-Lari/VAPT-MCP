"""Tiny MCP client to prove the VAPT server works end to end.

Run it from the project directory:

    python mcp_demo_client.py

It spawns mcp_server.py over stdio, lists the tools, and calls vapt_scope
(which needs no network). Add a vapt_detect call once your lab VM is up.
"""
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    params = StdioServerParameters(command=sys.executable, args=["mcp_server.py"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("Tools exposed:", [tool.name for tool in tools.tools])
            result = await session.call_tool("vapt_scope", {})
            print("vapt_scope ->", result.content[0].text if result.content else result)


if __name__ == "__main__":
    asyncio.run(main())
