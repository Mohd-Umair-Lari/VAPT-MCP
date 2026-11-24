import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    params = StdioServerParameters(command=sys.executable, args=[str(Path(__file__).with_name("mcp_server.py"))])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("Tools exposed:", [tool.name for tool in tools.tools])
            result = await session.call_tool("vapt_scope", {})
            print("vapt_scope ->", result.content[0].text if result.content else result)


if __name__ == "__main__":
    asyncio.run(main())
