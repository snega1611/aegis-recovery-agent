import asyncio
import sys

from langchain.mcp import MCPAdapter


async def main():
    adapter = MCPAdapter(
        {
            "logs": {
                "command": sys.executable,
                "args": ["mcp/logs_server.py"],
                "transport": "stdio",
            }
        }
    )

    tools = await adapter.list_tools()

    print("MCP tools available:")
    for tool in tools:
        print("-", tool.name)

    search_logs = next(
        tool for tool in tools
        if tool.name == "search_logs"
    )

    result = await search_logs.ainvoke(
        {"query": "HTTP"}
    )

    print("\nLOG SEARCH RESULT:")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())

if __name__ == "__main__":
    asyncio.run(main())