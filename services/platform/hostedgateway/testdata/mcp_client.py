"""A real MCP client for the gateway's test: the official MCP Python SDK.

It connects to the URL it is given (the gateway's address for a server) with
the two credentials an agent's configuration carries, lists the tools, calls
them, and prints what it saw as one JSON object.

usage: mcp_client.py <url> <platform token> <upstream credential> <mode>
mode is "legacy" (the initialize handshake) or "auto" (the newest revision
the client and the server share).
"""

import asyncio
import json
import sys

from mcp import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

url, token, credential, mode = sys.argv[1:5]


def text_of(result) -> str:
    return " ".join(block.text for block in result.content if getattr(block, "type", "") == "text")


async def main() -> None:
    headers = {"Authorization": f"Bearer {token}", "X-Zasp-Upstream-Authorization": credential, "X-Zasp-Agent-Id": "real-mcp-client"}
    async with create_mcp_http_client(headers=headers) as http_client:
        async with Client(streamable_http_client(url, http_client=http_client), mode=mode) as client:
            tools = await client.list_tools()
            seen = {"tools": sorted(tool.name for tool in tools.tools), "calls": {}}
            for name, arguments in (
                ("lookup_customer", {"query": "the account of private.person@example.com"}),
                ("read_page", {"url": "https://example.com/page"}),
                ("run_shell", {"command": "id"}),
            ):
                try:
                    result = await client.call_tool(name, arguments)
                    seen["calls"][name] = {"is_error": bool(result.is_error), "text": text_of(result)}
                except Exception as error:  # The gateway's refusals reach the client as tool errors.
                    seen["calls"][name] = {"raised": type(error).__name__, "text": str(error)}
            print(json.dumps(seen, sort_keys=True))


asyncio.run(main())
