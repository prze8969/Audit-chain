import asyncio
import json
import os
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED_TOOLS = {
    'graph_summary',
    'list_findings',
    'entry_paths_to',
    'unguarded_privileged_writers',
    'who_writes',
    'blast_radius',
    'hotspots',
    'attack_surface_score',
    'rank_findings',
}


async def main():
    env = os.environ.copy()
    env['AUDIT_GRAPH'] = 'audit_m7'
    params = StdioServerParameters(
        command=sys.executable,
        args=['-m', 'src.mcp_server'],
        env=env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tool_list_res = await session.list_tools()
            tool_names = {t.name for t in tool_list_res.tools}
            print('Tools found:', sorted(list(tool_names)))
            assert tool_names == EXPECTED_TOOLS, f'Mismatch: {tool_names} vs {EXPECTED_TOOLS}'

            call_res = await session.call_tool('graph_summary', {})
            content_text = call_res.content[0].text
            parsed = json.loads(content_text)
            print('graph_summary output:', parsed)
            assert len(parsed.get('unguarded_entries', [])) >= 1, 'unguarded_entries should be at least 1'
            print('MCP smoke test passed successfully!')


if __name__ == '__main__':
    asyncio.run(main())
