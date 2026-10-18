import json
import os
from mcp.server.fastmcp import FastMCP
from src import tools
from src.graph import get_graph

mcp = FastMCP('audit-chain')


def G():
    return get_graph(os.environ['AUDIT_GRAPH'])


@mcp.tool()
def graph_summary() -> str:
    '''Overview of the audited contract graph: counts and privileged state variables. Call this first.'''
    return json.dumps(tools.graph_summary(G()))


@mcp.tool()
def list_findings(klass: str | None = None) -> str:
    '''List detector and graph findings, optionally filtered by class R, P, U or OTHER.'''
    return json.dumps(tools.list_findings(G(), klass))


@mcp.tool()
def entry_paths_to(function_id: str, max_hops: int = 6) -> str:
    '''Find up to 3 shortest call paths from an attacker-callable function (public or external, no access control) to function_id. Use it to test whether a finding is reachable by an attacker.'''
    return json.dumps(tools.entry_paths_to(G(), function_id, max_hops))


@mcp.tool()
def unguarded_privileged_writers() -> str:
    '''Find paths from attacker-callable functions to functions that write privileged state such as owner or admin.'''
    return json.dumps(tools.unguarded_privileged_writers(G()))


@mcp.tool()
def who_writes(var_id: str) -> str:
    '''List every function that writes a given state variable id and whether it is access controlled.'''
    return json.dumps(tools.who_writes(G(), var_id))


@mcp.tool()
def blast_radius(function_id: str, max_hops: int = 6) -> str:
    '''List the state variables written and external targets reachable downstream of a function.'''
    return json.dumps(tools.blast_radius(G(), function_id, max_hops))


@mcp.tool()
def hotspots(top_n: int = 5) -> str:
    '''Rank functions by PageRank on the call graph to find central functions.'''
    return json.dumps(tools.hotspots(G(), top_n))


@mcp.tool()
def attack_surface_score() -> str:
    '''Compute a numeric attack surface score; lower is better.'''
    return json.dumps(tools.attack_surface_score(G()))


@mcp.tool()
def rank_findings() -> str:
    '''Rank report-eligible findings by impact, attacker reachability, confidence and centrality.'''
    return json.dumps(tools.rank_findings(G()))


if os.environ.get('MEMORY') == '1':
    from src import memory

    @mcp.tool()
    def recall_fixes(klass: str, top_n: int = 3) -> str:
        '''Recall past successful patches and fixes for a vulnerability class from the memory graph.'''
        return json.dumps(memory.recall_fixes(klass, top_n))


if __name__ == '__main__':
    mcp.run(transport='stdio')
