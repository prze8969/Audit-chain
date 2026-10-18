import asyncio
import json
import os
import sys
import time
from pathlib import Path
import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from src.graph import get_graph
from src.ingest import ingest
from src.models import FindingOut, Report
from src.verify import verify_report
from src import tools

SYSTEM = 'You are a smart-contract security auditor. You can learn about the contract only through the provided graph tools. Procedure: 1) call graph_summary. 2) call list_findings and unguarded_privileged_writers. 3) for every finding with impact High or Medium, and for every privileged writer, call entry_paths_to on its function to test attacker reachability. 4) call rank_findings and attack_surface_score. 5) call submit_report exactly once. Rules: never state a path that no tool returned; copy function ids exactly; when entry_paths_to returns no paths set reachable to false and path to an empty list; do not report findings that no tool returned; write each explanation in 2 to 4 sentences naming every function on the path; recommended_fix must be a minimal change: add an access-control modifier, move the state update before the external call, or require the result of the call.'

SUBMIT_TOOL = {
    'name': 'submit_report',
    'description': 'Submit the final audit report. Call exactly once.',
    'input_schema': {
        'type': 'object',
        'properties': {
            'findings': {
                'type': 'array',
                'items': FindingOut.model_json_schema(),
            }
        },
        'required': ['findings'],
    },
}


def run_offline(g, project: str) -> Report:
    tool_log = []
    rf = tools.rank_findings(g)
    tool_log.append({'name': 'rank_findings', 'input': {}, 'output': json.dumps(rf)})

    score_res = tools.attack_surface_score(g)
    tool_log.append({'name': 'attack_surface_score', 'input': {}, 'output': json.dumps(score_res)})

    findings_out = []
    p_writers = tools.unguarded_privileged_writers(g)
    tool_log.append({'name': 'unguarded_privileged_writers', 'input': {}, 'output': json.dumps(p_writers)})

    p_map = {(item['writer'], item['var']): item for item in p_writers}

    for item in rf:
        fn_id = item['function_ids'][0] if item['function_ids'] else ''
        ep = tools.entry_paths_to(g, fn_id)
        tool_log.append({'name': 'entry_paths_to', 'input': {'function_id': fn_id}, 'output': json.dumps(ep)})

        path = ep['paths'][0] if ep['paths'] else []
        sink_var = ''
        evidence_cypher = ep['cypher']

        if item['klass'] == 'P':
            for w in p_writers:
                if w['writer'] == fn_id:
                    sink_var = w['var']
                    break
            fix = 'Add an access-control modifier such as onlyOwner to the entry function of the path.'
            title = 'Unguarded Privileged State Write'
        elif item['klass'] == 'R':
            fix = 'Move the state update before the external call (checks-effects-interactions) or add a reentrancy guard.'
            title = 'Reentrancy Vulnerability'
        elif item['klass'] == 'U':
            fix = 'Capture the success flag of the low-level call and require that it is true.'
            title = 'Unchecked Low-Level Call'
        else:
            fix = 'Remediate identified security issue.'
            title = item['check']

        path_str = ' -> '.join(path) if path else 'None'
        explanation = f'{title} found affecting {fn_id}. Attacker reachable call path: {path_str}. Severity is {item["impact"]}.'

        fo = FindingOut(
            finding_id=item['finding_id'],
            klass=item['klass'],
            title=title,
            severity=item['impact'],
            function_id=fn_id,
            reachable=ep['reachable'],
            path=path,
            sink=sink_var,
            evidence_cypher=evidence_cypher,
            explanation=explanation,
            recommended_fix=fix,
        )
        findings_out.append(fo)

    rep = Report(
        project=project,
        attack_surface=score_res['score'],
        findings=findings_out,
        mode='offline',
    )
    acc, rej = verify_report(rep, tool_log, g)
    rep.findings = acc
    rep.rejected = rej

    Path('reports').mkdir(parents=True, exist_ok=True)
    trace_file = Path(f'reports/trace_{project}.jsonl')
    with trace_file.open('w', encoding='utf-8') as f:
        for entry in tool_log:
            f.write(json.dumps(entry) + '\n')

    return rep


async def run_agent_async(graph_name: str, project: str) -> Report:
    g = get_graph(graph_name)
    params = StdioServerParameters(command=sys.executable, args=['-m', 'src.mcp_server'], env={**os.environ, 'AUDIT_GRAPH': graph_name})
    client = anthropic.Anthropic(timeout=60)
    log, retries, calls_made = [], 0, 0
    final_report = None

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            agent_tools = [{'name': t.name, 'description': t.description, 'input_schema': t.inputSchema} for t in listed.tools]
            agent_tools.append(SUBMIT_TOOL)
            messages = [{'role': 'user', 'content': 'Audit the contract in graph ' + graph_name + '. Follow the procedure.'}]

            while calls_made < 14:
                resp = client.messages.create(
                    model=os.getenv('AGENT_MODEL', 'claude-sonnet-5-5'),
                    max_tokens=4096,
                    temperature=0,
                    system=SYSTEM,
                    tools=agent_tools,
                    messages=messages,
                )
                messages.append({'role': 'assistant', 'content': resp.content})
                uses = [b for b in resp.content if b.type == 'tool_use']
                if not uses:
                    break
                results = []
                for b in uses:
                    calls_made += 1
                    t0 = time.time()
                    if b.name == 'submit_report':
                        raw_findings = b.input.get('findings', [])
                        score_dict = tools.attack_surface_score(g)
                        rep = Report(
                            project=project,
                            attack_surface=score_dict['score'],
                            findings=[FindingOut(**f) for f in raw_findings],
                            mode='agent',
                        )
                        acc, rej = verify_report(rep, log, g)
                        if rej and retries < 1:
                            retries += 1
                            rej_reasons = [f"{r.get('finding_id')}: {r.get('reason')}" for r in rej]
                            err_msg = 'Verification failed for findings: ' + ', '.join(rej_reasons)
                            results.append({'type': 'tool_result', 'tool_use_id': b.id, 'content': err_msg, 'is_error': True})
                        else:
                            rep.findings = acc
                            rep.rejected = rej
                            final_report = rep
                            results.append({'type': 'tool_result', 'tool_use_id': b.id, 'content': 'Report accepted and processed.'})
                            break
                    else:
                        r = await session.call_tool(b.name, b.input)
                        text = r.content[0].text
                        elapsed = time.time() - t0
                        log.append({'name': b.name, 'input': b.input, 'output': text, 'seconds': elapsed})
                        results.append({'type': 'tool_result', 'tool_use_id': b.id, 'content': text})
                messages.append({'role': 'user', 'content': results})
                if final_report:
                    break

    Path('reports').mkdir(parents=True, exist_ok=True)
    trace_file = Path(f'reports/trace_{project}.jsonl')
    with trace_file.open('w', encoding='utf-8') as f:
        for entry in log:
            f.write(json.dumps(entry) + '\n')

    if final_report:
        return final_report
    fb = run_offline(g, project)
    fb.mode = 'fallback'
    return fb


def run_agent(graph_name: str, project: str) -> Report:
    try:
        return asyncio.run(run_agent_async(graph_name, project))
    except Exception:
        g = get_graph(graph_name)
        fb = run_offline(g, project)
        fb.mode = 'fallback'
        return fb


def main():
    if len(sys.argv) < 3:
        print('Usage: python -m src.agent <sol_path> <project> [--mode offline|agent]')
        sys.exit(1)
    sol_path = sys.argv[1]
    project = sys.argv[2]
    mode = 'agent'
    if '--mode' in sys.argv:
        idx = sys.argv.index('--mode')
        if idx + 1 < len(sys.argv):
            mode = sys.argv[idx + 1]

    ingest(sol_path, project)
    graph_name = f'audit_{project}'
    g = get_graph(graph_name)

    if mode == 'offline':
        rep = run_offline(g, project)
    else:
        rep = run_agent(graph_name, project)

    Path('reports').mkdir(parents=True, exist_ok=True)
    rep_path = Path(f'reports/report_{project}.json')
    rep_path.write_text(rep.model_dump_json(indent=2), encoding='utf-8')
    print(rep.model_dump_json(indent=2))


if __name__ == '__main__':
    main()
