import asyncio
import json
import os
import sys
import time
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from src.graph import get_graph
from src.ingest import ingest
from src.models import FindingOut, Report
from src.verify import verify_report
from src import tools
from src.llm import chat

SYSTEM = 'You audit a Solidity contract through graph tools. The summary of findings is in the first message. Steps: call entry_paths_to once for every function id listed there; call rank_findings; call submit_report once. Copy function ids and paths exactly as the tools return them. If entry_paths_to returns no paths, set reachable false and path to an empty list. Never invent findings or paths. Each explanation is 2 sentences. Keep each fix to one minimal change.'

SUBMIT_SCHEMA = FindingOut.model_json_schema()


def clean_schema(schema: dict) -> dict:
    if not isinstance(schema, dict):
        return schema
    res = {}
    for k, v in schema.items():
        if k == 'title':
            continue
        if isinstance(v, dict):
            res[k] = clean_schema(v)
        elif isinstance(v, list):
            res[k] = [clean_schema(item) if isinstance(item, dict) else item for item in v]
        else:
            res[k] = v
    return res


SUBMIT_TOOL = {
    'type': 'function',
    'function': {
        'name': 'submit_report',
        'description': 'Submit the final audit report. Call exactly once.',
        'parameters': clean_schema({
            'type': 'object',
            'properties': {
                'findings': {
                    'type': 'array',
                    'items': SUBMIT_SCHEMA,
                }
            },
            'required': ['findings'],
        }),
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


async def run_agent_async(graph_name: str, project: str, mode: str = 'guided') -> Report:
    g = get_graph(graph_name)
    params = StdioServerParameters(command=sys.executable, args=['-m', 'src.mcp_server'], env={**os.environ, 'AUDIT_GRAPH': graph_name})
    log, retries, calls_made = [], 0, 0
    final_report = None

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()

            openai_tools = []
            for t in listed.tools:
                openai_tools.append({
                    'type': 'function',
                    'function': {
                        'name': t.name,
                        'description': t.description,
                        'parameters': clean_schema(t.inputSchema) if t.inputSchema else {'type': 'object', 'properties': {}},
                    },
                })
            openai_tools.append(SUBMIT_TOOL)

            messages = [{'role': 'system', 'content': SYSTEM}]

            if mode == 'guided':
                t0 = time.time()
                r_sum = await session.call_tool('graph_summary', {})
                sum_text = r_sum.content[0].text
                log.append({'name': 'graph_summary', 'input': {}, 'output': sum_text, 'seconds': time.time() - t0})

                t0 = time.time()
                r_list = await session.call_tool('list_findings', {})
                list_text = r_list.content[0].text
                log.append({'name': 'list_findings', 'input': {}, 'output': list_text, 'seconds': time.time() - t0})

                t0 = time.time()
                r_pw = await session.call_tool('unguarded_privileged_writers', {})
                pw_text = r_pw.content[0].text
                log.append({'name': 'unguarded_privileged_writers', 'input': {}, 'output': pw_text, 'seconds': time.time() - t0})

                parsed_list = json.loads(list_text) if isinstance(list_text, str) else list_text
                parsed_pw = json.loads(pw_text) if isinstance(pw_text, str) else pw_text

                candidate_funcs = set()
                findings_summary = []
                for f in parsed_list:
                    if f.get('impact') in ('High', 'Medium') or f.get('klass') == 'P':
                        for fn in f.get('function_ids', []):
                            candidate_funcs.add(fn)
                        findings_summary.append(f"Finding id: {f.get('id')}, klass: {f.get('klass')}, check: {f.get('check')}, functions: {f.get('function_ids')}")

                for pw in parsed_pw:
                    candidate_funcs.add(pw.get('writer'))
                    findings_summary.append(f"Privileged writer: {pw.get('writer')}, var: {pw.get('var')}")

                summary_prompt = (
                    f"Audit contract {graph_name}.\n"
                    f"Discovered candidate functions to check reachability: {list(candidate_funcs)}\n"
                    f"Findings summary:\n" + "\n".join(findings_summary) + "\n\n"
                    "Now execute steps: call entry_paths_to for each function, rank_findings, attack_surface_score, then submit_report."
                )
                messages.append({'role': 'user', 'content': summary_prompt})
            else:
                messages.append({'role': 'user', 'content': f'Audit the contract in graph {graph_name}. Follow the procedure.'})

            turns = 0
            while turns < 8:
                turns += 1
                resp = chat(messages, tools=openai_tools, max_tokens=1500)
                assistant_msg = {'role': 'assistant', 'content': resp.get('content')}
                tool_calls = resp.get('tool_calls')
                if tool_calls:
                    assistant_msg['tool_calls'] = tool_calls
                messages.append(assistant_msg)

                if not tool_calls:
                    break

                for tc in tool_calls:
                    calls_made += 1
                    t0 = time.time()
                    fn_name = tc['function']['name']
                    fn_args_raw = tc['function']['arguments']
                    try:
                        fn_args = json.loads(fn_args_raw) if isinstance(fn_args_raw, str) else (fn_args_raw or {})
                    except Exception as parse_err:
                        err_res = f'Error parsing JSON arguments: {parse_err}'
                        messages.append({'role': 'tool', 'tool_call_id': tc['id'], 'content': err_res})
                        continue

                    if fn_name == 'submit_report':
                        raw_findings = fn_args.get('findings', [])
                        score_dict = tools.attack_surface_score(g)
                        rep = Report(
                            project=project,
                            attack_surface=score_dict['score'],
                            findings=[FindingOut(**f) for f in raw_findings],
                            mode=mode,
                        )
                        acc, rej = verify_report(rep, log, g)
                        if rej and retries < 1:
                            retries += 1
                            rej_reasons = [f"{r.get('finding_id')}: {r.get('reason')}" for r in rej]
                            err_msg = 'Verification failed for findings: ' + ', '.join(rej_reasons)
                            messages.append({'role': 'tool', 'tool_call_id': tc['id'], 'content': err_msg})
                        else:
                            rep.findings = acc
                            rep.rejected = rej
                            final_report = rep
                            messages.append({'role': 'tool', 'tool_call_id': tc['id'], 'content': 'Report accepted.'})
                            break
                    else:
                        r = await session.call_tool(fn_name, fn_args)
                        full_text = r.content[0].text
                        elapsed = time.time() - t0
                        log.append({'name': fn_name, 'input': fn_args, 'output': full_text, 'seconds': elapsed})
                        truncated_text = full_text[:1500]
                        messages.append({'role': 'tool', 'tool_call_id': tc['id'], 'content': truncated_text})

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


def run_agent(graph_name: str, project: str, mode: str = 'guided') -> Report:
    try:
        return asyncio.run(run_agent_async(graph_name, project, mode=mode))
    except Exception:
        g = get_graph(graph_name)
        fb = run_offline(g, project)
        fb.mode = 'fallback'
        return fb


def main():
    if len(sys.argv) < 3:
        print('Usage: python -m src.agent <sol_path> <project> [--mode guided|agent|offline]')
        sys.exit(1)
    sol_path = sys.argv[1]
    project = sys.argv[2]
    mode = 'guided'
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
        rep = run_agent(graph_name, project, mode=mode)

    Path('reports').mkdir(parents=True, exist_ok=True)
    rep_path = Path(f'reports/report_{project}.json')
    rep_path.write_text(rep.model_dump_json(indent=2), encoding='utf-8')
    print(rep.model_dump_json(indent=2))


if __name__ == '__main__':
    main()
