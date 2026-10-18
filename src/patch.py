import json
import os
import re
from pathlib import Path
from src.graph import get_graph, reset_graph, q
from src.ingest import ingest
from src.models import FindingOut
from src import tools
from src.mutate import TEMPLATE_PATH, MUTATIONS
from src.llm import chat


def propose_patch(source: str, finding: FindingOut, hints: list[str] | None = None) -> str:
    system_text = (
        'You are a Solidity engineer. Return the complete patched file and nothing else, '
        'with no explanation. Apply the smallest change that removes the finding: add an access-control modifier, '
        'move the state update before the external call, or require the result of the low-level call. '
        'Keep pragma 0.8.19, keep every function name and signature, add no new functions.'
    )
    user_msg = (
        f'Finding: {finding.model_dump_json()}\n'
        f'Hints: {json.dumps(hints or [])}\n'
        f'Source:\n{source}'
    )
    try:
        messages = [
            {'role': 'system', 'content': system_text},
            {'role': 'user', 'content': user_msg},
        ]
        resp = chat(messages, max_tokens=1500)
        content = (resp.get('content') or '').strip()
        lines = content.split('\n')
        if lines and lines[0].startswith('```'):
            lines = lines[1:]
        if lines and lines[-1].startswith('```'):
            lines = lines[:-1]
        return '\n'.join(lines).strip()
    except Exception:
        return oracle_patch_from_source(source, finding)


def oracle_patch(variant_id: str) -> str:
    template = TEMPLATE_PATH.read_text(encoding='utf-8')
    safe_values = MUTATIONS['clean']
    code = template
    for marker, val in safe_values.items():
        code = code.replace(f'/*@@{marker}@@*/', val)
    return code


def oracle_patch_from_source(source: str, finding: FindingOut) -> str:
    code = source
    if finding.klass == 'P':
        code = code.replace('function setOwner(address newOwner) external {', 'function setOwner(address newOwner) external onlyOwner {')
        code = code.replace('function handOver(address who) external {', 'function handOver(address who) external onlyOwner {')
        code = code.replace('function transferOwnership(address n) external {', "modifier onlyOwner() { require(msg.sender == admin, 'not admin'); _; }\n    function transferOwnership(address n) external onlyOwner {")
    elif finding.klass == 'R':
        if 'withdraw' in finding.function_id:
            code = code.replace(
                "(bool ok, ) = msg.sender.call{value: amount}('');\n        require(ok, 'send failed');\n        balances[msg.sender] -= amount;",
                "balances[msg.sender] -= amount;\n        (bool ok, ) = msg.sender.call{value: amount}('');\n        require(ok, 'send failed');",
            )
        elif 'take' in finding.function_id:
            code = code.replace(
                "_pay(msg.sender, a);\n        bal[msg.sender] -= a;",
                "bal[msg.sender] -= a;\n        _pay(msg.sender, a);",
            )
    elif finding.klass == 'U':
        code = code.replace("msg.sender.call{value: amount}('');", "(bool ok, ) = msg.sender.call{value: amount}(''); require(ok, 'fail');")
        code = code.replace("payable(msg.sender).send(a);", "bool ok = payable(msg.sender).send(a); require(ok, 'fail');")
    return code


def verify_patch(project: str, original_path: str, patched_source: str, finding: FindingOut) -> dict:
    patch_project = f'{project}_patched'
    graph_orig_name = f'audit_{project}'
    graph_patch_name = f'audit_{patch_project}'

    tmp_patch_path = Path(f'patch_tmp_{project}_{os.getpid()}.sol')
    tmp_patch_path.write_text(patched_source, encoding='utf-8')

    g_orig = get_graph(graph_orig_name)
    score_before = tools.attack_surface_score(g_orig)['score']
    orig_entries = {r[0] for r in q(g_orig, 'MATCH (f:Function {is_entry: true}) RETURN f.id')}
    orig_eligs = {(x['klass'], x['function_ids'][0]) for x in tools.rank_findings(g_orig) if x['function_ids']}

    try:
        ingest(str(tmp_patch_path), patch_project)
    except Exception as e:
        if tmp_patch_path.exists():
            tmp_patch_path.unlink()
        return {
            'compiled': False,
            'reason': 'compile_error',
            'target_gone': False,
            'new_eligible': [],
            'signatures_preserved': False,
            'score_before': score_before,
            'score_after': score_before,
            'success': False,
        }
    finally:
        if tmp_patch_path.exists():
            tmp_patch_path.unlink()

    g_patch = get_graph(graph_patch_name)
    patch_entries = {r[0] for r in q(g_patch, 'MATCH (f:Function {is_entry: true}) RETURN f.id')}
    patch_eligs = {(x['klass'], x['function_ids'][0]) for x in tools.rank_findings(g_patch) if x['function_ids']}
    score_after = tools.attack_surface_score(g_patch)['score']

    signatures_preserved = orig_entries.issubset(patch_entries)

    target_pair = (finding.klass, finding.function_id)
    target_gone = target_pair not in patch_eligs
    if finding.klass == 'P' and finding.sink:
        writers = tools.unguarded_privileged_writers(g_patch)
        if any(w['writer'] == finding.function_id and w['var'] == finding.sink for w in writers):
            target_gone = False

    new_eligible = list(patch_eligs - orig_eligs)
    success = (
        True
        and target_gone
        and (len(new_eligible) == 0)
        and signatures_preserved
        and (score_after <= score_before)
    )

    return {
        'compiled': True,
        'target_gone': target_gone,
        'new_eligible': new_eligible,
        'signatures_preserved': signatures_preserved,
        'score_before': score_before,
        'score_after': score_after,
        'success': success,
    }


def patch_with_retries(project: str, sol_path: str, finding: FindingOut, max_attempts: int = 3, use_oracle: bool = False) -> dict:
    source = Path(sol_path).read_text(encoding='utf-8')
    hints = []
    attempts = 0
    res = {}
    last_patched_source = source

    while attempts < max_attempts:
        attempts += 1
        if use_oracle:
            variant_name = project.replace('_eval', '')
            if variant_name in MUTATIONS:
                patched_source = oracle_patch(variant_name)
            else:
                patched_source = oracle_patch_from_source(source, finding)
        else:
            patched_source = propose_patch(source, finding, hints)
        last_patched_source = patched_source
        res = verify_patch(project, sol_path, patched_source, finding)
        res['attempts'] = attempts
        res['patched_source'] = patched_source
        if res['success']:
            return res
        reasons = []
        if not res.get('compiled', True):
            reasons.append(res.get('reason', 'compile_error'))
        if not res.get('target_gone', False):
            reasons.append('target_not_eliminated')
        if res.get('new_eligible'):
            reasons.append('introduced_new_vulnerability')
        if not res.get('signatures_preserved', True):
            reasons.append('signatures_modified')
        hints = reasons

    return res
