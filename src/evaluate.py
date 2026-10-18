import argparse
import json
import time
from pathlib import Path

from src.agent import run_agent, run_offline
from src.graph import get_graph
from src.ingest import ingest
from src.patch import patch_with_retries


ROUND_CONFIGS = {
    '0': {'variants': ['clean', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7'], 'dir': 'samples/variants', 'default_mode': 'offline', 'default_patch': 'oracle'},
    '1': {'variants': ['clean', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7'], 'dir': 'samples/variants', 'default_mode': 'agent', 'default_patch': 'llm'},
    '2': {'variants': ['h1', 'h2', 'h3', 'h4'], 'dir': 'samples/heldout', 'default_mode': 'agent', 'default_patch': 'llm'},
    '3': {'variants': ['m7', 'm7', 'm7'], 'dir': 'samples/variants', 'default_mode': 'agent', 'default_patch': 'llm'},
}

GROUND_TRUTH = {
    'clean': [],
    'm1': [('P', 'Treasury.setOwner(address)', ['Treasury.setOwner(address)'])],
    'm2': [('P', 'Treasury._grant(address)', ['Treasury.handOver(address)', 'Treasury._grant(address)'])],
    'm3': [('R', 'Treasury.withdraw(uint256)', ['Treasury.withdraw(uint256)'])],
    'm4': [('U', 'Treasury.refund(uint256)', ['Treasury.refund(uint256)'])],
    'm5': [
        ('P', 'Treasury.setOwner(address)', ['Treasury.setOwner(address)']),
        ('R', 'Treasury.withdraw(uint256)', ['Treasury.withdraw(uint256)']),
    ],
    'm6': [
        ('P', 'Treasury._grant(address)', ['Treasury.handOver(address)', 'Treasury._grant(address)']),
        ('U', 'Treasury.refund(uint256)', ['Treasury.refund(uint256)']),
    ],
    'm7': [
        ('P', 'Treasury.setOwner(address)', ['Treasury.setOwner(address)']),
        ('P', 'Treasury._grant(address)', ['Treasury.handOver(address)', 'Treasury._grant(address)']),
        ('R', 'Treasury.withdraw(uint256)', ['Treasury.withdraw(uint256)']),
        ('U', 'Treasury.refund(uint256)', ['Treasury.refund(uint256)']),
    ],
    'h1': [('R', 'H1.take(uint256)', ['H1.take(uint256)'])],
    'h2': [('P', 'H2.transferOwnership(address)', ['H2.transferOwnership(address)'])],
    'h3': [('U', 'H3.refund()', ['H3.refund()'])],
    'h4': [],
}


def run_evaluation(round_num: str, mode: str | None = None, patch_mode: str | None = None) -> dict:
    cfg = ROUND_CONFIGS.get(round_num, ROUND_CONFIGS['0'])
    actual_mode = mode or cfg['default_mode']
    actual_patch = patch_mode or cfg['default_patch']
    base_dir = Path(cfg['dir'])
    variants = cfg['variants']

    total_expected = 0
    total_detected = 0
    total_accepted_eligible = 0
    total_path_ok = 0
    total_rejected = 0
    total_patch_attempts = 0
    total_patch_success = 0
    total_tool_calls = 0
    total_seconds = 0.0

    variant_details = []

    for v in variants:
        t0 = time.time()
        sol_path = base_dir / f'{v}.sol'
        project = f'{v}_eval'
        ingest(str(sol_path), project)
        g = get_graph(f'audit_{project}')

        if actual_mode == 'offline':
            rep = run_offline(g, project)
        else:
            rep = run_agent(f'audit_{project}', project)

        elapsed = time.time() - t0
        total_seconds += elapsed

        trace_file = Path(f'reports/trace_{project}.jsonl')
        tool_call_count = len(trace_file.read_text(encoding='utf-8').splitlines()) if trace_file.exists() else 0
        total_tool_calls += tool_call_count

        expected = GROUND_TRUTH.get(v, [])
        exp_set = {(item[0], item[1]) for item in expected}
        exp_paths = {(item[0], item[1]): item[2] for item in expected}

        accepted_eligible = [f for f in rep.findings if f.klass in ('R', 'P', 'U')]
        acc_set = {(f.klass, f.function_id) for f in accepted_eligible}

        detected_count = len(acc_set.intersection(exp_set))
        false_positives = len(acc_set - exp_set)
        path_correct = sum(1 for f in accepted_eligible if (f.klass, f.function_id) in exp_paths and f.path == exp_paths[(f.klass, f.function_id)])

        total_expected += len(exp_set)
        total_detected += detected_count
        total_accepted_eligible += len(accepted_eligible)
        total_path_ok += path_correct
        total_rejected += len(rep.rejected)

        p_success = True
        p_attempts = 0
        use_oracle = (actual_patch == 'oracle')
        for f in accepted_eligible:
            patch_res = patch_with_retries(project, str(sol_path), f, max_attempts=3, use_oracle=use_oracle)
            p_attempts += patch_res.get('attempts', 1)
            if not patch_res.get('success', False):
                p_success = False

        if accepted_eligible:
            if p_success:
                total_patch_success += 1
            total_patch_attempts += p_attempts

        variant_details.append({
            'variant': v,
            'detected': detected_count,
            'expected': len(exp_set),
            'false_positives': false_positives,
            'path_ok': path_correct,
            'rejected': len(rep.rejected),
            'tool_calls': tool_call_count,
            'seconds': round(elapsed, 2),
            'patch_success': p_success if accepted_eligible else None,
            'patch_attempts': p_attempts,
        })

    num_v = len(variants)
    recall = (total_detected / total_expected) if total_expected > 0 else 1.0
    precision = (total_detected / total_accepted_eligible) if total_accepted_eligible > 0 else 1.0
    path_acc = (total_path_ok / total_expected) if total_expected > 0 else 1.0
    num_buggy = sum(1 for v in variants if GROUND_TRUTH.get(v, []))
    patch_success_rate = (total_patch_success / num_buggy) if num_buggy > 0 else 1.0
    mean_tools = round(total_tool_calls / num_v, 1)
    mean_secs = round(total_seconds / num_v, 2)

    summary = {
        'round': round_num,
        'mode': actual_mode,
        'patch_mode': actual_patch,
        'recall': round(recall, 3),
        'precision': round(precision, 3),
        'path_accuracy': round(path_acc, 3),
        'patch_success_rate': round(patch_success_rate, 3),
        'mean_tool_calls': mean_tools,
        'mean_seconds': mean_secs,
        'variants': variant_details,
    }

    Path('reports').mkdir(parents=True, exist_ok=True)
    round_path = Path(f'reports/round_{round_num}.json')
    round_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')

    scoreboard_path = Path('reports/scoreboard.md')
    if not scoreboard_path.exists():
        scoreboard_path.write_text(
            '# Audit-Chain Evaluation Scoreboard\n\n'
            '| Round | Mode | Patch Engine | Recall | Precision | Path Accuracy | Patch Success | Mean Tools | Mean Seconds |\n'
            '|---|---|---|---|---|---|---|---|---|\n',
            encoding='utf-8',
        )

    row = f'| Round {round_num} | {actual_mode} | {actual_patch} | {recall:.2f} | {precision:.2f} | {path_acc:.2f} | {patch_success_rate:.2f} | {mean_tools} | {mean_secs}s |\n'
    with scoreboard_path.open('a', encoding='utf-8') as f:
        f.write(row)

    print(f'Round {round_num} Evaluation Finished:')
    print(json.dumps(summary, indent=2))
    return summary


def main():
    parser = argparse.ArgumentParser(description='Evaluate Graph-Audit agent and harness')
    parser.add_argument('--round', default='0', help='Round number (0, 1, 2, 3)')
    parser.add_argument('--mode', choices=['offline', 'agent'], default=None, help='Audit mode')
    parser.add_argument('--patch', choices=['oracle', 'llm'], default=None, help='Patch mode')
    args = parser.parse_args()

    run_evaluation(args.round, args.mode, args.patch)


if __name__ == '__main__':
    main()
