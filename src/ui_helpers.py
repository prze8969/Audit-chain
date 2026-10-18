import hashlib
import json
import os
import time
from pathlib import Path
from src.agent import run_agent, run_offline
from src.graph import get_graph
from src.ingest import ingest
from src.patch import patch_with_retries

CLASS_LABELS = {
    'R': 'Reentrancy',
    'P': 'Unprotected privileged write',
    'U': 'Unchecked call',
    'OTHER': 'Other check',
}

SEVERITY_COLORS = {
    'High': '#ef4444',
    'Medium': '#f59e0b',
    'Low': '#3b82f6',
    'Informational': '#6b7280',
    'Optimization': '#10b981',
}


def compute_file_hash(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def path_to_dot(path: list[str], sink: str = '') -> str:
    Q = chr(34)
    lines = [
        'digraph G {',
        '  rankdir=LR;',
        '  bgcolor="transparent";',
        '  node [shape=box, style="rounded,filled", fontname="sans-serif", fontsize=11, fillcolor="#1e1e2e", fontcolor="#cdd6f4", color="#313244"];',
        '  edge [color="#89b4fa", fontname="sans-serif", fontsize=9, fontcolor="#a6adc8"];',
    ]
    if not path:
        lines.append('  empty [label="No Attacker Call Path", fillcolor="#313244", fontcolor="#a6adc8"];')
        lines.append('}')
        return '\n'.join(lines)

    for i, node in enumerate(path):
        if i == 0:
            lines.append(f'  {Q}{node}{Q} [label={Q}{node}\\n(Attacker Entry){Q}, fillcolor="#22c55e", fontcolor="#ffffff", style="rounded,filled", color="#16a34a", penwidth=2];')
        else:
            lines.append(f'  {Q}{node}{Q} [label={Q}{node}{Q}, fillcolor="#2d3748", fontcolor="#f87171", style="rounded,filled", color="#ef4444", penwidth=2];')

    for i in range(len(path) - 1):
        lines.append(f'  {Q}{path[i]}{Q} -> {Q}{path[i+1]}{Q} [label="CALLS", color="#ef4444", penwidth=2];')

    if sink:
        lines.append(f'  {Q}{sink}{Q} [label={Q}{sink}\\n(Privileged Var){Q}, shape=box, fillcolor="#f97316", fontcolor="#ffffff", style="filled", color="#ea580c", penwidth=2];')
        last_fn = path[-1]
        lines.append(f'  {Q}{last_fn}{Q} -> {Q}{sink}{Q} [label="WRITES", color="#f97316", style="dashed", penwidth=2];')

    lines.append('}')
    return '\n'.join(lines)


def run_audit_pipeline(source_code: str, project_name: str, mode: str, status_placeholder=None):
    if len(source_code.encode('utf-8')) > 20 * 1024:
        raise ValueError('File too large (maximum allowed size is 20 KB).')

    if 'pragma solidity 0.8.19' not in source_code and 'pragma solidity ^0.8.19' not in source_code:
        raise ValueError('Solidity compiler version mismatch: Contract pragma must be 0.8.19.')

    t0 = time.time()
    tmp_path = Path(f'tmp_audit_{project_name}_{int(time.time())}.sol')
    tmp_path.write_text(source_code, encoding='utf-8')

    try:
        if status_placeholder:
            status_placeholder.update(label='Compiling contract...', state='running')
        
        # Test db connectivity
        try:
            g_check = get_graph('audit_check')
            g_check.query('RETURN 1')
        except Exception:
            raise RuntimeError('Database unreachable: FalkorDB is not responding on localhost:6379. Make sure docker compose up -d is running.')

        if status_placeholder:
            status_placeholder.update(label='Building the code graph...', state='running')

        try:
            ingest(str(tmp_path), project_name)
        except Exception as e:
            raise RuntimeError(f'Compilation or graph ingestion failed: {e}. Please ensure pragma is 0.8.19 and code syntax is valid.')

        g = get_graph(f'audit_{project_name}')

        actual_mode = mode
        used_fallback_reason = None

        if actual_mode in ('guided', 'agent'):
            if status_placeholder:
                status_placeholder.update(label='Agent calling tools & exploring call-graph...', state='running')
            try:
                rep = run_agent(f'audit_{project_name}', project_name, mode=actual_mode)
                if rep.mode == 'fallback':
                    used_fallback_reason = 'LLM API key not configured or call timed out. Switched to deterministic offline reporter.'
            except Exception as e:
                rep = run_offline(g, project_name)
                used_fallback_reason = f'Agent encountered error: {e}. Switched to deterministic offline reporter.'
        else:
            if status_placeholder:
                status_placeholder.update(label='Running deterministic offline graph audit...', state='running')
            rep = run_offline(g, project_name)

        if status_placeholder:
            status_placeholder.update(label='Verifying every path with Verifier Gate...', state='running')

        elapsed = round(time.time() - t0, 2)
        if status_placeholder:
            status_placeholder.update(label=f'Audit complete in {elapsed}s!', state='complete')

        # Load tool trace
        trace_file = Path(f'reports/trace_{project_name}.jsonl')
        traces = []
        if trace_file.exists():
            for line in trace_file.read_text(encoding='utf-8').splitlines():
                if line.strip():
                    try:
                        traces.append(json.loads(line))
                    except Exception:
                        pass

        return {
            'report': rep,
            'traces': traces,
            'elapsed': elapsed,
            'fallback_note': used_fallback_reason,
            'source': source_code,
            'project': project_name,
        }
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def generate_markdown_report(audit_data: dict) -> str:
    rep = audit_data['report']
    lines = [
        f'# 🛡️ Audit-Chain Security Audit Report: {rep.project}',
        '**Graph-powered smart-contract audits you can trace and prove.**',
        '',
        f'**Attack Surface Score**: {rep.attack_surface} | **Mode**: {rep.mode}',
        '',
        '## Executive Summary',
        f'- Total Findings: {len(rep.findings)}',
        f'- Verified Reachable Paths: {sum(1 for f in rep.findings if f.reachable)}',
        f'- Rejected Claims: {len(rep.rejected)}',
        '',
        '## Detailed Findings',
    ]
    for idx, f in enumerate(rep.findings, 1):
        lines.append(f'### {idx}. [{f.klass}] {f.title} ({f.severity})')
        lines.append(f'**Function Affected**: `{f.function_id}`')
        lines.append(f'**Reachable by Attacker**: {"Yes" if f.reachable else "No"}')
        if f.path:
            lines.append('**Call Path**:')
            for step_num, step in enumerate(f.path, 1):
                lines.append(f'  {step_num}. `{step}`')
        lines.append(f'**Explanation**: {f.explanation}')
        lines.append(f'**Recommended Fix**: {f.recommended_fix}')
        if f.evidence_cypher:
            lines.append('```cypher')
            lines.append(f.evidence_cypher)
            lines.append('```')
        lines.append('')

    if rep.rejected:
        lines.append('## Rejected Claims (Blocked by Verifier Gate)')
        for r in rep.rejected:
            lines.append(f"- Finding `{r.get('finding_id')}` rejected: {r.get('reason')}")
        lines.append('')

    return '\n'.join(lines)


def check_health() -> dict:
    """System health check for DB, compiler, and model connectivity."""
    db_ok = False
    try:
        g = get_graph('health_check')
        g.query('RETURN 1')
        db_ok = True
    except Exception:
        db_ok = False

    compiler_ok = False
    try:
        import subprocess
        proc = subprocess.run(['solc', '--version'], capture_output=True, text=True, timeout=5)
        compiler_ok = proc.returncode == 0 and '0.8.19' in proc.stdout
    except Exception:
        compiler_ok = False

    has_key = bool(os.getenv('LLM_API_KEY') or os.getenv('GROQ_API_KEY') or os.getenv('OPENAI_API_KEY'))
    model_name = os.getenv('AGENT_MODEL', 'qwen/qwen3.8-27b')
    model_status = f'Configured ({model_name})' if has_key else 'Offline mode (deterministic graph engine)'

    return {
        'database': db_ok,
        'compiler': compiler_ok,
        'model_status': model_status,
        'all_ok': db_ok and compiler_ok,
    }
