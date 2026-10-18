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


def render_interactive_path_html(path: list[str], sink: str = '', height: int = 280) -> str:
    """Generate self-contained interactive vis-network graph for an attacker call path."""
    nodes = []
    edges = []

    if not path:
        nodes.append({
            'id': 'empty',
            'label': 'No Attacker Call Path',
            'color': {'background': '#1e293b', 'border': '#475569'},
            'font': {'color': '#94a3b8', 'face': 'Inter, system-ui, sans-serif'}
        })
    else:
        for i, node_name in enumerate(path):
            if i == 0:
                nodes.append({
                    'id': node_name,
                    'label': f"▶ {node_name}\n(Attacker Entry)",
                    'color': {'background': '#15803d', 'border': '#22c55e', 'highlight': {'background': '#16a34a', 'border': '#4ade80'}},
                    'font': {'color': '#ffffff', 'face': 'Inter, system-ui, sans-serif', 'bold': True},
                    'shape': 'box',
                    'margin': 10
                })
            else:
                nodes.append({
                    'id': node_name,
                    'label': f"{node_name}\n(Internal Hop)",
                    'color': {'background': '#1e293b', 'border': '#ef4444', 'highlight': {'background': '#334155', 'border': '#f87171'}},
                    'font': {'color': '#f87171', 'face': 'Inter, system-ui, sans-serif'},
                    'shape': 'box',
                    'margin': 10
                })

        for i in range(len(path) - 1):
            edges.append({
                'from': path[i],
                'to': path[i+1],
                'label': 'CALLS',
                'arrows': 'to',
                'color': {'color': '#ef4444', 'highlight': '#f87171'},
                'font': {'color': '#cbd5e1', 'size': 11, 'align': 'middle'},
                'width': 2.5
            })

        if sink:
            nodes.append({
                'id': sink,
                'label': f"⚠️ {sink}\n(Privileged Var)",
                'color': {'background': '#c2410c', 'border': '#ea580c', 'highlight': {'background': '#ea580c', 'border': '#fb923c'}},
                'font': {'color': '#ffffff', 'face': 'Inter, system-ui, sans-serif', 'bold': True},
                'shape': 'box',
                'margin': 10
            })
            edges.append({
                'from': path[-1],
                'to': sink,
                'label': 'WRITES',
                'arrows': 'to',
                'dashes': True,
                'color': {'color': '#f97316', 'highlight': '#fb923c'},
                'font': {'color': '#fb923c', 'size': 11, 'align': 'middle'},
                'width': 2.5
            })

    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
      <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
          background: #0b0f19;
          color: #e2e8f0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          overflow: hidden;
        }}
        #mynetwork {{
          width: 100%;
          height: {height}px;
          border: 1px solid #1e293b;
          border-radius: 8px;
          background: #080c14;
        }}
        .controls-hint {{
          position: absolute;
          bottom: 8px;
          right: 12px;
          font-size: 11px;
          color: #64748b;
          background: rgba(15, 23, 42, 0.7);
          padding: 2px 6px;
          border-radius: 4px;
          pointer-events: none;
        }}
      </style>
    </head>
    <body>
      <div id="mynetwork"></div>
      <div class="controls-hint">🖱️ Drag to pan • Scroll to zoom • Drag nodes</div>
      <script type="text/javascript">
        var container = document.getElementById('mynetwork');
        var data = {{
          nodes: new vis.DataSet({nodes_json}),
          edges: new vis.DataSet({edges_json})
        }};
        var options = {{
          layout: {{
            hierarchical: {{
              enabled: true,
              direction: 'LR',
              sortMethod: 'directed',
              levelSeparation: 180,
              nodeSpacing: 120,
              treeSpacing: 100,
              blockShifting: true,
              edgeMinimization: true,
              parentCentralization: true
            }}
          }},
          physics: {{
            hierarchicalRepulsion: {{
              centralGravity: 0.0,
              springLength: 120,
              springConstant: 0.01,
              nodeDistance: 140,
              damping: 0.09
            }},
            solver: 'hierarchicalRepulsion'
          }},
          interaction: {{
            hover: true,
            dragNodes: true,
            dragView: true,
            zoomView: true
          }},
          nodes: {{
            borderWidth: 2,
            shadow: {{
              enabled: true,
              color: 'rgba(0,0,0,0.5)',
              size: 8,
              x: 2,
              y: 2
            }}
          }},
          edges: {{
            smooth: {{
              type: 'cubicBezier',
              forceDirection: 'horizontal',
              roundness: 0.4
            }}
          }}
        }};
        var network = new vis.Network(container, data, options);
        network.once('stabilizationIterationsDone', function() {{
          network.fit({{
            animation: {{ duration: 400, easingFunction: 'easeInOutQuad' }}
          }});
        }});
        network.once('afterDrawing', function() {{
          network.fit();
        }});
        setTimeout(function() {{
          network.fit();
        }}, 150);
      </script>
    </body>
    </html>
    """


def render_interactive_full_graph_html(g, height: int = 480) -> str:
    """Generate self-contained interactive vis-network graph for the entire FalkorDB code graph."""
    nodes = []
    edges = []

    try:
        # Functions
        fn_rows = g.query("MATCH (f:Function) RETURN f.id, f.is_entry, f.guarded, f.visibility").result_set
        for row in fn_rows:
            f_id, is_entry, guarded, vis = row[0], row[1], row[2], row[3]
            if is_entry and not guarded:
                nodes.append({
                    'id': f_id,
                    'label': f"▶ {f_id}\n[Entry]",
                    'title': f"Public Entry Point: {f_id} (Unauthenticated/Unguarded)",
                    'color': {'background': '#15803d', 'border': '#22c55e', 'highlight': {'background': '#16a34a', 'border': '#4ade80'}},
                    'font': {'color': '#ffffff', 'face': 'Inter, system-ui, sans-serif'},
                    'shape': 'box',
                    'margin': 8
                })
            elif guarded:
                nodes.append({
                    'id': f_id,
                    'label': f"🛡️ {f_id}\n[Guarded]",
                    'title': f"Protected Function: {f_id} (Access controlled)",
                    'color': {'background': '#1e3a8a', 'border': '#3b82f6', 'highlight': {'background': '#2563eb', 'border': '#60a5fa'}},
                    'font': {'color': '#ffffff', 'face': 'Inter, system-ui, sans-serif'},
                    'shape': 'box',
                    'margin': 8
                })
            else:
                nodes.append({
                    'id': f_id,
                    'label': f"{f_id}\n[Internal]",
                    'title': f"Internal Function: {f_id}",
                    'color': {'background': '#1e293b', 'border': '#475569', 'highlight': {'background': '#334155', 'border': '#94a3b8'}},
                    'font': {'color': '#cbd5e1', 'face': 'Inter, system-ui, sans-serif'},
                    'shape': 'box',
                    'margin': 8
                })

        # State Variables
        var_rows = g.query("MATCH (v:StateVar) RETURN v.id, v.privileged").result_set
        for row in var_rows:
            v_id, priv = row[0], row[1]
            if priv:
                nodes.append({
                    'id': v_id,
                    'label': f"⚠️ {v_id}\n[Privileged Var]",
                    'title': f"Privileged State Variable: {v_id}",
                    'color': {'background': '#c2410c', 'border': '#ea580c', 'highlight': {'background': '#ea580c', 'border': '#fb923c'}},
                    'font': {'color': '#ffffff', 'face': 'Inter, system-ui, sans-serif'},
                    'shape': 'box',
                    'margin': 8
                })
            else:
                nodes.append({
                    'id': v_id,
                    'label': f"{v_id}\n[StateVar]",
                    'title': f"State Variable: {v_id}",
                    'color': {'background': '#0f172a', 'border': '#334155', 'highlight': {'background': '#1e293b', 'border': '#64748b'}},
                    'font': {'color': '#94a3b8', 'face': 'Inter, system-ui, sans-serif'},
                    'shape': 'box',
                    'margin': 8
                })

        # CALLS Edges
        call_rows = g.query("MATCH (a:Function)-[r:CALLS]->(b:Function) RETURN a.id, b.id").result_set
        for row in call_rows:
            edges.append({
                'from': row[0],
                'to': row[1],
                'label': 'CALLS',
                'arrows': 'to',
                'color': {'color': '#ef4444', 'highlight': '#f87171'},
                'font': {'color': '#94a3b8', 'size': 10, 'align': 'middle'},
                'width': 2
            })

        # WRITES Edges
        write_rows = g.query("MATCH (a:Function)-[r:WRITES]->(b:StateVar) RETURN a.id, b.id").result_set
        for row in write_rows:
            edges.append({
                'from': row[0],
                'to': row[1],
                'label': 'WRITES',
                'arrows': 'to',
                'dashes': True,
                'color': {'color': '#f97316', 'highlight': '#fb923c'},
                'font': {'color': '#fb923c', 'size': 10, 'align': 'middle'},
                'width': 2
            })

    except Exception as err:
        nodes.append({
            'id': 'error',
            'label': f"Error reading graph: {err}",
            'color': {'background': '#7f1d1d', 'border': '#ef4444'},
            'font': {'color': '#fca5a5'}
        })

    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
      <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
          background: #0b0f19;
          color: #e2e8f0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          overflow: hidden;
        }}
        #mynetwork {{
          width: 100%;
          height: {height}px;
          border: 1px solid #1e293b;
          border-radius: 8px;
          background: #080c14;
        }}
        .controls-hint {{
          position: absolute;
          bottom: 10px;
          right: 14px;
          font-size: 11px;
          color: #64748b;
          background: rgba(15, 23, 42, 0.75);
          padding: 3px 8px;
          border-radius: 4px;
          pointer-events: none;
        }}
      </style>
    </head>
    <body>
      <div id="mynetwork"></div>
      <div class="controls-hint">🖱️ Drag to pan • Scroll to zoom • Drag nodes freely</div>
      <script type="text/javascript">
        var container = document.getElementById('mynetwork');
        var data = {{
          nodes: new vis.DataSet({nodes_json}),
          edges: new vis.DataSet({edges_json})
        }};
        var options = {{
          physics: {{
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {{
              gravitationalConstant: -40,
              centralGravity: 0.01,
              springLength: 120,
              springConstant: 0.08,
              damping: 0.4
            }},
            stabilization: {{
              iterations: 150
            }}
          }},
          interaction: {{
            hover: true,
            tooltipDelay: 100,
            dragNodes: true,
            dragView: true,
            zoomView: true
          }},
          nodes: {{
            borderWidth: 2,
            shadow: {{
              enabled: true,
              color: 'rgba(0,0,0,0.4)',
              size: 6,
              x: 2,
              y: 2
            }}
          }},
          edges: {{
            smooth: {{
              type: 'continuous'
            }}
          }}
        }};
        var network = new vis.Network(container, data, options);
        network.once('stabilizationIterationsDone', function() {{
          network.fit({{
            animation: {{ duration: 500, easingFunction: 'easeInOutQuad' }}
          }});
        }});
        network.once('afterDrawing', function() {{
          network.fit();
        }});
        setTimeout(function() {{
          network.fit();
        }}, 200);
      </script>
    </body>
    </html>
    """


def full_graph_to_dot(g) -> str:
    """Generate Graphviz DOT representation of the entire contract call and state graph."""
    Q = chr(34)
    lines = [
        'digraph FullGraph {',
        '  rankdir=LR;',
        '  bgcolor="transparent";',
        '  node [shape=box, style="rounded,filled", fontname="sans-serif", fontsize=10];',
        '  edge [fontname="sans-serif", fontsize=9];',
    ]

    try:
        # Get all functions
        fn_rows = g.query("MATCH (f:Function) RETURN f.id, f.is_entry, f.guarded, f.visibility").result_set
        for row in fn_rows:
            f_id, is_entry, guarded, vis = row[0], row[1], row[2], row[3]
            if is_entry and not guarded:
                fill = "#22c55e" # Green = Attacker Entry
                font = "#ffffff"
                border = "#16a34a"
                lbl = f"{f_id}\\n[Public Entry]"
            elif guarded:
                fill = "#3b82f6" # Blue = Guarded
                font = "#ffffff"
                border = "#2563eb"
                lbl = f"{f_id}\\n[Guarded]"
            else:
                fill = "#334155" # Dark Slate = Internal/Helper
                font = "#f1f5f9"
                border = "#475569"
                lbl = f_id
            lines.append(f'  {Q}{f_id}{Q} [label={Q}{lbl}{Q}, fillcolor="{fill}", fontcolor="{font}", color="{border}", penwidth=1.5];')

        # Get state variables
        var_rows = g.query("MATCH (v:StateVar) RETURN v.id, v.privileged").result_set
        for row in var_rows:
            v_id, priv = row[0], row[1]
            fill = "#ea580c" if priv else "#475569" # Orange = Privileged
            lbl = f"{v_id}\\n[Privileged]" if priv else v_id
            lines.append(f'  {Q}{v_id}{Q} [label={Q}{lbl}{Q}, shape=box, fillcolor="{fill}", fontcolor="#ffffff", color="#c2410c", penwidth=2];')

        # Get calls
        call_rows = g.query("MATCH (a:Function)-[r:CALLS]->(b:Function) RETURN a.id, b.id").result_set
        for row in call_rows:
            lines.append(f'  {Q}{row[0]}{Q} -> {Q}{row[1]}{Q} [label="CALLS", color="#ef4444", penwidth=1.5];')

        # Get writes
        write_rows = g.query("MATCH (a:Function)-[r:WRITES]->(b:StateVar) RETURN a.id, b.id").result_set
        for row in write_rows:
            lines.append(f'  {Q}{row[0]}{Q} -> {Q}{row[1]}{Q} [label="WRITES", color="#f97316", style="dashed", penwidth=1.5];')

    except Exception:
        lines.append('  err [label="Graph empty or query error", fillcolor="#334155", fontcolor="#ffffff"];')

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
