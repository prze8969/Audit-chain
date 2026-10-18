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
            short_label = f_id.split('(')[0].split('.')[-1]
            if is_entry and not guarded:
                # Green = Function / Entry
                nodes.append({
                    'id': f_id,
                    'label': short_label,
                    'title': f"<b>Function (Entry)</b>: {f_id}<br>Visibility: {vis}<br>Guarded: False",
                    'color': {'background': '#22c55e', 'border': '#16a34a', 'highlight': {'background': '#4ade80', 'border': '#22c55e'}},
                    'font': {'color': '#ffffff', 'size': 12, 'face': 'Inter, system-ui, sans-serif', 'strokeWidth': 2, 'strokeColor': '#000000'},
                    'shape': 'dot',
                    'size': 20,
                    'group': 'FunctionEntry'
                })
            elif guarded:
                # Blue = Guarded Function
                nodes.append({
                    'id': f_id,
                    'label': short_label,
                    'title': f"<b>Function (Guarded)</b>: {f_id}<br>Guarded: True",
                    'color': {'background': '#3b82f6', 'border': '#1d4ed8', 'highlight': {'background': '#60a5fa', 'border': '#2563eb'}},
                    'font': {'color': '#ffffff', 'size': 12, 'face': 'Inter, system-ui, sans-serif', 'strokeWidth': 2, 'strokeColor': '#000000'},
                    'shape': 'dot',
                    'size': 20,
                    'group': 'FunctionGuarded'
                })
            else:
                # Purple / Magenta = Internal Function (matching FalkorDB browser Function label)
                nodes.append({
                    'id': f_id,
                    'label': short_label,
                    'title': f"<b>Function (Internal)</b>: {f_id}",
                    'color': {'background': '#c084fc', 'border': '#9333ea', 'highlight': {'background': '#d8b4fe', 'border': '#a855f7'}},
                    'font': {'color': '#ffffff', 'size': 12, 'face': 'Inter, system-ui, sans-serif', 'strokeWidth': 2, 'strokeColor': '#000000'},
                    'shape': 'dot',
                    'size': 18,
                    'group': 'FunctionInternal'
                })

        # State Variables
        var_rows = g.query("MATCH (v:StateVar) RETURN v.id, v.privileged").result_set
        for row in var_rows:
            v_id, priv = row[0], row[1]
            short_var = v_id.split('.')[-1]
            if priv:
                # Orange = Privileged StateVar
                nodes.append({
                    'id': v_id,
                    'label': short_var,
                    'title': f"<b>Privileged StateVar</b>: {v_id}",
                    'color': {'background': '#f97316', 'border': '#c2410c', 'highlight': {'background': '#fb923c', 'border': '#ea580c'}},
                    'font': {'color': '#ffffff', 'size': 13, 'face': 'Inter, system-ui, sans-serif', 'strokeWidth': 2, 'strokeColor': '#000000'},
                    'shape': 'dot',
                    'size': 24,
                    'group': 'PrivilegedVar'
                })
            else:
                # Slate / Cyan = StateVar
                nodes.append({
                    'id': v_id,
                    'label': short_var,
                    'title': f"<b>StateVar</b>: {v_id}",
                    'color': {'background': '#06b6d4', 'border': '#0891b2', 'highlight': {'background': '#22d3ee', 'border': '#06b6d4'}},
                    'font': {'color': '#ffffff', 'size': 11, 'face': 'Inter, system-ui, sans-serif', 'strokeWidth': 2, 'strokeColor': '#000000'},
                    'shape': 'dot',
                    'size': 16,
                    'group': 'StateVar'
                })

        # CALLS Edges
        call_rows = g.query("MATCH (a:Function)-[r:CALLS]->(b:Function) RETURN a.id, b.id").result_set
        for row in call_rows:
            edges.append({
                'from': row[0],
                'to': row[1],
                'label': 'CALLS',
                'arrows': {'to': {'enabled': True, 'scaleFactor': 0.7}},
                'color': {'color': '#ec4899', 'highlight': '#f472b6'},
                'font': {'color': '#94a3b8', 'size': 9, 'align': 'middle'},
                'width': 1.5
            })

        # WRITES Edges
        write_rows = g.query("MATCH (a:Function)-[r:WRITES]->(b:StateVar) RETURN a.id, b.id").result_set
        for row in write_rows:
            edges.append({
                'from': row[0],
                'to': row[1],
                'label': 'WRITES',
                'arrows': {'to': {'enabled': True, 'scaleFactor': 0.7}},
                'dashes': True,
                'color': {'color': '#f97316', 'highlight': '#fb923c'},
                'font': {'color': '#fb923c', 'size': 9, 'align': 'middle'},
                'width': 2
            })

    except Exception as err:
        nodes.append({
            'id': 'error',
            'label': f"Error: {err}",
            'color': {'background': '#7f1d1d', 'border': '#ef4444'},
            'font': {'color': '#fca5a5'},
            'shape': 'dot',
            'size': 15
        })

    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)
    node_count = len(nodes)
    edge_count = len(edges)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
      <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
          background: #0d1117;
          color: #c9d1d9;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          overflow: hidden;
          font-size: 12px;
        }}
        .falkor-window {{
          width: 100%;
          height: {height}px;
          display: flex;
          flex-direction: column;
          border: 1px solid #30363d;
          border-radius: 8px;
          background: #0d1117;
          overflow: hidden;
        }}
        /* Top Navigation Header */
        .falkor-top-nav {{
          background: #161b22;
          border-bottom: 1px solid #30363d;
          padding: 6px 14px;
          display: flex;
          align-items: center;
          gap: 16px;
          font-size: 11px;
          color: #8b949e;
        }}
        .top-badge-falkor {{
          background: linear-gradient(135deg, #7928ca, #ff0080);
          color: #fff;
          font-weight: 700;
          font-size: 11px;
          padding: 2px 7px;
          border-radius: 4px;
          display: flex;
          align-items: center;
          gap: 4px;
        }}
        .top-conn {{
          display: flex;
          align-items: center;
          gap: 6px;
        }}
        .top-conn-pill {{
          background: #238636;
          color: #fff;
          padding: 1px 6px;
          border-radius: 10px;
          font-size: 10px;
          font-weight: 600;
        }}
        /* Main Workspace Split */
        .falkor-body {{
          display: flex;
          flex: 1;
          height: calc(100% - 30px);
          overflow: hidden;
        }}
        /* Left Activity Toolbar */
        .activity-bar {{
          width: 38px;
          background: #0d1117;
          border-right: 1px solid #30363d;
          display: flex;
          flex-direction: column;
          align-items: center;
          padding-top: 10px;
          gap: 16px;
          color: #8b949e;
        }}
        .activity-icon {{
          cursor: pointer;
          font-size: 14px;
          transition: color 0.15s;
        }}
        .activity-icon:hover, .activity-icon.active {{
          color: #58a6ff;
        }}
        /* Left Info / Schema Panel */
        .info-panel {{
          width: 195px;
          background: #161b22;
          border-right: 1px solid #30363d;
          padding: 10px 12px;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 12px;
          font-size: 11px;
        }}
        .panel-title {{
          font-weight: 600;
          color: #f0f6fc;
          font-size: 12px;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }}
        .db-select {{
          background: #0d1117;
          border: 1px solid #30363d;
          color: #58a6ff;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 11px;
          font-weight: 500;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }}
        .schema-section-title {{
          font-size: 10px;
          font-weight: 700;
          color: #8b949e;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          margin-bottom: 5px;
        }}
        .label-chip-group {{
          display: flex;
          flex-wrap: wrap;
          gap: 4px;
        }}
        .label-chip {{
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 2px 7px;
          border-radius: 12px;
          font-size: 10px;
          background: #21262d;
          color: #c9d1d9;
          border: 1px solid #30363d;
        }}
        .chip-dot {{
          width: 8px;
          height: 8px;
          border-radius: 50%;
        }}
        /* Right Content Area (Query Bar + Graph) */
        .graph-area {{
          flex: 1;
          display: flex;
          flex-direction: column;
          position: relative;
          background: #0d1117;
          overflow: hidden;
        }}
        /* Query Input Bar */
        .query-bar {{
          background: #161b22;
          border-bottom: 1px solid #30363d;
          padding: 8px 12px;
          display: flex;
          align-items: center;
          gap: 8px;
        }}
        .query-input-wrapper {{
          flex: 1;
          background: #0d1117;
          border: 1px solid #30363d;
          border-radius: 4px;
          display: flex;
          align-items: center;
          padding: 4px 10px;
          color: #79c0ff;
          font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
          font-size: 12px;
        }}
        .query-run-btn {{
          background: #238636;
          color: #fff;
          border: none;
          border-radius: 4px;
          padding: 5px 12px;
          font-weight: 600;
          font-size: 11px;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 4px;
        }}
        .query-run-btn:hover {{
          background: #2ea043;
        }}
        /* Canvas */
        #mynetwork {{
          flex: 1;
          width: 100%;
          height: calc(100% - 75px);
        }}
        /* Footer Status Bar */
        .falkor-footer {{
          background: #161b22;
          border-top: 1px solid #30363d;
          padding: 5px 14px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          font-size: 11px;
          color: #8b949e;
        }}
        .footer-tools {{
          display: flex;
          align-items: center;
          gap: 12px;
        }}
      </style>
    </head>
    <body>
      <div class="falkor-window">
        <!-- Top FalkorDB Navbar -->
        <div class="falkor-top-nav">
          <div class="top-badge-falkor"><i class="fa-solid fa-circle-nodes"></i> FalkorDB Browser</div>
          <div class="top-conn"><span class="top-conn-pill">CONNECTED</span> localhost:6379</div>
          <div>Memory: <b>8.87M</b></div>
          <div>Graph: <b style="color: #58a6ff;">audit_m7</b></div>
        </div>

        <div class="falkor-body">
          <!-- Activity Icons -->
          <div class="activity-bar">
            <i class="fa-solid fa-diagram-project activity-icon active" title="Graph View"></i>
            <i class="fa-solid fa-terminal activity-icon" title="Cypher Console"></i>
            <i class="fa-solid fa-database activity-icon" title="Data Browser"></i>
            <i class="fa-solid fa-gear activity-icon" title="Settings"></i>
          </div>

          <!-- Left Info & Schema Panel -->
          <div class="info-panel">
            <div class="panel-title">
              <span>Graph Info</span>
              <i class="fa-solid fa-arrows-rotate" style="color: #8b949e; cursor: pointer;"></i>
            </div>
            
            <div class="db-select">
              <span>audit_m7</span>
              <i class="fa-solid fa-chevron-down" style="font-size: 9px;"></i>
            </div>

            <div>
              <div class="schema-section-title">Nodes ({node_count})</div>
              <div class="label-chip-group">
                <span class="label-chip"><span class="chip-dot" style="background:#22c55e;"></span> Function [Entry]</span>
                <span class="label-chip"><span class="chip-dot" style="background:#c084fc;"></span> Function [Internal]</span>
                <span class="label-chip"><span class="chip-dot" style="background:#3b82f6;"></span> Function [Guarded]</span>
                <span class="label-chip"><span class="chip-dot" style="background:#f97316;"></span> StateVar [Privileged]</span>
                <span class="label-chip"><span class="chip-dot" style="background:#06b6d4;"></span> StateVar</span>
              </div>
            </div>

            <div>
              <div class="schema-section-title">Relationships ({edge_count})</div>
              <div class="label-chip-group">
                <span class="label-chip"><span class="chip-dot" style="background:#ec4899;"></span> CALLS</span>
                <span class="label-chip"><span class="chip-dot" style="background:#f97316;"></span> WRITES</span>
                <span class="label-chip"><span class="chip-dot" style="background:#a855f7;"></span> DECLARES</span>
              </div>
            </div>

            <div>
              <div class="schema-section-title">Properties</div>
              <div style="font-size: 10px; color: #8b949e; line-height: 1.5;">
                is_entry, guarded, visibility, mutability, privileged, name
              </div>
            </div>
          </div>

          <!-- Graph Workspace Area -->
          <div class="graph-area">
            <div class="query-bar">
              <i class="fa-solid fa-play" style="color: #238636; font-size: 10px;"></i>
              <div class="query-input-wrapper">
                MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN * LIMIT 100
              </div>
              <button class="query-run-btn" onclick="network.fit();"><i class="fa-solid fa-play"></i> RUN</button>
            </div>

            <div id="mynetwork"></div>

            <div class="falkor-footer">
              <div class="footer-tools">
                <span><i class="fa-solid fa-circle" style="color: #238636; font-size: 8px;"></i> Ready</span>
                <span>Nodes: <b>{node_count}</b></span>
                <span>Edges: <b>{edge_count}</b></span>
              </div>
              <div>
                <span>🖱️ Drag nodes • Scroll zoom • Click RUN to auto-fit</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <script type="text/javascript">
        var container = document.getElementById('mynetwork');
        var data = {{
          nodes: new vis.DataSet({nodes_json}),
          edges: new vis.DataSet({edges_json})
        }};
        var options = {{
          physics: {{
            enabled: true,
            solver: 'barnesHut',
            barnesHut: {{
              gravitationalConstant: -18000,
              centralGravity: 0.15,
              springLength: 200,
              springConstant: 0.04,
              damping: 0.25,
              avoidOverlap: 1
            }},
            stabilization: {{
              enabled: true,
              iterations: 200,
              fit: true
            }}
          }},
          interaction: {{
            hover: true,
            tooltipDelay: 50,
            dragNodes: true,
            dragView: true,
            zoomView: true
          }},
          nodes: {{
            borderWidth: 2,
            shadow: {{
              enabled: true,
              color: 'rgba(0,0,0,0.5)',
              size: 5,
              x: 1,
              y: 1
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
        }}, 300);
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
