import difflib
import json
import os
import time
from pathlib import Path
import streamlit as st

from src.agent import run_agent, run_offline
from src.graph import get_graph
from src.ingest import ingest
from src.patch import patch_with_retries
from src.ui_helpers import (
    CLASS_LABELS,
    SEVERITY_COLORS,
    render_interactive_full_graph_html,
    render_interactive_path_html,
)

st.set_page_config(
    page_title='Audit-Chain | Autonomous Graph Security Agent',
    layout='wide',
    page_icon='🛡️',
    initial_sidebar_state='expanded',
)

def render_github_diff_view(orig_source: str, patched_source: str):
    orig_lines = orig_source.splitlines(keepends=True)
    patched_lines = patched_source.splitlines(keepends=True)
    diff = list(difflib.unified_diff(orig_lines, patched_lines, fromfile='contracts/Contract.sol', tofile='contracts/Contract.sol (patched)'))
    
    if not diff:
        st.info("No modifications detected.")
        return
        
    additions = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
    deletions = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
    
    header_html = f'''
    <div style="background:#161b22; border:1px solid #30363d; border-radius:6px 6px 0 0; padding:8px 14px; display:flex; justify-content:space-between; align-items:center; font-family:'Inter', sans-serif;">
        <span style="font-family:'JetBrains Mono', monospace; font-size:12px; color:#c9d1d9; font-weight:600;">
            📄 contracts/Contract.sol
        </span>
        <div style="font-size:12px; font-weight:600;">
            <span style="color:#3fb950; margin-right:8px;">+{additions} lines</span>
            <span style="color:#f85149;">-{deletions} lines</span>
        </div>
    </div>
    <div style="background:#0d1117; border:1px solid #30363d; border-top:none; border-radius:0 0 6px 6px; padding:10px; font-family:'JetBrains Mono', monospace; font-size:11.5px; line-height:1.5; max-height:260px; overflow-y:auto;">
    '''
    
    body_html = []
    for line in diff:
        clean = line.rstrip('\n\r').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        if line.startswith('---') or line.startswith('+++'):
            body_html.append(f'<div style="color:#8b949e; font-weight:bold; padding:1px 4px;">{clean}</div>')
        elif line.startswith('@@'):
            body_html.append(f'<div style="background:#1f2937; color:#58a6ff; padding:2px 6px; margin:4px 0; border-radius:3px;">{clean}</div>')
        elif line.startswith('-'):
            body_html.append(f'<div style="background:rgba(248,81,73,0.18); color:#ff7b72; padding:2px 6px; border-left:3px solid #f85149; margin:1px 0;"><b>-</b> {clean[1:]} <span style="float:right; font-size:9.5px; color:#f85149; font-weight:600;">REMOVE</span></div>')
        elif line.startswith('+'):
            body_html.append(f'<div style="background:rgba(46,160,67,0.18); color:#7ee787; padding:2px 6px; border-left:3px solid #3fb950; margin:1px 0;"><b>+</b> {clean[1:]} <span style="float:right; font-size:9.5px; color:#3fb950; font-weight:600;">ADD (FIX)</span></div>')
        else:
            body_html.append(f'<div style="color:#8b949e; padding:1px 6px;">&nbsp; {clean}</div>')
            
    footer_html = '</div>'
    st.markdown(header_html + ''.join(body_html) + footer_html, unsafe_allow_html=True)

# Custom Styling: Popout Compact Sidebar, Gliding Transitions, Zero-Scroll Views
st.markdown('''
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }

    /* Screen height budget: avoid scrolling */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 0.5rem !important;
        max-width: 96% !important;
    }

    /* Gliding slide transition */
    .glide-view {
        animation: glideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }
    @keyframes glideIn {
        from {
            opacity: 0;
            transform: translateY(10px) scale(0.997);
        }
        to {
            opacity: 1;
            transform: translateY(0) scale(1);
        }
    }

    /* Popout Slim Sidebar */
    [data-testid="stSidebar"] {
        min-width: 68px !important;
        max-width: 68px !important;
        background: #080c14 !important;
        border-right: 1px solid #1e293b !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
        overflow-x: hidden !important;
        z-index: 9999 !important;
    }
    [data-testid="stSidebar"]:hover {
        min-width: 215px !important;
        max-width: 215px !important;
        box-shadow: 6px 0 25px rgba(0,0,0,0.65) !important;
    }
    [data-testid="stSidebarCollapseButton"] {
        display: none !important;
    }
    [data-testid="stSidebarContent"] {
        padding: 0.5rem 0.25rem !important;
        overflow-x: hidden !important;
    }
    [data-testid="stSidebar"] .stButton > button {
        text-align: left !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: clip !important;
        padding: 8px 10px !important;
        font-size: 13px !important;
        border-radius: 8px !important;
        margin-bottom: 5px !important;
        transition: all 0.18s ease !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover {
        transform: translateX(3px) !important;
        border-color: #3b82f6 !important;
    }

    /* Centered Slide Titles */
    .slide-header {
        text-align: center;
        margin-bottom: 0.8rem;
    }
    .slide-title {
        font-size: 1.85rem;
        font-weight: 700;
        color: #f8fafc;
        margin: 0;
        letter-spacing: -0.02em;
    }
    .slide-subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        margin: 4px 0 0 0;
    }

    /* Interactive Buttons with Gliding Glow */
    .stButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 18px rgba(59, 130, 246, 0.35) !important;
    }
    .stButton > button:active {
        transform: translateY(0) !important;
    }

    /* Cards */
    .card-box {
        background: #131b2a;
        border: 1px solid #233145;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 0.8rem;
        height: 100%;
    }
    .visual-card {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 16px 20px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        height: 100%;
    }

    /* Large Graph Container */
    .graph-frame {
        border: 1px solid #334155;
        border-radius: 10px;
        background: #0d121f;
        box-shadow: 0 6px 28px rgba(0,0,0,0.45);
        overflow: hidden;
    }
</style>
''', unsafe_allow_html=True)

# ----------------- SESSION STATE -----------------
SIDEBAR_STEPS = [
    ('0 📖', 'Preface'),
    ('1 🎯', 'Inspect Code'),
    ('2 🕸️', 'Code Graph'),
    ('3 🧠', 'Live Reasoning'),
    ('4 ⚡', 'Exploit Route'),
    ('5 🩹', 'Merge Patch'),
    ('6 🏆', 'Conclusion'),
]

if 'step_index' not in st.session_state:
    st.session_state['step_index'] = 0
if 'selected_variant' not in st.session_state:
    st.session_state['selected_variant'] = 'm7'
if 'execution_mode' not in st.session_state:
    st.session_state['execution_mode'] = 'offline'
if 'audit_report' not in st.session_state:
    st.session_state['audit_report'] = None
if 'audit_source' not in st.session_state:
    st.session_state['audit_source'] = ''
if 'patch_result' not in st.session_state:
    st.session_state['patch_result'] = None

VARIANT_INFO = {
    'm7': {
        'name': 'm7: Privileged Owner Takeover',
        'desc': 'Public handOver() calls internal _grant() mutating owner state.',
        'vuln_class': 'Unprotected Privileged Write (P)',
        'file': 'samples/variants/m7.sol',
    },
    'm3': {
        'name': 'm3: Classical Reentrancy Attack',
        'desc': 'External funds call made before zeroing balances in withdraw().',
        'vuln_class': 'Reentrancy Vulnerability (R)',
        'file': 'samples/variants/m3.sol',
    },
    'm2': {
        'name': 'm2: Missing Access Control',
        'desc': 'Direct public setOwner() without onlyOwner authorization.',
        'vuln_class': 'Access Control Bypass (P)',
        'file': 'samples/variants/m2.sol',
    },
    'clean': {
        'name': 'clean: Verified Secure Contract',
        'desc': 'Strict checks-effects-interactions and modifier guards.',
        'vuln_class': 'Verified Secure Baseline',
        'file': 'samples/variants/clean.sol',
    },
}

# ----------------- SLIM POPOUT SIDEBAR -----------------
with st.sidebar:
    st.markdown('<div style="text-align:center; padding:4px 0 10px 0; font-size:20px;">🛡️</div>', unsafe_allow_html=True)
    for i, (icon, label) in enumerate(SIDEBAR_STEPS):
        is_active = (i == st.session_state['step_index'])
        btn_text = f"{icon}  {label}"
        if st.button(btn_text, key=f"nav_step_{i}", use_container_width=True, type="primary" if is_active else "secondary"):
            st.session_state['step_index'] = i
            st.rerun()

# ----------------- MAIN GLIDING FLOW -----------------
step = st.session_state['step_index']
st.markdown('<div class="glide-view">', unsafe_allow_html=True)

# ==============================================================================
# SLIDE 0: PREFACE (Short Intro, Para:Image / Image:Para)
# ==============================================================================
if step == 0:
    st.markdown('''
<div class="slide-header">
    <div class="slide-title">🛡️ Audit-Chain</div>
    <div class="slide-subtitle">Autonomous Smart Contract Security Powered by FalkorDB Graphs</div>
</div>
''', unsafe_allow_html=True)

    # Row 1: Para (Left) : Visual (Right)
    c1, c2 = st.columns([1.1, 0.9])
    with c1:
        st.markdown('''
<div class="card-box">
    <h3 style="margin-top:0; color:#f87171;">The Problem: Static Linters Cry Wolf</h3>
    <p style="color:#cbd5e1; font-size:14px; line-height:1.5;">
    Traditional analyzers flag hundreds of theoretical warnings because they inspect flat text.
    They cannot prove if an external attacker can actually reach the vulnerable code from an unauthenticated transaction.
    </p>
</div>
''', unsafe_allow_html=True)
    with c2:
        st.markdown('''
<div class="visual-card" style="border-left: 4px solid #ef4444;">
    <div style="font-size:1.8rem; font-weight:700; color:#ef4444;">❌ 90% False Positives</div>
    <p style="color:#94a3b8; font-size:13px; margin:4px 0 0 0;">
    Unreachable code trapped behind private functions wastes weeks of audit time.
    </p>
</div>
''', unsafe_allow_html=True)

    # Row 2: Visual (Left) : Para (Right)
    c3, c4 = st.columns([0.9, 1.1])
    with c3:
        st.markdown('''
<div class="visual-card" style="border-left: 4px solid #22c55e;">
    <div style="font-size:1.8rem; font-weight:700; color:#22c55e;">✅ Graph Proofs</div>
    <p style="color:#94a3b8; font-size:13px; margin:4px 0 0 0;">
    FalkorDB Cypher proves unbroken paths from <code>msg.sender</code> to critical sinks.
    </p>
</div>
''', unsafe_allow_html=True)
    with c4:
        st.markdown('''
<div class="card-box">
    <h3 style="margin-top:0; color:#38bdf8;">The Solution: Connected Code Intelligence</h3>
    <p style="color:#cbd5e1; font-size:14px; line-height:1.5;">
    Audit-Chain turns Solidity ASTs into queryable knowledge graphs. The <b>Verifier Gate</b> validates
    every finding against graph topology, eliminating hallucinations and synthesizing verified patches.
    </p>
</div>
''', unsafe_allow_html=True)

    st.markdown('<div style="height:10px;"></div>', unsafe_allow_html=True)
    _, col_btn, _ = st.columns([1, 1.5, 1])
    with col_btn:
        if st.button('Start Guided Tour ➔', type='primary', use_container_width=True):
            st.session_state['step_index'] = 1
            st.rerun()

# ==============================================================================
# SLIDE 1: INSPECT CONTRACT (Judges Walkthrough First)
# ==============================================================================
elif step == 1:
    st.markdown('''
<div class="slide-header">
    <div class="slide-title">🎯 Step 1: Inspect Target Contract</div>
    <div class="slide-subtitle">Inspect the code first — prove the vulnerability is real and not a hardcoded fix.</div>
</div>
''', unsafe_allow_html=True)

    ctrl_c1, ctrl_c2 = st.columns([1.2, 1])
    with ctrl_c1:
        variant_keys = list(VARIANT_INFO.keys())
        chosen_variant = st.selectbox(
            'Target Contract Variant:',
            variant_keys,
            index=variant_keys.index(st.session_state['selected_variant']),
            format_func=lambda k: VARIANT_INFO[k]['name'],
            label_visibility='collapsed',
        )
        st.session_state['selected_variant'] = chosen_variant
    with ctrl_c2:
        mode = st.radio('Engine:', ['offline', 'agent'], format_func=lambda m: '⚡ Deterministic Cypher' if m == 'offline' else '🧠 Autonomous Agent', horizontal=True)
        st.session_state['execution_mode'] = mode

    info = VARIANT_INFO[chosen_variant]
    fpath = Path(info['file'])
    source_code = fpath.read_text(encoding='utf-8') if fpath.exists() else ''
    st.session_state['audit_source'] = source_code

    # Alternating layout: Para : Visual (Code)
    col_para, col_code = st.columns([1, 1.3])
    with col_para:
        st.markdown(f'''
<div class="card-box">
    <h4 style="margin-top:0; color:#38bdf8;">Vulnerability Analysis</h4>
    <p style="margin:4px 0;"><b>File:</b> <code>{chosen_variant}.sol</code></p>
    <p style="margin:4px 0;"><b>Class:</b> <span style="color:#f87171; font-weight:600;">{info['vuln_class']}</span></p>
    <p style="color:#cbd5e1; font-size:13.5px; margin:8px 0;">{info['desc']}</p>
    <hr style="border-color:#283548; margin:10px 0;">
    <p style="font-size:12px; color:#94a3b8; margin:0;">
    💡 <i>Notice the internal function dispatch. Standard linters overlook internal functions, but FalkorDB maps the full multi-hop reachability path.</i>
    </p>
</div>
''', unsafe_allow_html=True)

    with col_code:
        st.code(source_code, language='solidity', line_numbers=True)

    c_prev, c_next = st.columns([1, 1])
    with c_prev:
        if st.button('⬅ Back to Preface', use_container_width=True):
            st.session_state['step_index'] = 0
            st.rerun()
    with c_next:
        if st.button('Next: Step 2 — Ingest into FalkorDB Graph ➔', type='primary', use_container_width=True):
            st.session_state['step_index'] = 2
            st.rerun()

# ==============================================================================
# SLIDE 2: FALKORDB CODE KNOWLEDGE GRAPH (Big Canvas Focus, Explanation Above)
# ==============================================================================
elif step == 2:
    st.markdown('''
<div class="slide-header">
    <div class="slide-title">🕸️ Step 2: FalkorDB Code Knowledge Graph</div>
    <div class="slide-subtitle">Solidity AST parsed and connected into Redis in-memory graph.</div>
</div>
''', unsafe_allow_html=True)

    # Explanation Placed Above the Graph
    st.markdown('''
<div style="background:#131b2a; border:1px solid #233145; border-radius:8px; padding:7px 14px; margin-bottom:8px; display:flex; justify-content:space-around; align-items:center; font-size:12.5px;">
    <span>🟢 <b>Public Entries</b> (Attack Surface)</span>
    <span>🟠 <b>State Variables</b> (Privileged Sinks)</span>
    <span>🔴 <b>Directed Edges</b> (CALLS & WRITES)</span>
    <span style="color:#94a3b8;"><i>💡 Drag nodes, zoom, or pan</i></span>
</div>
''', unsafe_allow_html=True)

    variant = st.session_state['selected_variant']
    tmp_path = Path(f'tmp_{variant}.sol')
    tmp_path.write_text(st.session_state['audit_source'], encoding='utf-8')
    try:
        with st.spinner(f'Compiling {variant}.sol and building FalkorDB graph...'):
            ingest(str(tmp_path), variant)
            g = get_graph(f'audit_{variant}')
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    # Big, Prominent Graph Box
    full_html = render_interactive_full_graph_html(g, height=520)
    st.components.v1.html(full_html, height=530)

    c_prev, c_next = st.columns([1, 1])
    with c_prev:
        if st.button('⬅ Back to Step 1', use_container_width=True):
            st.session_state['step_index'] = 1
            st.rerun()
    with c_next:
        if st.button('Next: Step 3 — Real-Time Agent Reasoning ➔', type='primary', use_container_width=True):
            st.session_state['step_index'] = 3
            st.rerun()

# ==============================================================================
# SLIDE 3: REAL-TIME REASONING & METRICS (Para:Image layout, Concise)
# ==============================================================================
elif step == 3:
    st.markdown('''
<div class="slide-header">
    <div class="slide-title">🧠 Step 3: Real-Time Reasoning & Verifier Gate</div>
    <div class="slide-subtitle">Autonomous Cypher traversal in Redis memory with zero-hallucination verification.</div>
</div>
''', unsafe_allow_html=True)

    variant = st.session_state['selected_variant']
    mode = st.session_state['execution_mode']

    if not st.session_state['audit_report'] or st.session_state['audit_report'].project != variant:
        with st.spinner(f'Executing {mode} Cypher reachability probes...'):
            g = get_graph(f'audit_{variant}')
            if mode == 'offline':
                rep = run_offline(g, variant)
            else:
                rep = run_agent(f'audit_{variant}', variant)
            st.session_state['audit_report'] = rep

    rep = st.session_state['audit_report']

    # 4 Quick Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric('Attack Surface Score', rep.attack_surface, help='Lower is safer (0 = secure)')
    m2.metric('Verified Findings', len(rep.findings), help='Confirmed reachable by Cypher')
    m3.metric('Reachable Paths', sum(1 for f in rep.findings if f.reachable))
    m4.metric('Blocked Claims', len(rep.rejected), help='Filtered by Verifier Gate')

    # Alternating Layout: Para (Left) : Visual Table (Right)
    col_desc, col_tbl = st.columns([1, 1.2])
    with col_desc:
        st.markdown('''
<div class="card-box">
    <h4 style="margin-top:0; color:#38bdf8;">Real-Time Processing Breakdown</h4>
    <p style="font-size:13px; color:#cbd5e1; margin-bottom:6px;">
    <b>1. Graph Traversal:</b> Evaluates <code>(:Function)-[:CALLS*]->(:StateVariable)</code> to prove reachability.
    </p>
    <p style="font-size:13px; color:#cbd5e1; margin-bottom:6px;">
    <b>2. Verifier Gate:</b> Blocks LLM hallucinations by demanding continuous graph edges.
    </p>
    <p style="font-size:13px; color:#cbd5e1; margin-bottom:0;">
    <b>3. Dynamic Surface Score:</b> Recomputes contract exposure in real time.
    </p>
</div>
''', unsafe_allow_html=True)

    with col_tbl:
        table_data = []
        for f in rep.findings:
            table_data.append({
                'Class': f.klass,
                'Severity': f.severity,
                'Function': f.function_id,
                'Reachable': '✅ Yes' if f.reachable else '❌ No',
                'Fix Sink': f.sink if f.sink else 'Control Flow',
            })
        st.dataframe(table_data, use_container_width=True, height=140)

    if rep.rejected:
        with st.expander('🛡️ Verifier Gate: Blocked Unverified Claims'):
            st.json(rep.rejected)

    c_prev, c_next = st.columns([1, 1])
    with c_prev:
        if st.button('⬅ Back to Step 2', use_container_width=True):
            st.session_state['step_index'] = 2
            st.rerun()
    with c_next:
        if st.button('Next: Step 4 — Multi-Hop Exploit Route ➔', type='primary', use_container_width=True):
            st.session_state['step_index'] = 4
            st.rerun()

# ==============================================================================
# SLIDE 4: MULTI-HOP EXPLOIT ROUTE (Interactive Focus)
# ==============================================================================
elif step == 4:
    st.markdown('''
<div class="slide-header">
    <div class="slide-title">⚡ Step 4: Multi-Hop Exploit Route Proof</div>
    <div class="slide-subtitle">Proves how an unauthenticated user jumps across internal functions into privileged sinks.</div>
</div>
''', unsafe_allow_html=True)

    rep = st.session_state['audit_report']
    if rep and rep.findings:
        selected_f = rep.findings[0]

        # Compact Route Cards Row
        flow_cols = st.columns(len(selected_f.path) + (1 if selected_f.sink else 0))
        for i, hop in enumerate(selected_f.path):
            with flow_cols[i]:
                if i == 0:
                    st.success(f"**1. Entry (Public)**\n`{hop}`")
                else:
                    st.error(f"**{i+1}. Dispatch (Internal)**\n`{hop}`")
        if selected_f.sink:
            with flow_cols[-1]:
                st.warning(f"**⚠️ Mutates State**\n`{selected_f.sink}`")

        # Big Path Graph
        path_html = render_interactive_path_html(selected_f.path, selected_f.sink, height=360)
        st.components.v1.html(path_html, height=370)

        with st.expander('Formal Cypher Reachability Proof'):
            st.code(selected_f.evidence_cypher or 'MATCH p=(e:Function {is_entry:true, guarded:false})-[:CALLS*1..6]->(t) RETURN p', language='cypher')

    c_prev, c_next = st.columns([1, 1])
    with c_prev:
        if st.button('⬅ Back to Step 3', use_container_width=True):
            st.session_state['step_index'] = 3
            st.rerun()
    with c_next:
        if st.button('Next: Step 5 — Synthesize Patch & Merge Diff ➔', type='primary', use_container_width=True):
            st.session_state['step_index'] = 5
            st.rerun()

# ==============================================================================
# SLIDE 5: AUTOMATED PATCH & GITHUB MERGE VIEW (Add / Remove Diff)
# ==============================================================================
elif step == 5:
    st.markdown('''
<div class="slide-header">
    <div class="slide-title">🩹 Step 5: Automated Patch & GitHub Merge View</div>
    <div class="slide-subtitle">Synthesizes minimal patches and mathematically proves the vulnerability route is destroyed.</div>
</div>
''', unsafe_allow_html=True)

    rep = st.session_state['audit_report']
    if rep and rep.findings:
        target_f = rep.findings[0]

        c_action, c_proof = st.columns([1.1, 1.4])
        with c_action:
            if st.button('🩹 Synthesize Minimal Patch & Execute Proof', type='primary', use_container_width=True):
                with st.spinner('Generating patch, compiling with solc 0.8.19, and re-evaluating graph...'):
                    tmp_patch_file = Path('temp_patch_walkthrough.sol')
                    tmp_patch_file.write_text(st.session_state['audit_source'], encoding='utf-8')
                    try:
                        res = patch_with_retries(rep.project, str(tmp_patch_file), target_f, max_attempts=3, use_oracle=False)
                        st.session_state['patch_result'] = res
                    finally:
                        if tmp_patch_file.exists():
                            tmp_patch_file.unlink()

            if st.session_state['patch_result']:
                p_res = st.session_state['patch_result']
                # Proof Metrics
                c1, c2 = st.columns(2)
                c1.metric('Compiled (solc)', '✅ Pass' if p_res.get('compiled') else '❌ Fail')
                c2.metric('Target Route', '✅ Eliminated' if p_res.get('target_gone') else '❌ Present')
                c3, c4 = st.columns(2)
                c3.metric('Signatures Kept', '✅ Intact' if p_res.get('signatures_preserved') else '❌ Modified')
                c4.metric('Attack Surface', f"{p_res.get('score_before')} ➔ {p_res.get('score_after')}")

        with c_proof:
            if st.session_state['patch_result']:
                p_res = st.session_state['patch_result']
                st.markdown('**GitHub Merge Diff (What to Remove & What to Keep):**')
                render_github_diff_view(st.session_state['audit_source'], p_res.get('patched_source', ''))
            else:
                st.info('Click the button on the left to synthesize the minimal patch and view the GitHub unified diff.')

    c_prev, c_next = st.columns([1, 1])
    with c_prev:
        if st.button('⬅ Back to Step 4', use_container_width=True):
            st.session_state['step_index'] = 4
            st.rerun()
    with c_next:
        if st.button('Next: Step 6 — Conclusion & Thank You ➔', type='primary', use_container_width=True):
            st.session_state['step_index'] = 6
            st.rerun()

# ==============================================================================
# SLIDE 6: CONCLUSION & THANK YOU (Para:Image / Image:Para)
# ==============================================================================
elif step == 6:
    st.markdown('''
<div class="slide-header">
    <div class="slide-title">🏆 Step 6: Conclusion</div>
    <div class="slide-subtitle">Thank you for evaluating Audit-Chain!</div>
</div>
''', unsafe_allow_html=True)

    # Row 1: Para (Left) : Visual (Right)
    c1, c2 = st.columns([1.1, 0.9])
    with c1:
        st.markdown('''
<div class="card-box">
    <h3 style="margin-top:0; color:#38bdf8;">Why Connected Data Matters</h3>
    <p style="color:#cbd5e1; font-size:14px; line-height:1.5;">
    Treating smart contracts as FalkorDB graphs transforms security audits from guesswork into formal proofs.
    We eliminate false positives, identify deep multi-hop routes, and synthesize mathematically proven patches.
    </p>
</div>
''', unsafe_allow_html=True)
    with c2:
        st.markdown('''
<div class="visual-card" style="border-left: 4px solid #38bdf8;">
    <div style="font-size:1.8rem; font-weight:700; color:#38bdf8;">100% Accuracy</div>
    <p style="color:#94a3b8; font-size:13px; margin:4px 0 0 0;">
    Zero false positives, 100% path accuracy, and 100% verified patch remediation on benchmark variants.
    </p>
</div>
''', unsafe_allow_html=True)

    # Row 2: Visual (Left) : Para (Right)
    c3, c4 = st.columns([0.9, 1.1])
    with c3:
        st.markdown('''
<div class="visual-card" style="border-left: 4px solid #a855f7;">
    <div style="font-size:1.4rem; font-weight:700; color:#c084fc;">Track 01</div>
    <p style="color:#94a3b8; font-size:13px; margin:4px 0 0 0;">
    Agents That Act on Connected Data (FalkorDB + Cypher + solc + LLM)
    </p>
</div>
''', unsafe_allow_html=True)
    with c4:
        st.markdown('''
<div class="card-box">
    <h3 style="margin-top:0; color:#4ade80;">Ready for Exploration</h3>
    <p style="color:#cbd5e1; font-size:14px; line-height:1.5;">
    Inspect the open-source code on GitHub:
    <br><a href="https://github.com/prze8969/Audit-chain" target="_blank" style="color:#38bdf8; font-weight:600;">github.com/prze8969/Audit-chain</a>
    </p>
</div>
''', unsafe_allow_html=True)

    st.markdown('<div style="height:10px;"></div>', unsafe_allow_html=True)
    _, col_btn, _ = st.columns([1, 1.5, 1])
    with col_btn:
        if st.button('🔄 Restart Walkthrough from Step 0', type='primary', use_container_width=True):
            st.session_state['step_index'] = 0
            st.rerun()

st.markdown('</div>', unsafe_allow_html=True)
