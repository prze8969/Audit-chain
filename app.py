import difflib
import json
import os
from pathlib import Path
import time
import streamlit as st

from src.graph import get_graph
from src.patch import patch_with_retries
from src.ui_helpers import (
    CLASS_LABELS,
    SEVERITY_COLORS,
    check_health,
    compute_file_hash,
    full_graph_to_dot,
    generate_markdown_report,
    path_to_dot,
    render_interactive_full_graph_html,
    render_interactive_path_html,
    run_audit_pipeline,
)

st.set_page_config(
    page_title='Audit-Chain | FalkorDB Smart Contract Studio',
    page_icon='🛡️',
    layout='wide',
    initial_sidebar_state='expanded',
)

# Custom CSS for Full FalkorDB Browser / Web3 Studio Look & Feel
st.markdown('''
<style>
    /* Google Fonts import */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Overall Dark Slate FalkorDB Theme */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }

    /* Top FalkorDB Global Banner */
    .falkor-global-header {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 8px 16px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1.2rem;
        font-size: 12px;
        color: #8b949e;
    }
    .falkor-logo-badge {
        background: linear-gradient(135deg, #7928ca 0%, #ff0080 100%);
        color: #ffffff;
        font-weight: 700;
        font-size: 13px;
        padding: 4px 10px;
        border-radius: 6px;
        letter-spacing: 0.03em;
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }
    .conn-status-badge {
        background: #238636;
        color: #ffffff;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
        display: inline-flex;
        align-items: center;
        gap: 5px;
    }

    /* Sidebar Styling (FalkorDB Browser Schema Explorer) */
    [data-testid="stSidebar"] {
        background-color: #161b22 !important;
        border-right: 1px solid #30363d !important;
        min-width: 320px !important;
        max-width: 360px !important;
    }
    [data-testid="stSidebar"] * {
        color: #c9d1d9 !important;
    }
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3, [data-testid="stSidebar"] h4 {
        color: #f0f6fc !important;
    }

    /* Studio Step & Metric Cards */
    .step-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 14px 18px;
        text-align: left;
        font-weight: 500;
        color: #c9d1d9;
        transition: border-color 0.2s;
    }
    .step-card:hover {
        border-color: #58a6ff;
    }
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
        text-align: center;
    }
    .metric-value {
        font-size: 1.9rem;
        font-weight: 700;
        color: #58a6ff;
        font-family: 'JetBrains Mono', monospace;
    }
    .metric-label {
        font-size: 0.8rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-top: 4px;
    }

    /* Styled Buttons */
    .stButton>button {
        background-color: #21262d;
        color: #c9d1d9;
        border: 1px solid #30363d;
        border-radius: 6px;
        font-weight: 500;
        transition: all 0.15s ease-in-out;
    }
    .stButton>button:hover {
        background-color: #30363d;
        color: #f0f6fc;
        border-color: #8b949e;
    }
    .stButton>button[kind="primary"] {
        background-color: #238636;
        color: #ffffff;
        border: 1px solid rgba(240, 246, 252, 0.1);
        font-weight: 600;
    }
    .stButton>button[kind="primary"]:hover {
        background-color: #2ea043;
    }

    /* Code Block & Terminal Styling */
    pre, code {
        font-family: 'JetBrains Mono', monospace !important;
        background-color: #0d1117 !important;
        border-color: #30363d !important;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #161b22;
        border-bottom: 1px solid #30363d;
        padding: 4px 8px;
        border-radius: 8px 8px 0 0;
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8b949e;
        font-weight: 500;
        border-radius: 6px;
        padding: 6px 14px;
    }
    .stTabs [aria-selected="true"] {
        color: #58a6ff !important;
        background-color: #21262d !important;
    }
</style>
''', unsafe_allow_html=True)

# ----------------- SESSION STATE SETUP -----------------
if 'audit_data' not in st.session_state:
    st.session_state['audit_data'] = None
if 'active_target' not in st.session_state:
    st.session_state['active_target'] = None
if 'cached_audits' not in st.session_state:
    st.session_state['cached_audits'] = {}
if 'patch_results' not in st.session_state:
    st.session_state['patch_results'] = {}
if 'audit_timestamps' not in st.session_state:
    st.session_state['audit_timestamps'] = []

# Sidebar: Controls & Audit Configuration (FalkorDB / Studio Feel)
with st.sidebar:
    st.markdown('### 🛡️ **Audit-Chain**')
    st.caption('Autonomous Graph-Powered Smart Contract Audits')
    st.divider()

    st.markdown('#### 🎯 **1. Target Contract**')
    target_mode = st.radio(
        'Select Input Method',
        ['Pre-built Mutation Variant', 'Held-out Benchmark', 'Upload Custom .sol'],
        index=0,
        label_visibility='collapsed'
    )

    chosen_code = None
    chosen_name = None
    trigger_run = False

    if target_mode == 'Pre-built Mutation Variant':
        variant_options = {
            'm7: Privileged Owner Overwrite': 'm7',
            'm3: Classical Reentrancy Attack': 'm3',
            'm2: Missing Access Control': 'm2',
            'm1: Unprotected State Write': 'm1',
            'm4: Unguarded Selfdestruct': 'm4',
            'm5: Reentrancy in Token Transfer': 'm5',
            'm6: Unchecked Low-Level Call': 'm6',
            'clean: Verified Secure Contract': 'clean',
        }
        chosen_label = st.selectbox('Choose Variant', list(variant_options.keys()), index=0)
        chosen_var = variant_options[chosen_label]
        fpath = Path(f'samples/variants/{chosen_var}.sol')
        if fpath.exists():
            chosen_code = fpath.read_text(encoding='utf-8')
            chosen_name = chosen_var

    elif target_mode == 'Held-out Benchmark':
        held_options = {
            'h1: Multi-Hop Reentrancy': 'h1',
            'h2: Complex Access Path': 'h2',
            'h3: Guarded Write Invalidation': 'h3',
            'h4: Deep Call-Chain Bypass': 'h4',
        }
        chosen_label = st.selectbox('Choose Held-out Contract', list(held_options.keys()), index=0)
        chosen_held = held_options[chosen_label]
        fpath = Path(f'samples/heldout/{chosen_held}.sol')
        if fpath.exists():
            chosen_code = fpath.read_text(encoding='utf-8')
            chosen_name = chosen_held

    else:
        uploaded_file = st.file_uploader('Upload Solidity File (.sol)', type=['sol'], help='Solidity 0.8.19 single-file contract, max 20 KB')
        if uploaded_file is not None:
            try:
                chosen_code = uploaded_file.getvalue().decode('utf-8')
                chosen_name = Path(uploaded_file.name).stem
            except Exception as e:
                st.error(f'Could not read file: {e}')

    st.markdown('#### ⚙️ **2. Agent & Audit Mode**')
    mode_choice = st.selectbox(
        'Execution Mode',
        ['guided', 'agent', 'offline'],
        index=0,
        help='guided: MCP summary with directed reachability probes; agent: autonomous open-ended tool discovery; offline: deterministic Cypher AST graph engine.'
    )

    run_audit_clicked = st.button('🚀 Run Audit Pipeline', type='primary', use_container_width=True)
    if run_audit_clicked and chosen_code:
        trigger_run = True

    st.divider()
    st.markdown('#### 🖥️ **System Health**')
    h = check_health()
    db_icon = '🟢' if h['database'] else '🔴'
    solc_icon = '🟢' if h['compiler'] else '🔴'
    st.write(f"{db_icon} **FalkorDB**: {'Online (6379)' if h['database'] else 'Unreachable'}")
    st.write(f"{solc_icon} **Compiler**: {'solc 0.8.19 ready' if h['compiler'] else 'solc missing'}")
    st.write(f"🤖 **Model Engine**: {h['model_status']}")
    st.caption('Public Demo Limits: Max 5 audits / hr per session • Max 20 KB')

# ----------------- 1. LANDING & PRESET SELECTION -----------------
# FalkorDB Browser Global Top Navbar (Matching the image)
st.markdown('''
<div class="falkor-global-header">
    <div style="display: flex; align-items: center; gap: 14px;">
        <span class="falkor-logo-badge">⚡ FalkorDB Browser v4.22.01</span>
        <span>Connections: <b>audit_m7</b></span>
        <span class="conn-status-badge">🟢 Connected</span>
        <span>User: <b>default</b></span>
        <span>Host: <code>localhost:6379</code></span>
    </div>
    <div style="display: flex; align-items: center; gap: 14px;">
        <span>Memory: <b>8.87M</b></span>
        <span>Graphs: <b>5</b></span>
    </div>
</div>
''', unsafe_allow_html=True)

st.markdown('<div class="main-title">🛡️ Audit-Chain Studio</div>', unsafe_allow_html=True)
st.markdown('<div style="font-size: 1.15rem; font-weight: 600; color: #58a6ff; margin-bottom: 0.3rem;">Autonomous Graph-Powered Smart Contract Audits & Proofs</div>', unsafe_allow_html=True)
st.markdown('<div style="color: #8b949e; margin-bottom: 1.2rem;">Select a smart contract below or configure it on the left panel. The agent analyzes the AST code graph, proves attacker reachability, and verifies automated patches in FalkorDB.</div>', unsafe_allow_html=True)

# 3 Step Explainer Cards
c1, c2, c3 = st.columns(3)
with c1:
    st.markdown('<div class="step-card"><b>1. Select or Upload</b><br><span style="font-size:0.85rem; color:#94a3b8;">Pick an attack variant or upload custom .sol</span></div>', unsafe_allow_html=True)
with c2:
    st.markdown('<div class="step-card"><b>2. Code Graph Traversal</b><br><span style="font-size:0.85rem; color:#94a3b8;">Agent traces multi-hop calls to privileged sinks</span></div>', unsafe_allow_html=True)
with c3:
    st.markdown('<div class="step-card"><b>3. Prove & Remediate</b><br><span style="font-size:0.85rem; color:#94a3b8;">1-click automated patch with proof of removal</span></div>', unsafe_allow_html=True)

st.markdown('<div style="height: 14px;"></div>', unsafe_allow_html=True)

# One-Click Quick Presets Bar
st.markdown('##### ⚡ Quick Start Presets:')
btn_col1, btn_col2, btn_col3, btn_col4 = st.columns([1.2, 1.2, 1.2, 1.4])
with btn_col1:
    if st.button('⚡ Takeover: Privileged Owner (m7)', use_container_width=True, help='Overwrites contract ownership through unguarded write'):
        fpath = Path('samples/variants/m7.sol')
        if fpath.exists():
            chosen_code = fpath.read_text(encoding='utf-8')
            chosen_name = 'm7'
            trigger_run = True
with btn_col2:
    if st.button('⚡ Bug: Reentrancy Attack (m3)', use_container_width=True, help='Drains contract funds through external call before balance update'):
        fpath = Path('samples/variants/m3.sol')
        if fpath.exists():
            chosen_code = fpath.read_text(encoding='utf-8')
            chosen_name = 'm3'
            trigger_run = True
with btn_col3:
    if st.button('🛡️ Safe: Verified Contract (clean)', use_container_width=True, help='Fully guarded contract with zero reachable vulnerabilities'):
        fpath = Path('samples/variants/clean.sol')
        if fpath.exists():
            chosen_code = fpath.read_text(encoding='utf-8')
            chosen_name = 'clean'
            trigger_run = True
with btn_col4:
    up_direct = st.file_uploader('Upload .sol directly', type=['sol'], label_visibility='collapsed', help='Upload Solidity 0.8.19 single-file contract, max 20 KB')
    if up_direct is not None:
        try:
            chosen_code = up_direct.getvalue().decode('utf-8')
            chosen_name = Path(up_direct.name).stem
            trigger_run = True
        except Exception as e:
            st.error(f'Could not read file: {e}')

# ----------------- 2. PROGRESS & AUDIT EXECUTION -----------------
if trigger_run and chosen_code:
    # Visitor rate limiter: max 5 audits per hour
    now = time.time()
    st.session_state['audit_timestamps'] = [t for t in st.session_state['audit_timestamps'] if now - t < 3600]
    
    cache_key = f"{compute_file_hash(chosen_code)}_{mode_choice}"
    is_cached = cache_key in st.session_state['cached_audits']

    if not is_cached and len(st.session_state['audit_timestamps']) >= 5:
        st.warning('⏱️ Public demo limit reached: You have run 5 audits in the last hour. Please wait a bit or test with already cached examples.')
    else:
        if not is_cached:
            st.session_state['audit_timestamps'].append(now)

        st.session_state['active_target'] = chosen_name

        if is_cached:
            st.session_state['audit_data'] = st.session_state['cached_audits'][cache_key]
            st.toast(f'Loaded cached audit for {chosen_name}!', icon='⚡')
        else:
            status_box = st.status('Starting audit pipeline...', expanded=True)
            try:
                audit_result = run_audit_pipeline(
                    source_code=chosen_code,
                    project_name=chosen_name,
                    mode=mode_choice,
                    status_placeholder=status_box,
                )
                st.session_state['audit_data'] = audit_result
                st.session_state['cached_audits'][cache_key] = audit_result
                st.session_state['patch_results'] = {}
            except Exception as err:
                status_box.update(label='Audit encountered an issue', state='error')
                st.error(f'⚠️ {err}')
                st.info('👉 Quick fix: Verify that FalkorDB is running (`docker compose up -d`) and the contract pragma is 0.8.19.')

# ----------------- 3. RESULTS DISPLAY -----------------
audit_data = st.session_state.get('audit_data')

if audit_data:
    rep = audit_data['report']
    traces = audit_data.get('traces', [])
    elapsed_time = audit_data.get('elapsed', 0.0)

    if audit_data.get('fallback_note'):
        st.warning(f"ℹ️ {audit_data['fallback_note']}")

    st.markdown('---')

    # Top Metric Summary Cards
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{rep.attack_surface}</div><div class="metric-label">Attack Surface Score</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{len(rep.findings)}</div><div class="metric-label">Reported Findings</div></div>', unsafe_allow_html=True)
    with m3:
        reachable_count = sum(1 for f in rep.findings if f.reachable)
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#22c55e;">{reachable_count}</div><div class="metric-label">Verified Paths</div></div>', unsafe_allow_html=True)
    with m4:
        rejected_count = len(rep.rejected)
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:{"#ef4444" if rejected_count else "#94a3b8"};">{rejected_count}</div><div class="metric-label">Rejected Claims</div></div>', unsafe_allow_html=True)

    st.markdown('<div style="height: 16px;"></div>', unsafe_allow_html=True)

    tab_findings, tab_graph, tab_scoreboard, tab_glossary = st.tabs([
        '🔍 Findings & Remediation',
        '🕸️ Code Knowledge Graph',
        '📊 How well does it work?',
        '📖 Security Glossary',
    ])

    with tab_findings:
        if not rep.findings:
            st.success('🎉 Zero attacker-reachable vulnerabilities found! All entry points and state updates are properly protected.')
        else:
            left_col, right_col = st.columns([1.1, 1.1])

            # Left Column: Findings List
            with left_col:
                st.subheader('Verified Vulnerabilities')
                for idx, f in enumerate(rep.findings):
                    class_name = CLASS_LABELS.get(f.klass, f.klass)
                    sev_color = SEVERITY_COLORS.get(f.severity, '#3b82f6')

                    expander_label = f"[{f.klass}] {class_name}: {f.function_id}"
                    with st.expander(expander_label, expanded=(idx == 0)):
                        st.markdown(f"<span style='background-color:{sev_color}; color:white; padding:2px 8px; border-radius:4px; font-size:0.8rem; font-weight:600;'>{f.severity.upper()}</span> &nbsp; <b>Function:</b> <code>{f.function_id}</code>", unsafe_allow_html=True)
                        st.markdown('<div style="height: 6px;"></div>', unsafe_allow_html=True)

                        st.markdown('**1. What is wrong:**')
                        st.write(f.explanation)

                        st.markdown('**2. How an attacker reaches it:**')
                        if f.reachable and f.path:
                            for step_idx, step_fn in enumerate(f.path, 1):
                                role_tag = ' *(Attacker callable entry)*' if step_idx == 1 else ''
                                st.markdown(f"{step_idx}. ` {step_fn} `{role_tag}")
                            if f.sink:
                                st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;↳ **Mutates privileged state:** ` {f.sink} `")
                        else:
                            st.write('No callable path from an unauthenticated entry point.')

                        st.markdown('**3. How to fix:**')
                        st.info(f.recommended_fix)

                        # Technical details expander
                        with st.expander('Technical Details (Cypher Evidence)', expanded=False):
                            st.code(f.evidence_cypher or 'MATCH p=(e:Function)-[:CALLS*]->(t) RETURN p', language='cypher')

                        # Fix and prove button
                        fix_key = f"fix_{idx}_{f.finding_id}"
                        if st.button('🩹 Fix this finding', key=fix_key, type='primary'):
                            with st.spinner('Synthesizing minimal patch and executing proof-of-removal in FalkorDB...'):
                                patch_tmp = Path(f'patch_source_{int(time.time())}.sol')
                                patch_tmp.write_text(audit_data['source'], encoding='utf-8')
                                try:
                                    res = patch_with_retries(audit_data['project'], str(patch_tmp), f, max_attempts=3, use_oracle=False)
                                    st.session_state['patch_results'][f.finding_id] = res
                                finally:
                                    if patch_tmp.exists():
                                        patch_tmp.unlink()

                        # Show Patch results if available
                        if f.finding_id in st.session_state['patch_results']:
                            p_res = st.session_state['patch_results'][f.finding_id]
                            st.markdown('---')
                            if p_res.get('success'):
                                st.success(f"✅ Patch Proved Successful! Attack surface dropped: {p_res['score_before']} ➔ {p_res['score_after']}")
                            else:
                                st.warning('⚠️ Patch did not completely remove the vulnerability or broke contract signatures.')

                            # Diff display
                            orig_lines = audit_data['source'].splitlines(keepends=True)
                            patched_lines = p_res.get('patched_source', '').splitlines(keepends=True)
                            diff = list(difflib.unified_diff(orig_lines, patched_lines, fromfile='Original.sol', tofile='Patched.sol'))
                            if diff:
                                st.markdown('**Patch Diff:**')
                                st.code(''.join(diff), language='diff')

            # Right Column: Path Graph of First Finding & Timeline
            with right_col:
                st.subheader('Attacker Call Path')
                first_finding = rep.findings[0]
                interactive_html = render_interactive_path_html(first_finding.path, first_finding.sink, height=280)
                st.components.v1.html(interactive_html, height=300)

                st.markdown('---')
                st.subheader('⏱️ What the agent did')
                if traces:
                    timeline_lines = []
                    for t in traces:
                        t_name = t.get('name', 'tool')
                        t_in = json.dumps(t.get('input', {}))
                        out_raw = str(t.get('output', ''))[:80] + ('...' if len(str(t.get('output', ''))) > 80 else '')
                        st.markdown(f"- **`{t_name}`**: Input `{t_in}` ➔ *{out_raw}*")
                else:
                    st.write('Graph queries evaluated directly via deterministic offline engine.')

                with st.expander('🛡️ Why you can trust this report', expanded=False):
                    st.markdown('''
Every finding in this report has undergone rigorous mathematical verification against the FalkorDB code graph.
1. The entry function must be confirmed as public or external with no access control modifier.
2. Every consecutive call must be backed by an active, directed `CALLS` edge in the graph AST.
3. The claim must be proven to reach the sink without relying on ungrounded model outputs.
''')
                    if rep.rejected:
                        st.write('**Rejected unverified claims:**')
                        for rej in rep.rejected:
                            st.markdown(f"- `{rej.get('finding_id')}` rejected: `{rej.get('reason')}`")

        # Download Report Section
        st.markdown('---')
        d_col1, d_col2 = st.columns(2)
        with d_col1:
            json_report = rep.model_dump_json(indent=2)
            st.download_button('📥 Download Report (JSON)', data=json_report, file_name=f'audit_{rep.project}.json', mime='application/json', use_container_width=True)
        with d_col2:
            md_report = generate_markdown_report(audit_data)
            st.download_button('📥 Download Report (Markdown)', data=md_report, file_name=f'audit_{rep.project}.md', mime='text/markdown', use_container_width=True)

    with tab_graph:
        st.subheader(f'🕸️ Code Knowledge Graph & Source Inspector: `{rep.project}`')
        st.caption('Explore contract source code side-by-side with its interactive FalkorDB AST graph, call paths, and state writes.')
        
        graph_col, code_col = st.columns([1.25, 0.95])
        
        with graph_col:
            st.markdown('**Interactive FalkorDB Graph Canvas** *(Drag nodes, zoom, pan)*')
            g = get_graph(f'audit_{rep.project}')
            full_interactive_html = render_interactive_full_graph_html(g, height=520)
            st.components.v1.html(full_interactive_html, height=545)

        with code_col:
            st.markdown(f'**Solidity Source Code** (`{rep.project}.sol`)')
            st.code(audit_data.get('source', '// No source available'), language='solidity', line_numbers=True)

        g_col1, g_col2 = st.columns(2)
        with g_col1:
            with st.expander('📊 Graph Legend & Node Types', expanded=False):
                st.markdown('''
- 🟢 **Green Circles**: Attacker-callable public/external entry points with no modifier guard.
- 🔵 **Blue Circles**: Guarded functions (protected by `onlyOwner` or `msg.sender` condition).
- 🟣 **Purple Circles**: Internal functions discovered via contract AST.
- 🟠 **Orange Circles**: Privileged state variables (`owner`, `admin`, `balances`).
- 🔷 **Cyan Circles**: Standard state variables.
- 🔴 **Red Arrows**: Directed `CALLS` edges between functions.
- 🟠 **Dashed Arrows**: `WRITES` edges mutating persistent storage.
''')
        with g_col2:
            with st.expander('🔍 Live FalkorDB Cypher Console', expanded=False):
                cypher_input = st.text_input('Run Cypher Query', value='MATCH (a)-[r]->(b) RETURN a.id, type(r), b.id LIMIT 25')
                if st.button('Execute Query', key='exec_cypher'):
                    try:
                        res = g.query(cypher_input).result_set
                        st.dataframe(res, use_container_width=True)
                    except Exception as q_err:
                        st.error(f'Cypher query error: {q_err}')

    with tab_scoreboard:
        st.subheader('📊 Benchmark Results & Verifier Performance')
        st.caption('Results come from a small set of generated and hand-written contracts tested across rounds.')
        sb_path = Path('reports/scoreboard.md')
        if sb_path.exists():
            st.markdown(sb_path.read_text(encoding='utf-8'))
        else:
            st.info('Scoreboard records not yet generated. Run `python -m src.evaluate --round 0` to populate.')

    with tab_glossary:
        st.subheader('📖 Smart Contract Security Glossary')
        st.markdown('''
**Reentrancy (R)**  
When an external call hands execution flow to an untrusted contract before internal balances or flags are updated. The recipient can recursively re-invoke the withdrawal function to drain contract funds.

**Access Control & Privileged Writes (P)**  
Functions that modify critical state variables (e.g. `owner`, `admin`) without requiring authorization checks like `onlyOwner`. Any external account can call these to take over contract ownership.

**Call Path**  
The exact, multi-hop sequence of function dispatches leading from an unauthenticated user transaction into a vulnerable sink. Proving this path confirms that a vulnerability is exploitable.

**Attack Surface Score**  
A weighted metric measuring reachable privileged write paths, unauthenticated low-level calls, and unguarded state mutations. A lower score signifies a safer contract.
''')

else:
    # Initial empty state prompt
    st.info('👆 Click one of the example buttons above or upload your own `.sol` file to begin an automated graph security audit.')
