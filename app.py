import difflib
import json
from pathlib import Path
import streamlit as st

from src.agent import run_agent, run_offline
from src.graph import get_graph
from src.ingest import ingest
from src.patch import patch_with_retries
from src.ui_helpers import (
    render_interactive_full_graph_html,
    render_interactive_path_html,
)


def path_to_dot(path: list[str], sink: str = '') -> str:
    Q = chr(34)
    lines = [
        'digraph G {',
        '  rankdir=LR;',
        '  node [shape=box, style="rounded,filled", fontname="Courier", fontsize=11, fillcolor="#1e1e2e", fontcolor="#cdd6f4", color="#313244"];',
        '  edge [color="#89b4fa", fontname="Courier", fontsize=9, fontcolor="#a6adc8"];',
    ]
    if not path:
        lines.append('  empty [label="No Attacker Call Path", fillcolor="#313244", fontcolor="#a6adc8"];')
        lines.append('}')
        return '\n'.join(lines)

    for i, node in enumerate(path):
        if i == 0:
            lines.append(f'  {Q}{node}{Q} [label={Q}{node}\\n(Attacker Entry){Q}, fillcolor="#a6e3a1", fontcolor="#11111b", style="rounded,filled", color="#94e2d5", penwidth=2];')
        else:
            lines.append(f'  {Q}{node}{Q} [label={Q}{node}{Q}, fillcolor="#313244", fontcolor="#f38ba8", style="rounded,filled", color="#f38ba8", penwidth=2];')

    for i in range(len(path) - 1):
        lines.append(f'  {Q}{path[i]}{Q} -> {Q}{path[i+1]}{Q} [label="CALLS", color="#f38ba8", penwidth=2];')

    if sink:
        lines.append(f'  {Q}{sink}{Q} [label={Q}{sink}\\n(Privileged Var){Q}, shape=box, fillcolor="#fab387", fontcolor="#11111b", style="filled", color="#f9e2af", penwidth=2];')
        last_fn = path[-1]
        lines.append(f'  {Q}{last_fn}{Q} -> {Q}{sink}{Q} [label="WRITES", color="#fab387", style="dashed", penwidth=2];')

    lines.append('}')
    return '\n'.join(lines)


st.set_page_config(page_title='Audit-Chain | Autonomous Graph Security Agent', layout='wide', page_icon='🛡️')

st.title('🛡️ Audit-Chain: Autonomous Graph Security Agent')
st.caption('Multi-Hop Attacker Reachability Prover, Verifier Gate & Automated Remediation Patcher powered by FalkorDB & MCP')

st.sidebar.markdown('### ⚙️ **Audit Configuration**')
st.sidebar.caption('Configure target smart contract & audit mode:')

st.sidebar.markdown('#### 🎯 **Step 1: Pick Contract**')
sample_type = st.sidebar.selectbox(
    'Target Source',
    ['Variant (samples/variants)', 'Held-out (samples/heldout)', 'Custom Upload'],
    help='Choose an existing vulnerability variant or upload your own single-file Solidity contract.'
)

sol_source = None
target_name = 'custom'

VARIANT_DESCRIPTIONS = {
    'm7': 'm7 — Privileged Owner Overwrite (Multi-hop exploit)',
    'm3': 'm3 — Classical Reentrancy (State updated after call)',
    'm2': 'm2 — Missing Access Control (Direct unguarded write)',
    'm1': 'm1 — Unprotected State Mutation',
    'm4': 'm4 — Unguarded Selfdestruct',
    'm5': 'm5 — Reentrancy in Token Transfer',
    'm6': 'm6 — Unchecked Low-Level Call',
    'clean': 'clean — Verified Secure Contract (No bugs)',
}

HELDOUT_DESCRIPTIONS = {
    'h1': 'h1 — Multi-Hop Reentrancy Benchmark',
    'h2': 'h2 — Complex Access Path Benchmark',
    'h3': 'h3 — Guarded Write Invalidation Benchmark',
    'h4': 'h4 — Deep Call-Chain Bypass Benchmark',
}

if sample_type == 'Variant (samples/variants)':
    chosen_var = st.sidebar.selectbox(
        'Choose Variant',
        list(VARIANT_DESCRIPTIONS.keys()),
        index=7,
        format_func=lambda k: VARIANT_DESCRIPTIONS[k],
        help='Select a contract variant to analyze.'
    )
    target_name = chosen_var
    sol_file = Path(f'samples/variants/{chosen_var}.sol')
    if sol_file.exists():
        sol_source = sol_file.read_text(encoding='utf-8')

elif sample_type == 'Held-out (samples/heldout)':
    chosen_held = st.sidebar.selectbox(
        'Choose Held-out Contract',
        list(HELDOUT_DESCRIPTIONS.keys()),
        index=0,
        format_func=lambda k: HELDOUT_DESCRIPTIONS[k],
        help='Held-out test contracts evaluated across benchmark rounds.'
    )
    target_name = chosen_held
    sol_file = Path(f'samples/heldout/{chosen_held}.sol')
    if sol_file.exists():
        sol_source = sol_file.read_text(encoding='utf-8')
else:
    uploaded = st.sidebar.file_uploader('Upload Solidity File (.sol)', type=['sol'], help='Max 20 KB, pragma 0.8.19')
    if uploaded:
        sol_source = uploaded.getvalue().decode('utf-8')
        target_name = Path(uploaded.name).stem

st.sidebar.markdown('#### 🤖 **Step 2: Execution Mode**')
mode_choice = st.sidebar.radio(
    'Execution Engine',
    ['offline', 'agent'],
    format_func=lambda m: '⚡ Deterministic Offline (Fast Cypher Engine)' if m == 'offline' else '🧠 Autonomous Agent (OpenAI/Qwen + FastMCP)',
    help='Offline performs instant deterministic graph reachability analysis; Agent runs autonomous multi-tool MCP investigation.'
)

st.sidebar.markdown('#### 🚀 **Step 3: Run Audit**')
run_btn = st.sidebar.button('🚀 Run Audit Pipeline', type='primary', use_container_width=True)

st.sidebar.divider()
st.sidebar.markdown('##### 🖥️ **System Status**')
st.sidebar.markdown('🟢 **Database**: FalkorDB (Port 6379)')
st.sidebar.markdown('🟢 **Compiler**: solc 0.8.19')
st.sidebar.caption('FalkorDB Browser: `http://localhost:3000`')

if 'report' not in st.session_state:
    st.session_state['report'] = None
if 'current_source' not in st.session_state:
    st.session_state['current_source'] = ''
if 'current_project' not in st.session_state:
    st.session_state['current_project'] = ''

if run_btn and sol_source:
    with st.spinner('Ingesting contract into FalkorDB call-graph & running multi-hop analysis...'):
        tmp_run_path = Path(f'tmp_run_{target_name}.sol')
        tmp_run_path.write_text(sol_source, encoding='utf-8')
        try:
            ingest(str(tmp_run_path), target_name)
            g = get_graph(f'audit_{target_name}')
            if mode_choice == 'offline':
                rep = run_offline(g, target_name)
            else:
                rep = run_agent(f'audit_{target_name}', target_name)
            st.session_state['report'] = rep
            st.session_state['current_source'] = sol_source
            st.session_state['current_project'] = target_name
            st.sidebar.success(f'Audit finished! Mode: {rep.mode}')
        finally:
            if tmp_run_path.exists():
                tmp_run_path.unlink()

tabs = st.tabs([
    '📋 Findings',
    '🕸️ Reachability Graph',
    '🔮 FalkorDB Code Knowledge Graph',
    '🩹 Remediation Patch & Proof',
    '📊 Evaluation Scoreboard',
])

with tabs[0]:
    st.subheader('Verified Security Findings')
    report = st.session_state.get('report')
    if report:
        st.markdown(f'**Project**: `{report.project}` | **Attack Surface Score**: `{report.attack_surface}` | **Mode**: `{report.mode}`')
        if report.findings:
            table_data = []
            for f in report.findings:
                table_data.append({
                    'Class': f.klass,
                    'Severity': f.severity,
                    'Function': f.function_id,
                    'Reachable': '✅ Yes' if f.reachable else '❌ No',
                    'Path Length': len(f.path),
                    'Fix Target': f.sink if f.sink else 'Control Flow',
                })
            st.dataframe(table_data, use_container_width=True)

            for idx, f in enumerate(report.findings):
                with st.expander(f'[{f.klass}] {f.title} - {f.function_id} ({f.severity})'):
                    st.write(f'**Explanation**: {f.explanation}')
                    st.write(f'**Recommended Fix**: {f.recommended_fix}')
                    st.code(' -> '.join(f.path) if f.path else 'Unreachable', language='text')
        else:
            st.success('✅ Zero eligible findings detected. The contract call-graph is safe.')

        if report.rejected:
            with st.expander('🛡️ Verifier Gate: Rejected Unverified Findings', expanded=False):
                st.write('The following potential findings were blocked by the verifier gate (no graph path / invalid edge):')
                st.json(report.rejected)
    else:
        st.info('Select a contract variant in the sidebar and click "Run Audit Pipeline" to analyze.')

with tabs[1]:
    st.subheader('🎯 Multi-Hop Attacker Reachability Proof')
    st.caption('Mathematically proven path from an unauthenticated external entry into a privileged sink.')
    report = st.session_state.get('report')
    if report and report.findings:
        finding_opts = [f'[{f.klass}] {f.function_id} ({f.severity}) ➔ Sink: {f.sink or "Control Flow"}' for f in report.findings]
        selected_idx = st.selectbox('Select Vulnerability Finding to Inspect:', range(len(finding_opts)), format_func=lambda i: finding_opts[i])
        selected_f = report.findings[selected_idx]

        # Detailed exploit narrative card
        col_summary, col_path_stats = st.columns([2, 1])
        with col_summary:
            st.markdown(f"**Vulnerability**: `{selected_f.title}` &nbsp;|&nbsp; **Target**: `{selected_f.function_id}`")
            st.markdown(f"**How the exploit occurs**: {selected_f.explanation}")
        with col_path_stats:
            st.metric('Exploit Path Length', f"{len(selected_f.path)} Hops", delta='Attacker Reachable' if selected_f.reachable else 'Unreachable', delta_color='inverse' if selected_f.reachable else 'normal')

        st.markdown('---')
        
        # Step-by-Step Path Flow
        if selected_f.path:
            st.markdown('**Step-by-Step Exploit Route:**')
            flow_cols = st.columns(len(selected_f.path) + (1 if selected_f.sink else 0))
            for i, hop in enumerate(selected_f.path):
                with flow_cols[i]:
                    if i == 0:
                        st.success(f"**1. Attacker Entry**\n\n`{hop}`\n\n*(Public/External)*")
                    else:
                        st.error(f"**{i+1}. Internal Dispatch**\n\n`{hop}`\n\n*(Private/Internal)*")
            if selected_f.sink:
                with flow_cols[-1]:
                    st.warning(f"**⚠️ Mutates State**\n\n`{selected_f.sink}`\n\n*(Privileged Var)*")

        st.markdown('<div style="height: 10px;"></div>', unsafe_allow_html=True)
        st.markdown('**Interactive Call Graph:** *(Drag nodes or scroll to zoom)*')
        interactive_path = render_interactive_path_html(selected_f.path, selected_f.sink, height=320)
        st.components.v1.html(interactive_path, height=350)

        with st.expander('Formal Cypher Reachability Proof'):
            st.code(selected_f.evidence_cypher or 'MATCH p=(e:Function {is_entry:true, guarded:false})-[:CALLS*1..6]->(t) RETURN p', language='cypher')
    else:
        st.info('Select a contract variant in the sidebar and click "Run Audit Pipeline" to analyze.')

with tabs[2]:
    st.subheader('🔮 FalkorDB Code Knowledge Graph')
    st.caption('Complete directed multi-hop graph of public entries, internal functions, modifier guards, and state-variable writes.')
    report = st.session_state.get('report')
    if report:
        g = get_graph(f'audit_{report.project}')
        full_browser_html = render_interactive_full_graph_html(g, height=560)
        st.components.v1.html(full_browser_html, height=585)
    else:
        st.info('Run an audit pipeline from the sidebar to explore the interactive FalkorDB code graph.')

with tabs[3]:
    st.subheader('Autonomous Patch Generation & Proof-of-Removal')
    report = st.session_state.get('report')
    if report and report.findings:
        finding_opts = [f'{f.klass}: {f.function_id}' for f in report.findings]
        patch_sel = st.selectbox('Select Finding to Patch', range(len(finding_opts)), format_func=lambda i: finding_opts[i], key='patch_sel')
        target_f = report.findings[patch_sel]

        if st.button('🩹 Propose and Verify Patch', type='primary'):
            with st.spinner('Generating patch and proving attack-surface reduction in FalkorDB...'):
                tmp_patch_file = Path('temp_source_patch.sol')
                tmp_patch_file.write_text(st.session_state['current_source'], encoding='utf-8')
                try:
                    patch_res = patch_with_retries(st.session_state['current_project'], str(tmp_patch_file), target_f, max_attempts=3, use_oracle=False)
                    if patch_res.get('success'):
                        st.success(f'✅ Patch Proved Successful! Attack surface reduced from {patch_res["score_before"]} to {patch_res["score_after"]}.')
                    else:
                        st.warning(f'Patch verification: target_gone={patch_res.get("target_gone")}, signatures_preserved={patch_res.get("signatures_preserved")}')

                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric('Compiled', '✅' if patch_res.get('compiled') else '❌')
                    col2.metric('Target Gone', '✅' if patch_res.get('target_gone') else '❌')
                    col3.metric('Signatures Preserved', '✅' if patch_res.get('signatures_preserved') else '❌')
                    col4.metric('Score Delta', f'{patch_res.get("score_before")} -> {patch_res.get("score_after")}')

                    orig_lines = st.session_state['current_source'].splitlines(keepends=True)
                    patched_lines = patch_res.get('patched_source', '').splitlines(keepends=True)
                    diff = list(difflib.unified_diff(orig_lines, patched_lines, fromfile='Original.sol', tofile='Patched.sol'))
                    st.write('**Unified Diff**:')
                    st.code(''.join(diff) if diff else 'No text changes', language='diff')
                finally:
                    if tmp_patch_file.exists():
                        tmp_patch_file.unlink()
    else:
        st.info('Run an audit to generate and prove security patches.')

with tabs[4]:
    st.subheader('Autonomous Red-Team / Blue-Team Scoreboard')
    sb_file = Path('reports/scoreboard.md')
    if sb_file.exists():
        st.markdown(sb_file.read_text(encoding='utf-8'))
    else:
        st.info('Scoreboard records will appear here as evaluation rounds complete.')
