import json
import os
import re
import subprocess
import sys
from pathlib import Path
from slither import Slither
from slither.core.declarations.function import Function
from slither.core.declarations.solidity_variables import SolidityFunction
from src.config import CLASS_MAP, GUARD_RE, PRIVILEGED_NAMES, REENTRANCY_RE
from src.graph import get_graph, q, reset_graph
from src import tools


def ensure_solc_env(sol_path: str) -> None:
    venv_scripts = str(Path('.venv/Scripts').resolve())
    solc_dir = str(Path.home() / '.solc-select' / 'artifacts' / 'solc-0.8.19')
    os.environ['PATH'] = f'{venv_scripts};{solc_dir};' + os.environ.get('PATH', '')
    content = Path(sol_path).read_text(encoding='utf-8')
    m = re.search(r'pragma\s+solidity\s+([^;]+);', content)
    if m:
        ver = m.group(1).replace('^', '').replace('=', '').strip()
        os.environ['SOLC_VERSION'] = ver


def is_fn_guarded(fn) -> bool:
    mod_names = [m.name for m in fn.modifiers]
    if any(GUARD_RE.search(m) for m in mod_names):
        return True
    try:
        cond_vars = fn.all_conditional_solidity_variables_read(include_loop=False)
        if any(getattr(v, 'name', '') == 'msg.sender' for v in cond_vars):
            return True
    except Exception:
        pass
    return False


def is_fn_reentrancy_guarded(fn) -> bool:
    mod_names = [m.name for m in fn.modifiers]
    return any(REENTRANCY_RE.search(m) for m in mod_names)


def get_mutability(fn) -> str:
    if fn.view:
        return 'view'
    if fn.pure:
        return 'pure'
    if fn.payable:
        return 'payable'
    return 'nonpayable'


def extract(sol_path: str):
    sl = Slither(sol_path)
    contracts, state_vars, functions, ext_targets = [], [], [], {}
    calls_edges, calls_ext_edges, reads_edges, writes_edges = [], [], [], []
    inherits_edges, declares_edges, has_var_edges = [], [], []

    fn_ids = set()
    for c in sl.contracts:
        for fn in c.functions_declared:
            if not fn.name.startswith('slither'):
                fn_ids.add(f'{c.name}.{fn.full_name}')

    for c in sl.contracts:
        c_kind = 'contract'
        if c.is_interface:
            c_kind = 'interface'
        elif c.is_library:
            c_kind = 'library'
        contracts.append({'id': c.name, 'name': c.name, 'kind': c_kind})

        for parent in c.immediate_inheritance:
            inherits_edges.append({'src': c.name, 'dst': parent.name})

        for v in c.state_variables_declared:
            v_id = f'{c.name}.{v.name}'
            is_priv = v.name.lower() in PRIVILEGED_NAMES
            state_vars.append({
                'id': v_id,
                'name': v.name,
                'contract': c.name,
                'type': str(v.type),
                'privileged': is_priv,
            })
            has_var_edges.append({'src': c.name, 'dst': v_id})

        for fn in c.functions_declared:
            if fn.name.startswith('slither'):
                continue
            fn_id = f'{c.name}.{fn.full_name}'
            declares_edges.append({'src': c.name, 'dst': fn_id})

            is_entry = fn.visibility in ('public', 'external') and not fn.is_constructor and fn.is_implemented
            guarded = is_fn_guarded(fn)
            re_guarded = is_fn_reentrancy_guarded(fn)
            mods_str = ','.join([m.name for m in fn.modifiers])
            line = fn.source_mapping.lines[0] if (fn.source_mapping and fn.source_mapping.lines) else 0
            has_low_level = len(fn.low_level_calls) > 0

            functions.append({
                'id': fn_id,
                'name': fn.name,
                'contract': c.name,
                'visibility': fn.visibility,
                'mutability': get_mutability(fn),
                'is_entry': is_entry,
                'guarded': guarded,
                'reentrancy_guarded': re_guarded,
                'is_constructor': fn.is_constructor,
                'has_low_level_call': has_low_level,
                'modifiers': mods_str,
                'line': line,
            })

            for item in fn.internal_calls:
                target = getattr(item, 'function', item)
                if isinstance(target, Function) and not isinstance(target, SolidityFunction):
                    c_target = getattr(target, 'contract', None)
                    c_name = c_target.name if c_target else c.name
                    target_id = f'{c_name}.{target.full_name}'
                    if target_id in fn_ids:
                        calls_edges.append({'src': fn_id, 'dst': target_id, 'kind': 'internal'})

            for item in fn.high_level_calls:
                target_c = item[0] if isinstance(item, tuple) else None
                target_f = item[1] if isinstance(item, tuple) else item
                if isinstance(target_f, Function):
                    t_cname = getattr(target_f, 'contract', target_c).name
                    t_id = f'{t_cname}.{target_f.full_name}'
                    if t_id in fn_ids:
                        calls_edges.append({'src': fn_id, 'dst': t_id, 'kind': 'external'})
                    else:
                        ext_id = f'ext:{t_cname}.{target_f.name}'
                        ext_targets[ext_id] = {'id': ext_id, 'kind': 'interface_call'}
                        calls_ext_edges.append({'src': fn_id, 'dst': ext_id})
                else:
                    ext_id = f'ext:{getattr(target_c, "name", "target")}.unknown'
                    ext_targets[ext_id] = {'id': ext_id, 'kind': 'interface_call'}
                    calls_ext_edges.append({'src': fn_id, 'dst': ext_id})

            for llc in fn.low_level_calls:
                fname = getattr(llc, 'function_name', 'call')
                ext_id = f'lowlevel:{fname}'
                ext_targets[ext_id] = {'id': ext_id, 'kind': 'low_level'}
                calls_ext_edges.append({'src': fn_id, 'dst': ext_id})

            for v in fn.state_variables_read:
                c_decl = getattr(v, 'contract', c).name
                reads_edges.append({'src': fn_id, 'dst': f'{c_decl}.{v.name}'})

            for v in fn.state_variables_written:
                c_decl = getattr(v, 'contract', c).name
                writes_edges.append({'src': fn_id, 'dst': f'{c_decl}.{v.name}'})

    return (
        contracts, state_vars, functions, list(ext_targets.values()),
        calls_edges, calls_ext_edges, reads_edges, writes_edges,
        inherits_edges, declares_edges, has_var_edges,
    )


def slither_findings(sol_path: str):
    tmp_file = Path(f'slither_tmp_{os.getpid()}.json')
    if tmp_file.exists():
        tmp_file.unlink()
    env = os.environ.copy()
    subprocess.run(
        [sys.executable, '-m', 'slither', sol_path, '--json', str(tmp_file)],
        env=env, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if not tmp_file.exists():
        return [], []
    data = json.loads(tmp_file.read_text(encoding='utf-8'))
    tmp_file.unlink()

    findings, affects = [], []
    for idx, r in enumerate(data.get('results', {}).get('detectors', [])):
        check = r.get('check', '')
        f_id = f'S{idx}:{check}'
        impact = r.get('impact', 'Low')
        confidence = r.get('confidence', 'Low')
        desc = r.get('description', '')
        klass = CLASS_MAP.get(check, 'OTHER')

        findings.append({
            'id': f_id,
            'check': check,
            'impact': impact,
            'confidence': confidence,
            'klass': klass,
            'source': 'slither',
            'description': desc,
        })

        for elem in r.get('elements', []):
            if elem.get('type') == 'function':
                spec = elem.get('type_specific_fields', {}) or {}
                parent = spec.get('parent', {}) or {}
                parent_name = parent.get('name')
                sig = spec.get('signature')
                if parent_name and sig:
                    affects.append({'src': f_id, 'dst': f'{parent_name}.{sig}'})
                elif elem.get('name') and parent_name:
                    affects.append({'src': f_id, 'dst': f'{parent_name}.{elem.get("name")}'})

    return findings, affects


def ingest(sol_path: str, project: str):
    ensure_solc_env(sol_path)
    graph_name = f'audit_{project}'
    reset_graph(graph_name)
    g = get_graph(graph_name)

    for label in ['Function', 'Contract', 'StateVar', 'Finding']:
        try:
            g.query(f'CREATE INDEX FOR (n:{label}) ON (n.id)')
        except Exception:
            pass

    (
        contracts, state_vars, functions, ext_targets,
        calls, calls_ext, reads, writes,
        inherits, declares, has_var,
    ) = extract(sol_path)

    findings, affects = slither_findings(sol_path)

    if contracts:
        g.query('UNWIND $rows AS r MERGE (c:Contract {id: r.id}) SET c.name = r.name, c.kind = r.kind', {'rows': contracts})
    if state_vars:
        g.query('UNWIND $rows AS r MERGE (v:StateVar {id: r.id}) SET v.name = r.name, v.contract = r.contract, v.type = r.type, v.privileged = r.privileged', {'rows': state_vars})
    if functions:
        g.query('UNWIND $rows AS r MERGE (f:Function {id: r.id}) SET f.name = r.name, f.contract = r.contract, f.visibility = r.visibility, f.mutability = r.mutability, f.is_entry = r.is_entry, f.guarded = r.guarded, f.reentrancy_guarded = r.reentrancy_guarded, f.is_constructor = r.is_constructor, f.has_low_level_call = r.has_low_level_call, f.modifiers = r.modifiers, f.line = r.line', {'rows': functions})
    if ext_targets:
        g.query('UNWIND $rows AS r MERGE (t:ExternalTarget {id: r.id}) SET t.kind = r.kind', {'rows': ext_targets})

    if calls:
        g.query('UNWIND $rows AS r MATCH (a:Function {id: r.src}), (b:Function {id: r.dst}) MERGE (a)-[e:CALLS]->(b) SET e.kind = r.kind', {'rows': calls})
    if calls_ext:
        g.query('UNWIND $rows AS r MATCH (a:Function {id: r.src}), (b:ExternalTarget {id: r.dst}) MERGE (a)-[:CALLS_EXT]->(b)', {'rows': calls_ext})
    if reads:
        g.query('UNWIND $rows AS r MATCH (a:Function {id: r.src}), (b:StateVar {id: r.dst}) MERGE (a)-[:READS]->(b)', {'rows': reads})
    if writes:
        g.query('UNWIND $rows AS r MATCH (a:Function {id: r.src}), (b:StateVar {id: r.dst}) MERGE (a)-[:WRITES]->(b)', {'rows': writes})
    if declares:
        g.query('UNWIND $rows AS r MATCH (a:Contract {id: r.src}), (b:Function {id: r.dst}) MERGE (a)-[:DECLARES]->(b)', {'rows': declares})
    if has_var:
        g.query('UNWIND $rows AS r MATCH (a:Contract {id: r.src}), (b:StateVar {id: r.dst}) MERGE (a)-[:HAS_VAR]->(b)', {'rows': has_var})
    if inherits:
        g.query('UNWIND $rows AS r MATCH (a:Contract {id: r.src}), (b:Contract {id: r.dst}) MERGE (a)-[:INHERITS]->(b)', {'rows': inherits})

    p_findings, p_affects = [], []
    writers = tools.unguarded_privileged_writers(g)
    for idx, item in enumerate(writers):
        writer = item['writer']
        var = item['var']
        p_id = f'P{idx}:{writer}:{var}'
        p_findings.append({
            'id': p_id,
            'check': 'unguarded-privileged-writer',
            'impact': 'High',
            'confidence': 'High',
            'klass': 'P',
            'source': 'graph',
            'description': f'Privileged state variable {var} is written by attacker reachable function {writer}.',
        })
        p_affects.append({'src': p_id, 'dst': writer})

    all_findings = findings + p_findings
    all_affects = affects + p_affects

    if all_findings:
        g.query("UNWIND $rows AS r MERGE (x:Finding {id: r.id}) SET x.check = r.check, x.impact = r.impact, x.confidence = r.confidence, x.klass = r.klass, x.source = r.source, x.description = r.description, x.status = 'open'", {'rows': all_findings})
    if all_affects:
        g.query('UNWIND $rows AS r MATCH (x:Finding {id: r.src}), (f:Function {id: r.dst}) MERGE (x)-[:AFFECTS]->(f)', {'rows': all_affects})

    counts = {
        'Contract': len(contracts),
        'Function': len(functions),
        'StateVar': len(state_vars),
        'Finding': len(all_findings),
        'CALLS': len(calls),
        'WRITES': len(writes),
    }
    return counts


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python -m src.ingest <sol_path> <project>')
        sys.exit(1)
    res = ingest(sys.argv[1], sys.argv[2])
    print(res)
