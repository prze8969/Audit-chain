import networkx as nx
from src.config import CONF, IMPACT
from src.graph import q


def graph_summary(g) -> dict:
    funcs = [r[0] for r in q(g, 'MATCH (f:Function) RETURN f.id')]
    entries = [r[0] for r in q(g, 'MATCH (f:Function {is_entry: true}) RETURN f.id')]
    ung_entries = [r[0] for r in q(g, 'MATCH (f:Function {is_entry: true, guarded: false}) RETURN f.id')]
    priv_vars = [r[0] for r in q(g, 'MATCH (v:StateVar {privileged: true}) RETURN v.id')]
    findings_rows = q(g, 'MATCH (x:Finding) RETURN coalesce(x.klass, "OTHER") AS k, count(x)')
    finding_counts = {r[0]: r[1] for r in findings_rows}

    return {
        'functions': funcs,
        'entries': entries,
        'unguarded_entries': ung_entries,
        'privileged_vars': priv_vars,
        'findings': finding_counts,
    }


def list_findings(g, klass: str | None = None) -> list:
    if klass:
        rows = q(
            g,
            'MATCH (x:Finding {klass: $k}) OPTIONAL MATCH (x)-[:AFFECTS]->(f:Function) '
            'RETURN x.id, x.check, x.impact, x.confidence, x.klass, x.source, collect(f.id)',
            {'k': klass},
        )
    else:
        rows = q(
            g,
            'MATCH (x:Finding) OPTIONAL MATCH (x)-[:AFFECTS]->(f:Function) '
            'RETURN x.id, x.check, x.impact, x.confidence, x.klass, x.source, collect(f.id)',
        )
    out = []
    for r in rows:
        out.append({
            'id': r[0],
            'check': r[1],
            'impact': r[2],
            'confidence': r[3],
            'klass': r[4],
            'source': r[5],
            'function_ids': r[6],
        })
    return out


def entry_paths_to(g, function_id: str, max_hops: int = 6) -> dict:
    clamped_hops = max(1, min(8, int(max_hops)))
    t_row = q(g, 'MATCH (t:Function {id: $id}) RETURN t.is_entry, t.guarded', {'id': function_id})
    paths = []
    cypher_used = ''

    if t_row and t_row[0][0] is True and t_row[0][1] is False:
        paths.append([function_id])

    cypher_used = (
        f'MATCH p = (e:Function {{is_entry: true, guarded: false}})-[:CALLS*1..{clamped_hops}]->(t:Function {{id: $id}}) '
        f'WITH p, length(p) AS len '
        f'RETURN [n IN nodes(p) | n.id] AS path ORDER BY len LIMIT 3'
    )
    rows = q(g, cypher_used, {'id': function_id})
    for r in rows:
        p = r[0]
        if p not in paths:
            paths.append(p)

    paths = paths[:3]
    return {
        'function_id': function_id,
        'reachable': len(paths) > 0,
        'paths': paths,
        'cypher': cypher_used,
    }


def unguarded_privileged_writers(g) -> list:
    writers = q(g, 'MATCH (w:Function)-[:WRITES]->(v:StateVar {privileged: true}) RETURN w.id AS writer, v.id AS var')
    items = []
    for row in writers:
        w_id, v_id = row[0], row[1]
        ep = entry_paths_to(g, w_id)
        if ep['reachable'] and ep['paths']:
            shortest_path = min(ep['paths'], key=len)
            items.append({
                'writer': w_id,
                'var': v_id,
                'path': shortest_path,
                'cypher': ep['cypher'],
            })
    return items


def who_writes(g, var_id: str) -> list:
    rows = q(g, 'MATCH (f:Function)-[:WRITES]->(v:StateVar {id: $id}) RETURN f.id, f.is_entry, f.guarded', {'id': var_id})
    return [{'function': r[0], 'is_entry': r[1], 'guarded': r[2]} for r in rows]


def blast_radius(g, function_id: str, max_hops: int = 6) -> dict:
    clamped = max(1, min(8, int(max_hops)))
    cypher_reach = f'MATCH (s:Function {{id: $id}})-[:CALLS*1..{clamped}]->(f:Function) RETURN DISTINCT f.id'
    rows = q(g, cypher_reach, {'id': function_id})
    reach_ids = {r[0] for r in rows}
    reach_ids.add(function_id)
    id_list = list(reach_ids)

    vars_written = [r[0] for r in q(g, 'MATCH (f:Function)-[:WRITES]->(v:StateVar) WHERE f.id IN $ids RETURN DISTINCT v.id', {'ids': id_list})]
    ext_targets = [r[0] for r in q(g, 'MATCH (f:Function)-[:CALLS_EXT]->(t:ExternalTarget) WHERE f.id IN $ids RETURN DISTINCT t.id', {'ids': id_list})]

    return {
        'reachable_functions': id_list,
        'state_written': vars_written,
        'external_targets': ext_targets,
    }


def hotspots(g, top_n: int = 5) -> dict:
    try:
        rows = q(g, 'CALL algo.pageRank(\'Function\', \'CALLS\') YIELD node, score RETURN node.id AS id, score ORDER BY score DESC LIMIT $n', {'n': int(top_n)})
        return {
            'engine': 'falkordb',
            'items': [{'function': r[0], 'score': float(r[1])} for r in rows],
        }
    except Exception:
        edges = q(g, 'MATCH (a:Function)-[:CALLS]->(b:Function) RETURN a.id, b.id')
        all_funcs = [r[0] for r in q(g, 'MATCH (f:Function) RETURN f.id')]
        G = nx.DiGraph()
        for f in all_funcs:
            G.add_node(f)
        for u, v in edges:
            G.add_edge(u, v)
        pr = nx.pagerank(G)
        sorted_items = sorted(pr.items(), key=lambda x: x[1], reverse=True)[:int(top_n)]
        return {
            'engine': 'networkx',
            'items': [{'function': k, 'score': float(v)} for k, v in sorted_items],
        }


def attack_surface_score(g) -> dict:
    p_paths = len(unguarded_privileged_writers(g))
    res_ext = q(g, 'MATCH (f:Function {is_entry: true, guarded: false}) WHERE f.has_low_level_call = true RETURN count(f)')
    ung_ext = res_ext[0][0] if res_ext else 0
    res_w = q(g, 'MATCH (f:Function {is_entry: true, guarded: false})-[:WRITES]->(v:StateVar) RETURN count(DISTINCT f)')
    ung_writers = res_w[0][0] if res_w else 0
    score = 5 * p_paths + 2 * ung_ext + ung_writers
    return {
        'score': score,
        'p_paths': p_paths,
        'unguarded_ext_call_entries': ung_ext,
        'unguarded_state_writers': ung_writers,
    }


def rank_findings(g) -> list:
    eligible_rows = q(
        g,
        'MATCH (x:Finding) WHERE x.impact IN [\'High\', \'Medium\'] OR x.klass = \'P\' '
        'OPTIONAL MATCH (x)-[:AFFECTS]->(f:Function) '
        'RETURN x.id, x.check, x.impact, x.confidence, x.klass, x.source, collect(f.id)',
    )
    hs = hotspots(g, top_n=50)
    pr_map = {item['function']: item['score'] for item in hs['items']}
    max_pr = max(pr_map.values()) if pr_map and max(pr_map.values()) > 0 else 1.0

    ranked = []
    for r in eligible_rows:
        f_id, check, impact, conf, klass, source, funcs = r[0], r[1], r[2], r[3], r[4], r[5], r[6]
        primary_fn = funcs[0] if funcs else None
        reachable = False
        path = []
        pr = 0.0
        if primary_fn:
            ep = entry_paths_to(g, primary_fn)
            reachable = ep['reachable']
            path = ep['paths'][0] if ep['paths'] else []
            pr = (pr_map.get(primary_fn, 0.0) / max_pr) if max_pr > 0 else 0.0

        imp_val = IMPACT.get(impact, 2.0)
        conf_val = CONF.get(conf, 0.8)
        reach_weight = 1.0 if reachable else 0.3
        score = imp_val * reach_weight * conf_val * (1.0 + 2.0 * pr)

        ranked.append({
            'finding_id': f_id,
            'check': check,
            'impact': impact,
            'confidence': conf,
            'klass': klass,
            'source': source,
            'function_ids': funcs,
            'reachable': reachable,
            'path': path,
            'score': round(score, 4),
        })

    ranked.sort(key=lambda x: x['score'], reverse=True)
    return ranked
