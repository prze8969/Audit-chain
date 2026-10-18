import json
from src.graph import q
from src.models import FindingOut, Report
from src import tools


def collect_paths(tool_log: list[dict]) -> set[tuple]:
    collected = set()
    for entry in tool_log:
        output_raw = entry.get('output', '')
        if not output_raw:
            continue
        try:
            data = json.loads(output_raw) if isinstance(output_raw, str) else output_raw
            if isinstance(data, dict):
                if 'path' in data and isinstance(data['path'], list):
                    collected.add(tuple(data['path']))
                if 'paths' in data and isinstance(data['paths'], list):
                    for p in data['paths']:
                        if isinstance(p, list):
                            collected.add(tuple(p))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        if 'path' in item and isinstance(item['path'], list):
                            collected.add(tuple(item['path']))
                        if 'paths' in item and isinstance(item['paths'], list):
                            for p in item['paths']:
                                if isinstance(p, list):
                                    collected.add(tuple(p))
        except Exception:
            pass
    return collected


def verify_report(report: Report, tool_log: list[dict], g) -> tuple[list[FindingOut], list[dict]]:
    accepted = []
    rejected = list(report.rejected)
    tool_paths = collect_paths(tool_log)

    rank_list = tools.rank_findings(g)
    score_map = {item['finding_id']: item['score'] for item in rank_list}

    for finding in report.findings:
        fn_rows = q(g, 'MATCH (f:Function {id: $id}) RETURN count(f)', {'id': finding.function_id})
        if not fn_rows or fn_rows[0][0] == 0:
            rejected.append({'finding_id': finding.finding_id, 'reason': 'unknown_function'})
            continue

        f_rows = q(g, 'MATCH (x:Finding {id: $id}) RETURN x.klass', {'id': finding.finding_id})
        if not f_rows:
            rejected.append({'finding_id': finding.finding_id, 'reason': 'unknown_finding'})
            continue
        node_klass = f_rows[0][0]
        if node_klass != finding.klass:
            rejected.append({'finding_id': finding.finding_id, 'reason': 'klass_mismatch'})
            continue

        if finding.reachable:
            if not finding.path or finding.path[-1] != finding.function_id:
                rejected.append({'finding_id': finding.finding_id, 'reason': 'bad_endpoints'})
                continue
            entry_fn = finding.path[0]
            e_rows = q(g, 'MATCH (e:Function {id: $id}) RETURN e.is_entry, e.guarded', {'id': entry_fn})
            if not e_rows or not e_rows[0][0] or e_rows[0][1]:
                rejected.append({'finding_id': finding.finding_id, 'reason': 'bad_endpoints'})
                continue

            has_broken_edge = False
            for i in range(len(finding.path) - 1):
                a_id, b_id = finding.path[i], finding.path[i + 1]
                call_rows = q(g, 'MATCH (a:Function {id: $a})-[:CALLS]->(b:Function {id: $b}) RETURN count(*)', {'a': a_id, 'b': b_id})
                if not call_rows or call_rows[0][0] == 0:
                    has_broken_edge = True
                    break
            if has_broken_edge:
                rejected.append({'finding_id': finding.finding_id, 'reason': 'broken_edge'})
                continue

            if tuple(finding.path) not in tool_paths:
                rejected.append({'finding_id': finding.finding_id, 'reason': 'path_not_from_tools'})
                continue
        else:
            if finding.path:
                rejected.append({'finding_id': finding.finding_id, 'reason': 'false_unreachable'})
                continue
            ep = tools.entry_paths_to(g, finding.function_id)
            if ep['reachable']:
                rejected.append({'finding_id': finding.finding_id, 'reason': 'false_unreachable'})
                continue

        accepted.append(finding)

    accepted.sort(key=lambda f: score_map.get(f.finding_id, 0.0), reverse=True)
    return accepted, rejected
