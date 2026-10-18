import hashlib
import os
from src.graph import get_graph, q


def record_audit(audit_id: str, project: str, score: int, klass: str, patch_text: str | None = None) -> None:
    g = get_graph('audit_memory')
    try:
        g.query('CREATE INDEX FOR (a:Audit) ON (a.id)')
        g.query('CREATE INDEX FOR (p:Pattern) ON (p.id)')
        g.query('CREATE INDEX FOR (f:Fix) ON (f.id)')
    except Exception:
        pass

    q(g, 'MERGE (a:Audit {id: $audit}) SET a.project = $project, a.score = $score', {'audit': audit_id, 'project': project, 'score': score})

    if klass == 'P':
        shape = 'unguarded->owner'
    elif klass == 'R':
        shape = 'extcall-before-write'
    elif klass == 'U':
        shape = 'unchecked-lowlevel'
    else:
        shape = 'other'

    pid = f'{klass}:{shape}'
    q(g, 'MERGE (p:Pattern {id: $pid}) SET p.klass = $klass', {'pid': pid, 'klass': klass})
    q(g, 'MATCH (a:Audit {id: $audit}), (p:Pattern {id: $pid}) MERGE (a)-[:HAD]->(p)', {'audit': audit_id, 'pid': pid})

    if patch_text:
        trimmed = patch_text[:300]
        fid = hashlib.sha1(trimmed.encode('utf-8')).hexdigest()[:12]
        q(g, 'MERGE (f:Fix {id: $fid}) SET f.text = $text', {'fid': fid, 'text': trimmed})
        q(g, 'MATCH (p:Pattern {id: $pid}), (f:Fix {id: $fid}) MERGE (p)-[r:FIXED_BY]->(f) SET r.uses = coalesce(r.uses, 0) + 1', {'pid': pid, 'fid': fid})


def recall_fixes(klass: str, top_n: int = 3) -> list:
    g = get_graph('audit_memory')
    rows = q(g, 'MATCH (p:Pattern {klass: $k})-[r:FIXED_BY]->(f:Fix) RETURN f.text AS text, r.uses AS uses ORDER BY uses DESC LIMIT $n', {'k': klass, 'n': int(top_n)})
    return [{'text': r[0], 'uses': r[1]} for r in rows]
