import json
from pathlib import Path
import pytest
from src.agent import run_offline
from src.graph import get_graph
from src.ingest import ingest

LABELS_PATH = Path('samples/variants/labels.json')
LABELS = json.loads(LABELS_PATH.read_text(encoding='utf-8'))


@pytest.mark.parametrize('item', LABELS)
def test_offline_variant(item):
    variant = item['variant']
    expected = item['expected']
    sol_path = f'samples/variants/{variant}.sol'
    ingest(sol_path, variant)
    g = get_graph(f'audit_{variant}')

    rep = run_offline(g, variant)
    assert len(rep.rejected) == 0

    accepted_pairs = {(f.klass, f.function_id) for f in rep.findings}
    expected_pairs = {(e['klass'], e['function_id']) for e in expected}
    assert accepted_pairs == expected_pairs

    exp_map = {(e['klass'], e['function_id']): e['path'] for e in expected}
    for f in rep.findings:
        pair = (f.klass, f.function_id)
        assert f.path == exp_map[pair]
