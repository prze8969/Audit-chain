import pytest
from src.graph import get_graph
from src.ingest import ingest
from src import tools

VARIANTS = ['clean', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7']


@pytest.fixture(scope='session', autouse=True)
def ingest_all_variants():
    for v in VARIANTS:
        ingest(f'samples/variants/{v}.sol', v)


def test_clean():
    g = get_graph('audit_clean')
    writers = tools.unguarded_privileged_writers(g)
    assert len(writers) == 0
    rf = tools.rank_findings(g)
    assert len(rf) == 0


def test_m1():
    g = get_graph('audit_m1')
    writers = tools.unguarded_privileged_writers(g)
    assert len(writers) == 1
    assert writers[0]['writer'] == 'Treasury.setOwner(address)'
    assert writers[0]['path'] == ['Treasury.setOwner(address)']
    rf = tools.rank_findings(g)
    klasses = [x['klass'] for x in rf]
    assert klasses == ['P']


def test_m2():
    g = get_graph('audit_m2')
    writers = tools.unguarded_privileged_writers(g)
    assert len(writers) == 1
    assert writers[0]['writer'] == 'Treasury._grant(address)'
    assert writers[0]['path'] == ['Treasury.handOver(address)', 'Treasury._grant(address)']
    rf = tools.rank_findings(g)
    klasses = [x['klass'] for x in rf]
    assert klasses == ['P']


def test_m3():
    g = get_graph('audit_m3')
    writers = tools.unguarded_privileged_writers(g)
    assert len(writers) == 0
    rf = tools.rank_findings(g)
    klasses = [x['klass'] for x in rf]
    assert klasses == ['R']


def test_m4():
    g = get_graph('audit_m4')
    writers = tools.unguarded_privileged_writers(g)
    assert len(writers) == 0
    rf = tools.rank_findings(g)
    klasses = [x['klass'] for x in rf]
    assert klasses == ['U']


def test_m5():
    g = get_graph('audit_m5')
    writers = tools.unguarded_privileged_writers(g)
    assert len(writers) == 1
    assert writers[0]['writer'] == 'Treasury.setOwner(address)'
    rf = tools.rank_findings(g)
    klasses = sorted([x['klass'] for x in rf])
    assert klasses == ['P', 'R']


def test_m6():
    g = get_graph('audit_m6')
    writers = tools.unguarded_privileged_writers(g)
    assert len(writers) == 1
    assert writers[0]['writer'] == 'Treasury._grant(address)'
    rf = tools.rank_findings(g)
    klasses = sorted([x['klass'] for x in rf])
    assert klasses == ['P', 'U']


def test_m7():
    g = get_graph('audit_m7')
    writers = tools.unguarded_privileged_writers(g)
    assert len(writers) == 2
    writer_names = {w['writer'] for w in writers}
    assert writer_names == {'Treasury.setOwner(address)', 'Treasury._grant(address)'}

    rf = tools.rank_findings(g)
    klasses = sorted([x['klass'] for x in rf])
    assert klasses == ['P', 'P', 'R', 'U']

    ep = tools.entry_paths_to(g, 'Treasury._grant(address)')
    assert ep['reachable'] is True
    shortest = min(ep['paths'], key=len)
    assert shortest == ['Treasury.handOver(address)', 'Treasury._grant(address)']

    score_m7 = tools.attack_surface_score(g)['score']
    score_clean = tools.attack_surface_score(get_graph('audit_clean'))['score']
    assert score_m7 > score_clean

    hs = tools.hotspots(g)
    assert len(hs['items']) > 0
