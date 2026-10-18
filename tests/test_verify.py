import pytest
from src.graph import get_graph
from src.ingest import ingest
from src.models import FindingOut, Report
from src.verify import verify_report
from src import tools


@pytest.fixture(scope='module', autouse=True)
def setup_graphs():
    ingest('samples/variants/m2.sol', 'm2')
    ingest('samples/variants/m7.sol', 'm7')


def test_forged_unknown_function():
    g = get_graph('audit_m7')
    rf = tools.rank_findings(g)
    real_f = rf[0]
    forged_finding = FindingOut(
        finding_id=real_f['finding_id'],
        klass=real_f['klass'],
        title='Bug',
        severity=real_f['impact'],
        function_id='Treasury.nonExistentFunction()',
        reachable=True,
        path=['Treasury.setOwner(address)'],
        explanation='Expl',
        recommended_fix='Fix',
    )
    rep = Report(project='m7', attack_surface=10, findings=[forged_finding])
    tool_log = [{'name': 'entry_paths_to', 'input': {}, 'output': '{"paths": [["Treasury.setOwner(address)"]]}'}]
    accepted, rejected = verify_report(rep, tool_log, g)
    assert len(accepted) == 0
    assert len(rejected) == 1
    assert rejected[0]['reason'] == 'unknown_function'


def test_forged_broken_edge():
    g = get_graph('audit_m7')
    rf = tools.rank_findings(g)
    real_f = [x for x in rf if x['klass'] == 'P' and 'setOwner' in x['function_ids'][0]][0]
    forged_finding = FindingOut(
        finding_id=real_f['finding_id'],
        klass=real_f['klass'],
        title='Bug',
        severity=real_f['impact'],
        function_id='Treasury.setOwner(address)',
        reachable=True,
        path=['Treasury.deposit()', 'Treasury.setOwner(address)'],
        explanation='Expl',
        recommended_fix='Fix',
    )
    rep = Report(project='m7', attack_surface=10, findings=[forged_finding])
    tool_log = [{'name': 'entry_paths_to', 'input': {}, 'output': '{"paths": [["Treasury.deposit()", "Treasury.setOwner(address)"]]}'}]
    accepted, rejected = verify_report(rep, tool_log, g)
    assert len(accepted) == 0
    assert len(rejected) == 1
    assert rejected[0]['reason'] == 'broken_edge'


def test_forged_false_unreachable():
    g = get_graph('audit_m2')
    rf = tools.rank_findings(g)
    real_f = rf[0]
    forged_finding = FindingOut(
        finding_id=real_f['finding_id'],
        klass=real_f['klass'],
        title='Bug',
        severity=real_f['impact'],
        function_id='Treasury._grant(address)',
        reachable=False,
        path=[],
        explanation='Expl',
        recommended_fix='Fix',
    )
    rep = Report(project='m2', attack_surface=10, findings=[forged_finding])
    tool_log = []
    accepted, rejected = verify_report(rep, tool_log, g)
    assert len(accepted) == 0
    assert len(rejected) == 1
    assert rejected[0]['reason'] == 'false_unreachable'
