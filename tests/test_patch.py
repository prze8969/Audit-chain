from pathlib import Path
import pytest
from src.agent import run_offline
from src.graph import get_graph
from src.ingest import ingest
from src.models import FindingOut
from src.patch import oracle_patch, verify_patch


def test_oracle_patch_m1():
    variant = 'm1'
    sol_path = f'samples/variants/{variant}.sol'
    ingest(sol_path, variant)
    g = get_graph(f'audit_{variant}')
    rep = run_offline(g, variant)
    f = rep.findings[0]

    patched_src = oracle_patch(variant)
    res = verify_patch(variant, sol_path, patched_src, f)
    assert res['compiled'] is True
    assert res['target_gone'] is True
    assert len(res['new_eligible']) == 0
    assert res['signatures_preserved'] is True
    assert res['success'] is True


def test_patch_syntax_error():
    variant = 'm1'
    sol_path = f'samples/variants/{variant}.sol'
    f = FindingOut(
        finding_id='P0',
        klass='P',
        title='Bug',
        severity='High',
        function_id='Treasury.setOwner(address)',
        reachable=True,
        path=['Treasury.setOwner(address)'],
        explanation='Expl',
        recommended_fix='Fix',
    )
    bad_source = 'contract Treasury { syntax error here ;;; '
    res = verify_patch(variant, sol_path, bad_source, f)
    assert res['compiled'] is False
    assert res['reason'] == 'compile_error'
    assert res['success'] is False


def test_patch_renamed_function():
    variant = 'm1'
    sol_path = f'samples/variants/{variant}.sol'
    ingest(sol_path, variant)
    orig_src = Path(sol_path).read_text(encoding='utf-8')
    renamed_src = orig_src.replace('function setOwner(address newOwner)', 'function setOwnerRenamed(address newOwner)')
    f = FindingOut(
        finding_id='P0',
        klass='P',
        title='Bug',
        severity='High',
        function_id='Treasury.setOwner(address)',
        reachable=True,
        path=['Treasury.setOwner(address)'],
        explanation='Expl',
        recommended_fix='Fix',
    )
    res = verify_patch(variant, sol_path, renamed_src, f)
    assert res['compiled'] is True
    assert res['signatures_preserved'] is False
    assert res['success'] is False
