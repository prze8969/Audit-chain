from src.graph import get_graph, q


def test_m7_ingest():
    g = get_graph('audit_m7')

    res = q(g, "MATCH (f:Function {id: 'Treasury.setOwner(address)'}) RETURN f.is_entry, f.guarded")
    assert len(res) == 1
    assert res[0][0] is True
    assert res[0][1] is False

    res = q(g, "MATCH (a:Function {id: 'Treasury.handOver(address)'})-[:CALLS]->(b:Function {id: 'Treasury._grant(address)'}) RETURN count(*)")
    assert res[0][0] == 1

    res = q(g, "MATCH (a:Function {id: 'Treasury._grant(address)'})-[:WRITES]->(v:StateVar {id: 'Treasury.owner'}) RETURN v.privileged")
    assert len(res) == 1
    assert res[0][0] is True

    res = q(g, "MATCH (f:Function {id: 'Treasury.withdraw(uint256)'})-[:WRITES]->(v:StateVar {id: 'Treasury.balances'}) RETURN f.has_low_level_call")
    assert len(res) == 1
    assert res[0][0] is True

    res = q(g, "MATCH (x:Finding {check: 'reentrancy-eth', klass: 'R'}) RETURN count(x)")
    assert res[0][0] >= 1

    res = q(g, "MATCH (x:Finding {check: 'unchecked-lowlevel', klass: 'U'}) RETURN count(x)")
    assert res[0][0] >= 1

    res = q(g, "MATCH (f:Function) WHERE f.id STARTS WITH 'Treasury.slither' RETURN count(f)")
    assert res[0][0] == 0
