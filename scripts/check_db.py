from falkordb import FalkorDB

g = FalkorDB().select_graph('t')
print(g.query('RETURN 1').result_set)
