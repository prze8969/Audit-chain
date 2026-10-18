import os
from falkordb import FalkorDB


def get_graph(name: str):
    host = os.getenv('FALKORDB_HOST', 'localhost')
    port = int(os.getenv('FALKORDB_PORT', '6379'))
    db = FalkorDB(host=host, port=port)
    return db.select_graph(name)


def reset_graph(name: str) -> None:
    try:
        get_graph(name).delete()
    except Exception:
        pass


def q(g, cypher: str, params: dict | None = None) -> list:
    return g.query(cypher, params or {}).result_set
