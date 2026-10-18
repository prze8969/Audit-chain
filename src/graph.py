import os
from falkordb import FalkorDB


def get_graph(name: str):
    host = os.getenv('FALKORDB_HOST', 'localhost')
    port = int(os.getenv('FALKORDB_PORT', '6379'))
    username = os.getenv('FALKORDB_USERNAME')
    password = os.getenv('FALKORDB_PASSWORD')
    ssl_str = os.getenv('FALKORDB_SSL', 'false').lower()
    ssl = ssl_str in ('true', '1', 'yes')
    kwargs = {}
    if username:
        kwargs['username'] = username
    if password:
        kwargs['password'] = password
    if ssl:
        kwargs['ssl'] = True
    db = FalkorDB(host=host, port=port, **kwargs)
    return db.select_graph(name)


def reset_graph(name: str) -> None:
    try:
        get_graph(name).delete()
    except Exception:
        pass


def q(g, cypher: str, params: dict | None = None) -> list:
    return g.query(cypher, params or {}).result_set
