| id | symptom | root cause | fix | guarding test / CP |
|---|---|---|---|---|
| BUG-01 | `_AR_EXP_UpdateEntityIdx: Unable to locate a value with alias p within the record` | FalkorDB variable-length Cypher query cannot evaluate `ORDER BY length(p)` without projecting length alias first | In `src/tools.py` `entry_paths_to`, used `WITH p, length(p) AS len ... ORDER BY len` | CP3.1 / `tests/test_tools.py` |
| BUG-02 | `ModuleNotFoundError: No module named 'mcp.server.fastmcp'` with mcp 2.x | mcp package 2.x deprecated fastmcp in favor of MCPServer | Pinned `mcp<2` in requirements.lock and environment | CP3.3 / `scripts/mcp_smoke.py` |
| BUG-03 | `take(uint256)` in `h1.sol` wrongly detected as guarded | Slither's `fn.is_protected()` classified functions passing `msg.sender` as arguments (e.g., `_pay(msg.sender, a)`) as protected | Refined `is_fn_guarded` to inspect conditional read variables (`all_conditional_solidity_variables_read`) instead of argument variables | CP5.4 / Held-out Round 2 |


