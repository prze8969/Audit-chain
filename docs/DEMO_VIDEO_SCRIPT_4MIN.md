# 🎬 Full 4-Minute Demo Video Script: Audit-Chain
**Track**: Track 01 (Agents That Act on Connected Data)  
**Project**: Audit-Chain: Autonomous Graph Security Agent with Proof-of-Reachability & Remediation  
**Target Duration**: 4:00 (240 Seconds)

---

### [0:00 - 0:40] Scene 1: The Critical Flaw in Smart Contract Auditing
- **Visual on Screen**: 
  - Open terminal running traditional AST / regex linters (e.g. Slither CLI directly). 
  - Show the terminal flooded with 20+ alerts: warnings about low-level calls, unindexed events, unhandled returns.
- **Narrator**:
  > *"Every Web3 developer and security auditor knows the nightmare of static analysis today: endless noise. Linters flag dozens of theoretical warnings on smart contracts, but they fail to answer the single most vital question in security:*
  > 
  > ***Can an attacker actually reach this bug from an external transaction?***
  > 
  > *If vulnerable code is trapped behind an internal helper or protected by access control higher up the call stack, it cannot be exploited. But if there is a multi-hop route from `msg.sender` straight into that flaw, funds will be drained.*
  > 
  > *Welcome to **Audit-Chain**: an autonomous security agent powered by **FalkorDB** and **Model Context Protocol (MCP)** that turns smart contracts into connected knowledge graphs, proves reachability with multi-hop Cypher paths, generates patches, and mathematically proves the patch eliminated the exploit."*

---

### [0:40 - 1:20] Scene 2: Connected Data & The FalkorDB Code Graph
- **Visual on Screen**:
  - Open FalkorDB Browser UI at `http://localhost:3000`.
  - Execute: `MATCH (n)-[e]->(m) RETURN n,e,m` on graph `audit_m7`.
  - Zoom in on nodes: Green `Function` nodes, Orange `StateVar` nodes, `CALLS` edges, and `WRITES` edges.
- **Narrator**:
  > *"Instead of treating Solidity as static text or a flat syntax tree, Audit-Chain parses the contract into a rich directed graph inside **FalkorDB**:*
  > - *Every function becomes a node with visibility, mutability, entry status, and access-control modifiers.*
  > - *State variables are nodes with privileged flags for variables like `owner`, `admin`, or `governance`.*
  > - *`CALLS` edges map both internal and external contract dispatch, while `READS` and `WRITES` map state mutations.*
  > 
  > *Now, finding an exploit isn't guesswork—it's graph traversal. We can run Cypher queries to discover multi-hop paths from any unauthenticated entry point into critical state updates."*

---

### [1:20 - 2:05] Scene 3: Tool Selection Through MCP & Graph Algorithms
- **Visual on Screen**:
  - Show FastMCP server (`src/mcp_server.py`) and inspect the trace logs in `reports/trace_m7.jsonl`.
  - Show the 9 specialized MCP tools:
    1. `graph_summary`: High-level graph topology and privileged variable counts.
    2. `entry_paths_to`: Multi-hop shortest paths up to 6 hops from unauthenticated entries.
    3. `unguarded_privileged_writers`: Attacker routes to functions overwriting owner/admin.
    4. `who_writes`: Reverse storage dependency mapping.
    5. `blast_radius`: Downstream state variables and external contracts reachable from a function.
    6. `hotspots`: Centrality scoring using **PageRank** (`CALL algo.pageRank` with NetworkX fallback).
    7. `attack_surface_score`: A composite formula combining unguarded state writers, privileged write paths, and low-level call exposures.
    8. `rank_findings`: Centrality- and reachability-weighted finding prioritizer.
    9. `recall_fixes`: Audit memory graph query tool.
- **Narrator**:
  > *"Audit-Chain exposes 9 graph intelligence tools via a standardized Model Context Protocol (MCP) server.*
  > 
  > *Rather than hardcoding rigid agent scripts, the autonomous agent inspects the contract using dynamic MCP discovery. It queries graph centrality via **PageRank** to identify hot functions, checks the blast radius of state modifications, and measures the quantitative **Attack Surface Score** before and after audits.*
  > 
  > *The agent chooses its own investigation order, using graph algorithms as cognitive tools."*

---

### [2:05 - 2:50] Scene 4: Multi-Hop Reasoning & The Strict Verifier Gate
- **Visual on Screen**:
  - Switch to the Audit-Chain Streamlit Web App (`http://localhost:8501`).
  - Select variant `m7.sol` and click **"Run Audit Pipeline"**.
  - Show the **Findings** tab populating with 4 verified findings:
    - `P0`: `_grant` reached via `handOver`
    - `P1`: `setOwner` direct write
    - `S0`: Reentrancy in `withdraw`
    - `S1`: Unchecked low-level call in `refund`
  - Switch to the **Reachability Graph** tab:
    - Display the live Graphviz diagram: `handOver (Green Entry)` -> `CALLS` -> `_grant (Red Path)` -> `WRITES` -> `owner (Orange Privileged Sink)`.
    - Expand the formal Cypher proof below it.
- **Narrator**:
  > *"Notice finding P0. This is **Multi-Hop Reasoning** in action.*
  > 
  > *`_grant` is an internal function—an attacker cannot invoke it directly. However, Audit-Chain follows the call graph: public entry function `handOver` has no access control, and calls `_grant`, which writes the privileged state variable `owner`.*
  > 
  > *Next, observe our core differentiator: **The Verifier Gate**.*
  > *LLMs are notorious for hallucinating security vulnerabilities. Audit-Chain enforces an immutable rule: **No verified graph path, no finding**.*
  > 
  > *Every proposed finding is checked against FalkorDB. The entry must be unauthenticated, every consecutive node must have a real `CALLS` edge, and the exact path must have been emitted by an MCP tool during the session. If the agent hallucinates, the verifier gate rejects it."*

---

### [2:50 - 3:35] Scene 5: Actions Based on Graph State (Patch & Proof)
- **Visual on Screen**:
  - Navigate to the **Remediation Patch & Proof** tab.
  - Select finding `P0: Treasury._grant(address):Treasury.owner`.
  - Click **"Propose and Verify Patch"**.
  - Show the progress spinner: compilation -> re-ingestion into `audit_m7_patched` -> verification metrics.
  - Display the metrics:
    - `Compiled`: ✅
    - `Target Gone`: ✅
    - `Signatures Preserved`: ✅
    - `Score Delta`: `18 -> 7` (Major attack-surface drop)
  - Display the Unified Diff highlighting the addition of `onlyOwner` access control.
- **Narrator**:
  > *"Audit-Chain doesn't just diagnose—it takes concrete **actions based on what the graph reveals**.*
  > 
  > *When we trigger remediation, our blue-team patcher crafts a minimal, targeted fix. But unlike other AI tools that guess whether a patch works, Audit-Chain **proves it**.*
  > 
  > *It compiles the patched contract, ingests it into a new graph, and executes formal verification:*
  > 1. *It verifies the contract compiles with zero errors.*
  > 2. *It runs entry path queries to prove the exploit route is completely broken.*
  > 3. *It confirms all original public function signatures remain intact.*
  > 4. *And it calculates the Attack Surface Score, showing a measurable drop from 18 down to 7.*
  > 
  > *This is closed-loop, verifiable autonomous defense."*

---

### [3:35 - 4:00] Scene 6: The Adversarial Harness, Memory Graph & Conclusion
- **Visual on Screen**:
  - Switch to the **Evaluation Scoreboard** tab.
  - Show the table: Round 0 (100% Recall, 100% Precision, 100% Path Accuracy, 100% Patch Success), Round 2 (Held-out contracts `h1`-`h4`), and Round 3 (3x repeats).
  - Show terminal output showing `23 passed in 28.14s`.
  - Show closing slide with GitHub URL: `https://github.com/prze8969/Audit-chain`.
- **Narrator**:
  > *"To ensure bulletproof reliability, Audit-Chain includes a built-in adversarial Red-Team / Blue-Team benchmark harness.*
  > 
  > *Tested across 8 mutation variants and 4 held-out contracts with multi-hop reentrancy and inline guards, Audit-Chain achieved a perfect **100% recall, 100% precision, 100% path accuracy, and 100% patch success rate**.*
  > 
  > *Plus, with its **Audit Memory Graph**, past verified patches are stored as graph patterns to accelerate future audits.*
  > 
  > *Audit-Chain: Where connected data meets autonomous smart contract security. Check out the open-source repository on GitHub today!"*
