# 🎬 Demo Video Script: Audit-Chain (2:30)

**Track**: Track 01 (Agents That Act on Connected Data)  
**Product**: Autonomous Graph Security Agent with Proof-of-Reachability & Patch Remediation

---

### [0:00 - 0:25] The Problem
- **Visual**: Show traditional static analysis output with 20+ alerts on a smart contract.
- **Narrator**: *"Every smart contract engineer is drowning in false positives. Static analyzers flag potential bugs everywhere, but they cannot tell you the most crucial fact: can an unprivileged attacker actually reach the vulnerable code?"*
- **Visual**: Highlight the difference between unreachable dead code and a multi-hop exploit route.

---

### [0:25 - 0:50] Graph Ingestion & FalkorDB
- **Visual**: Upload `m7.sol` in the Streamlit UI; switch to FalkorDB Browser at `localhost:3000` showing `audit_m7` graph.
- **Narrator**: *"Audit-Chain changes this by ingesting the contract's AST into FalkorDB as a directed call graph. Functions, state variables, read/write dependencies, and external calls become first-class graph elements. Multi-hop attacker reachability is no longer a guess—it's a Cypher traversal."*

---

### [0:50 - 1:20] Autonomous MCP Tool Selection & The Verifier Gate
- **Visual**: Show `reports/trace_m7.jsonl` and the terminal logs as the agent selects FastMCP tools: `graph_summary`, `unguarded_privileged_writers`, `entry_paths_to`, and `rank_findings`.
- **Narrator**: *"The autonomous agent discovers 9 MCP tools, calculates PageRank hotspots, and probes reachability for each finding. Crucially, every finding must pass the Verifier Gate: no verified graph path, no finding in the final report."*

---

### [1:20 - 1:55] Multi-Hop Path Prover & Patch Remediation
- **Visual**: In the Streamlit app, switch to the 'Reachability Graph' tab. Show the highlighted path from entry `handOver` to internal `_grant` to state variable `owner`.
- **Narrator**: *"Here is finding P0: an attacker enters through handOver, hops internally to _grant, and overwrites the contract owner. Audit-Chain renders the full call chain and outputs the formal Cypher proof."*
- **Visual**: Click 'Propose and Verify Patch'. Show the unified diff and the attack surface score drop from 18 to 7.
- **Narrator**: *"The blue-team patcher applies a minimal fix, compiles it, re-ingests into a new graph, and proves that the target vulnerability is eliminated while public signatures remain preserved."*

---

### [1:55 - 2:30] Adversarial Scoreboard & Memory Graph
- **Visual**: Show the Scoreboard tab with Rounds 0, 2, and 3. Show `audit_memory` storing successful patches.
- **Narrator**: *"Our built-in red-team/blue-team harness validates the system against 8 mutation variants and 4 held-out contracts, achieving 100% recall, 100% precision, and 100% path accuracy. With audit memory graph integration, past verified fixes continuously train future patch recommendations."*
- **Visual**: Final slide with GitHub repo link and Track 01 submission details.
