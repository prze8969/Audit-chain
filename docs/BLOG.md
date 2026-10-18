# Audit-Chain: giving a smart-contract auditor a map it can prove.

*Graph-powered smart-contract audits you can trace and prove.*

---

## 1. The Core Problem in Smart Contract Security

Every smart contract engineer is familiar with the noise problem of static analysis tools. Standard linters and AST analyzers flag hundreds of warnings: "Low-level call used", "State variable written without event", "Reentrancy detected".

Yet, when a human auditor reviews the contract, 85% of these alerts turn out to be unreachable dead code, internal functions protected by higher-level modifiers, or completely benign patterns.

**The fundamental missing link is attacker reachability.**
A bug is only an exploit if an unprivileged attacker can trigger it from an external transaction. If there is no callable route from `msg.sender` to the vulnerable line of code, the issue cannot drain funds.

---

## 2. The FalkorDB Code Graph Solution

We built **Audit-Chain** to model Solidity contracts as directed code knowledge graphs in **FalkorDB**:

- **Function Nodes**: Id, visibility, mutability, entry status, and access-control guards.
- **StateVar Nodes**: Declared variables and privileged flags (`owner`, `admin`, `governance`).
- **CALLS Edges**: Internal and external call paths connecting dispatch points.
- **WRITES & READS Edges**: Data-flow interaction between logic and storage.

```
(Attacker Entry: handOver) ---[:CALLS]---> (Internal: _grant) ---[:WRITES]---> (Privileged: owner)
```

With FalkorDB, complex reachability questions become clean Cypher path queries:

```cypher
MATCH p = (e:Function {is_entry: true, guarded: false})-[:CALLS*1..6]->(t:Function {id: $id})
WITH p, length(p) AS len
RETURN [n IN nodes(p) | n.id] AS path ORDER BY len LIMIT 3
```

---

## 3. The Verifier Gate: No Path, No Finding

Large Language Models excel at code reasoning but are notoriously prone to hallucinating vulnerability reports and nonexistent exploit chains.

Audit-Chain enforces a strict **Verifier Gate** before any finding enters the audit report:
1. **Node Validation**: The targeted function and finding must exist in the FalkorDB schema.
2. **Reachable Proof**: If claimed reachable, the path must start at an unguarded entry function, terminate at the target, and every step must have a verified `CALLS` edge in the graph.
3. **Trace Grounding**: The exact path must have been emitted by an MCP tool during the session.

If any check fails, the finding is discarded into the rejected log.

---

## 4. The Adversarial Red-Team / Blue-Team Harness

To validate the agent under real pressure, we constructed an automated mutation and held-out test harness:
- **Red Team**: Injects reentrancy, privileged write bypasses, and unchecked call flaws across 8 contract variants (`clean`, `m1` to `m7`) and 4 held-out contracts (`h1` to `h4`).
- **Blue Team**: Autonomously produces minimal patches and re-ingests the patched contract into a new graph (`audit_<project>_patched`).
- **Scoreboard Proof**: Mathematically proves that:
  - The vulnerable target is gone.
  - No new vulnerabilities were introduced.
  - All public function signatures are preserved.
  - The attack surface score dropped.

### Results:
- **Recall**: 100% across all variants and held-out test suites.
- **Precision**: 100% (zero false positives on negative controls like `h4` and `clean`).
- **Path Accuracy**: 100% match with ground truth exploit paths.
- **Patch Success Rate**: 100% verified remediation with attack surface score reduction.

---

## 5. What We Learned & What Comes Next

During development, local adversarial checks in `BUGS.md` caught subtle edge cases:
- Variable-length Cypher queries in FalkorDB requiring aliased projections for ordering.
- Function parameter inspection falsely categorizing functions passing `msg.sender` as arguments as access-controlled.

By coupling graph theory with Model Context Protocol (MCP) agents, we move from speculative vulnerability guessing to mathematical, explainable exploit proofs.
