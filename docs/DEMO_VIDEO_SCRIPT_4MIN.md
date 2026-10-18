# 🎬 4-Minute Demo Video Script: Audit-Chain Walkthrough
**Track**: Track 01 (Agents That Act on Connected Data)  
**Project**: Audit-Chain: Autonomous Graph Security Agent with Proof-of-Reachability & Automated Remediation  
**Target Duration**: 4:00 (240 Seconds)  
**Interface**: Guided Judge Stepper (`Slide 0` through `Slide 6`)

---

## ⏱️ Timeline Overview

| Timestamp | Slide | Focus Area | Key Visual Action |
| :--- | :--- | :--- | :--- |
| **0:00 – 0:35** | **Slide 0: Preface** | Problem vs. Connected Solution | Show 50/50 comparison cards, click *Start Guided Walkthrough* |
| **0:35 – 1:15** | **Step 1: Inspect Code** | Proving bugs are real, not hardcoded | Select `m7: Owner Takeover`, toggle engine, inspect Solidity code |
| **1:15 – 1:55** | **Step 2: Code Graph** | FalkorDB In-Memory Graph AST | Drag nodes, show Public Entries, Internal Calls, State Sinks |
| **1:55 – 2:35** | **Step 3: Reasoning & Gate** | Real-time Cypher & Verifier Gate | 4 Hero Metrics, Surface Score, Blocked Hallucinations |
| **2:35 – 3:15** | **Step 4: Exploit Route** | Multi-hop attacker call path proof | Hop sequence cards, isolated path subgraph, Cypher proof |
| **3:15 – 3:45** | **Step 5: Patch & Merge Diff**| Patch synthesis & GitHub merge diff | Click Synthesize, show 4 checkmarks & green/red diff |
| **3:45 – 4:00** | **Step 6: Conclusion** | Track 01 summary & thank you | Highlight 100% benchmark accuracy, thank judges |

---

## 🎙️ Step-by-Step Script & Narration

### [0:00 – 0:35] Slide 0: Product Preface
- **On Screen**:
  - Web app opens on **Slide 0: Preface**.
  - Display the symmetrical comparison deck: `❌ Traditional Static Linters` on the left vs `✅ Audit-Chain Graph Intelligence` on the right.
  - Hover cursor over the key problem points (90% false positives, missed multi-hop calls).
- **Spoken Narration**:
  > *"Hello hackathon judges! Every smart contract developer and auditor knows the nightmare of static analysis today: endless noise.*
  > 
  > *Traditional linters scan flat syntax and flag dozens of theoretical warnings. But they fail to answer the single question that actually matters:*
  > 
  > ***Can an external attacker actually reach this bug from an unauthenticated transaction?***
  > 
  > *If flawed code is trapped behind private internal functions or protected by modifiers, it is harmless. But if there is an unbroken call chain from `msg.sender` straight into that sink, funds will be stolen.*
  > 
  > *Welcome to **Audit-Chain**: an autonomous security agent powered by **FalkorDB** that transforms smart contracts into connected knowledge graphs to mathematically prove reachability, eliminate hallucinations, and synthesize verified patches.*
  > 
  > *Let's start the guided walkthrough."*
- **Action**: Click the blue **"🚀 Start Guided Walkthrough ➔"** button.

---

### [0:35 – 1:15] Step 1: Select Target Contract & Inspect Code
- **On Screen**:
  - The screen glides into **Step 1: Inspect Target Contract**.
  - Show the 4 large selection cards: `m7: Owner Takeover`, `m3: Reentrancy Attack`, `m2: Missing Auth`, and `clean: Verified Secure`.
  - Click on `m7: Owner Takeover` (shows active green checkmark and glowing border).
  - Point out the 2 execution engine tiles: `⚡ In-Memory Cypher Engine` and `🧠 Autonomous Agent`.
  - Scroll through lines 25–35 of the Solidity source code on the right.
- **Spoken Narration**:
  > *"First, as judges, we want you to inspect the real contract code to prove this is a live, dynamic audit—not a hardcoded demo.*
  > 
  > *We provide 4 benchmark contract variants ranging from reentrancy to access control bypasses and verified secure contracts. Today, we'll inspect **m7: Privileged Owner Takeover**.*
  > 
  > *Look at lines 31 through 34 of the Solidity code:*
  > 
  > *The attacker invokes a public function called `handOver()`. Notice that `handOver()` doesn't modify state directly; instead, it jumps internally into `_grant()`, which mutates the privileged state variable `owner`.*
  > 
  > *Traditional linters miss this because `_grant()` is marked internal. But in a graph database, these functions are connected."*
- **Action**: Click **"Next: Step 2 — Ingest into FalkorDB Graph ➔"**.

---

### [1:15 – 1:55] Step 2: FalkorDB Code Knowledge Graph
- **On Screen**:
  - The screen glides to **Step 2: FalkorDB Code Knowledge Graph**.
  - Highlight the clean badge legend above the graph:
    `🟢 Public Entry Points` • `⚡ Internal Functions` • `🔑 Privileged Sinks (owner)` • `💰 State Variables (balances)`.
  - The large, high-contrast graph canvas renders immediately with large box nodes.
  - Click and drag a node to demonstrate live physics; hover over `🔓 handOver()` and `🔑 owner`.
- **Spoken Narration**:
  > *"Behind the scenes, Audit-Chain compiles the Solidity AST using `solc 0.8.19` and ingests the contract directly into an in-memory graph inside **FalkorDB**.*
  > 
  > *Notice how the code is now represented as connected data:*
  > - *Green nodes represent **Public Entry Points** exposed to unauthenticated callers.*
  > - *Purple nodes represent **Internal Functions** dispatched inside the contract.*
  > - *The orange node is `owner`, our **Privileged Storage Sink**.*
  > - *Pink directed arrows represent function `CALLS`, while orange dashed arrows represent persistent storage `WRITES`.*
  > 
  > *Finding an exploit is no longer regex guesswork—it is graph traversal in Redis memory."*
- **Action**: Click **"Next: Step 3 — Run Autonomous Agent & Verify ➔"**.

---

### [1:55 – 2:35] Step 3: Real-Time Reasoning & The Verifier Gate
- **On Screen**:
  - The screen glides to **Step 3: Real-Time Reasoning & Verifier Gate**.
  - Show the 4 Hero Metric boxes:
    - **Attack Surface Score**: `18`
    - **Verified Findings**: `4`
    - **Reachable Paths**: `4`
    - **Blocked Claims**: `0` (Zero Hallucinations)
  - Point to the Real-Time Traversal explanation card on the left, and scroll the findings table on the right.
- **Spoken Narration**:
  > *"In Step 3, our agent queries FalkorDB in real time using standardized Cypher path traversal.*
  > 
  > *Look at the top metrics:*
  > - *Our contract has an **Attack Surface Score of 18**, calculated from unguarded state writes and reachable public entry points.*
  > - *We have **4 verified findings**, and all 4 have proven unbroken call paths.*
  > 
  > *Now notice the fourth metric: **Blocked Claims**.*
  > *LLMs are notorious for hallucinating security vulnerabilities. Audit-Chain introduces **The Verifier Gate**: an immutable formal check against FalkorDB graph topology.*
  > 
  > *If an agent proposes a vulnerability that lacks a continuous, unbroken path from an unauthenticated entry into that sink, the Verifier Gate immediately discards it. Result: zero hallucinations."*
- **Action**: Click **"Next: Step 4 — Multi-Hop Exploit Route ➔"**.

---

### [2:35 – 3:15] Step 4: Multi-Hop Attacker Call Path Proof
- **On Screen**:
  - The screen glides to **Step 4: Multi-Hop Exploit Route Proof**.
  - Point to the 3 sequential step cards across the top:
    `1. Attacker Entry (Public): Treasury.handOver` ➔ `2. Internal Dispatch: Treasury._grant` ➔ `⚠️ Mutates Privileged State: Treasury.owner`.
  - Show the isolated path sub-graph in the middle.
  - Expand the **Formal Cypher Reachability Proof** dropdown and show the Cypher query.
- **Spoken Narration**:
  > *"Step 4 shows the mathematical exploit proof that traditional linters fail to discover: a **Multi-Hop Exploit Route**.*
  > 
  > *Here is the exact attacker execution sequence:*
  > 1. *The attacker calls `handOver()` from `msg.sender`—an unauthenticated public entry point.*
  > 2. *`handOver()` dispatches an internal call into `_grant()`.*
  > 3. *`_grant()` executes a persistent storage write directly into `owner`.*
  > 
  > *In the box below, you see the isolated sub-graph and the exact Cypher query: `MATCH p=(e:Function {is_entry:true, guarded:false})-[:CALLS*1..6]->(t) RETURN p`.*
  > 
  > *This is deterministic mathematical proof that any external user can take over ownership of this contract."*
- **Action**: Click **"Next: Step 5 — Synthesize Patch & Merge Diff ➔"**.

---

### [3:15 – 3:45] Step 5: Automated Patch Remediation & GitHub Merge Diff
- **On Screen**:
  - The screen glides to **Step 5: Automated Patch & GitHub Merge Diff**.
  - Click the blue button: **"🩹 Synthesize Minimal Patch & Execute Proof"**.
  - Watch the spinner run for 2 seconds.
  - Highlight the 4 verification metrics that appear:
    - `Compiled (solc)`: **✅ Pass**
    - `Target Route`: **✅ Eliminated**
    - `Signatures Kept`: **✅ Intact**
    - `Attack Surface`: **18 ➔ 0**
  - Scroll down the **GitHub Merge Diff** on the right, pointing out the red line removed and green lines added.
- **Spoken Narration**:
  > *"Audit-Chain doesn't just diagnose exploits—it takes autonomous action on connected data.*
  > 
  > *Let's click 'Synthesize Minimal Patch & Execute Proof'.*
  > 
  > *In seconds, the agent synthesizes a minimal fix, recompiles with `solc`, re-ingests the patched contract into FalkorDB, and verifies the result:*
  > - *The contract compiles cleanly.*
  > - *The exploit route is **100% eliminated** from the graph.*
  > - *All public function signatures remain intact.*
  > - *And our Attack Surface Score drops from **18 to 0**.*
  > 
  > *On the right, you see a clean GitHub-style merge diff: red lines show the unprotected dispatch removed, and green lines show the secure `onlyOwner` access-control guard added."*
- **Action**: Click **"Next: Step 6 — Conclusion & Thank You ➔"**.

---

### [3:45 – 4:00] Step 6: Conclusion & Thank You
- **On Screen**:
  - The screen glides to **Step 6: Conclusion**.
  - Show the two symmetrical closing cards: `Why Connected Data Transforms Auditing` and `Track 01: Agents on Connected Data`.
  - Highlight the `100% Benchmark Accuracy` badge and the GitHub link.
- **Spoken Narration**:
  > *"By representing smart contracts as in-memory knowledge graphs rather than flat text, Audit-Chain achieves **100% precision, 100% recall, zero hallucinations, and verified automated patching**.*
  > 
  > *This is the true potential of **Track 01: Agents That Act on Connected Data**.*
  > 
  > *Thank you, judges! Our code is open source on GitHub at `github.com/prze8969/Audit-chain`. We invite you to test any variant yourself!"*
- **Action**: Fade to black / show repository URL.

---

## 💡 Recording Tips
1. **Resolution**: Record at 1080p (1920×1080) or 1440p (2560×1440) in full-screen browser mode.
2. **Pacing**: Follow the timestamps above; each slide has approximately 35–40 seconds of focused commentary.
3. **Smooth Clicks**: The interface has built-in gliding transitions (`glideIn`) between steps, so keep mouse movements deliberate and steady.
