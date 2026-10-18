---
title: Audit-Chain
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# Deploying Audit-Chain to Hugging Face Spaces (Docker SDK)

**Graph-powered smart-contract audits you can trace and prove.**

Audit-Chain runs as a self-contained container packaging **FalkorDB**, **Solidity compiler (solc 0.8.19)**, and the **Streamlit** audit interface.

---

## 1. Create a New Hugging Face Space

1. Go to [huggingface.co/new-space](https://huggingface.co/new-space).
2. Space Name: `Audit-chain` (or your choice).
3. Select License: `mit` or `apache-2.0`.
4. **Space SDK**: Choose **Docker** (Blank template).
5. Hardware: **Free CPU (2 vCPU, 16 GB RAM)** is fully sufficient.

> **Note on Free/Static Spaces**: If your Space was created as a "Static" space, go to **Settings -> Space hardware** or re-create it selecting **Docker SDK**. Docker SDK is required to run the embedded FalkorDB graph engine and Python runtime.

---

## 2. Configure Environment Variables (Settings -> Variables and Secrets)

Under **Settings -> Variables and Secrets**:

### Public Variables or Secrets:
| Key | Example Value | Description |
|---|---|---|
| `LLM_API_KEY` | `gsk_...` | Groq / OpenAI API Key for agent tool calling |
| `LLM_BASE_URL` | `https://api.groq.com/openai/v1` | OpenAI-compatible endpoint |
| `AGENT_MODEL` | `qwen/qwen3.8-27b` | Model name |
| `LLM_MIN_INTERVAL`| `2.5` | Rate-limit delay between calls (seconds) |
| `LLM_CACHE` | `1` | Cache responses to replay sample audits instantly |
| `AUDIT_GRAPH` | `audit_m7` | Default graph name |

> **Offline Fallback**: If `LLM_API_KEY` is omitted, the app automatically runs in **deterministic offline mode** using full graph reasoning without requiring any external API calls.

---

## 3. Push Repository to Hugging Face Space

From your local project directory:

```bash
# Add Hugging Face Space remote
git remote add space https://huggingface.co/spaces/prze8969/Audit-chain

# Stage Docker configuration and commit
git add Dockerfile start.sh .dockerignore app.py src/ DEPLOY.md
git commit -m "Configure Hugging Face Space Docker container"

# Push to Hugging Face Space main branch
git push space main -u
```

---

## 4. Build Time and Reading Build Logs

- **Expected Build Time**: ~2 to 4 minutes on Hugging Face's container builders.
- **Watching Build Logs**:
  1. Open your Space page (`https://huggingface.co/spaces/prze8969/Audit-chain`).
  2. Click the **"Building"** or **"Logs"** button in the top status bar.
  3. You will see:
     - FalkorDB layer initialization
     - `apt-get` installation of Python 3 and Graphviz
     - `solc-select install 0.8.19`
     - Redis / FalkorDB startup (`PONG`)
     - `streamlit run app.py --server.port 7860`
  4. Once logs show `Streamlit app ready at http://0.0.0.0:7860`, the Space switches to **Running**.
