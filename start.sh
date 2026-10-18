#!/bin/bash
set -e

echo "=== Starting Audit-Chain Container (FalkorDB + Streamlit) ==="
echo "=== Graph-powered smart-contract audits you can trace and prove. ==="
# Ensure data directory exists
mkdir -p /var/lib/falkordb/data

# Start Redis + FalkorDB module in the background (exact command from run.sh)
redis-server --protected-mode no \
    --dir /var/lib/falkordb/data \
    --loadmodule /var/lib/falkordb/bin/falkordb.so \
    MAX_QUEUED_QUERIES 25 TIMEOUT 1000 RESULTSET_SIZE 10000 &
DB_PID=$!

echo "Waiting for FalkorDB to be ready on port 6379..."
MAX_WAIT=30
WAITED=0
DB_UP=0

while [ $WAITED -lt $MAX_WAIT ]; do
    if redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null | grep -q "PONG"; then
        DB_UP=1
        echo "FalkorDB is online and responding to PING! (waited ${WAITED}s)"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

if [ $DB_UP -ne 1 ]; then
    echo "ERROR: FalkorDB failed to start within ${MAX_WAIT} seconds." >&2
    kill $DB_PID 2>/dev/null || true
    exit 1
fi

echo "=== Launching Streamlit Application ==="
PORT="${PORT:-7860}"
exec streamlit run app.py \
    --server.port "${PORT}" \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.enableCORS false \
    --server.enableXsrfProtection false
