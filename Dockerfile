# Audit-Chain: Graph-powered smart-contract audits you can trace and prove.
FROM falkordb/falkordb:latest

USER root

# Install system dependencies (Python, venv, git, graphviz for visualization, passwd for user management)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    graphviz \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Create working directory and set permissions
WORKDIR /app

# Create virtualenv and install solc-select + solc 0.8.19
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python requirements and solc compiler at build time
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && solc-select install 0.8.19 \
    && solc-select use 0.8.19 \
    && ln -sf /opt/venv/.solc-select/artifacts/solc-0.8.19/solc-0.8.19 /usr/bin/solc

# Copy project files
COPY . /app/

# Make startup script executable and configure non-root user (appuser uid 1000)
RUN chmod +x /app/start.sh \
    && useradd -m -u 1000 appuser \
    && chown -R appuser:appuser /app /opt/venv /var/lib/falkordb

# Environment settings for Hugging Face Spaces & Streamlit
ENV BROWSER=0 \
    PORT=7860 \
    FALKORDB_HOST=127.0.0.1 \
    FALKORDB_PORT=6379 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/appuser

# Switch to non-root appuser
USER appuser

EXPOSE 7860

ENTRYPOINT ["/app/start.sh"]
