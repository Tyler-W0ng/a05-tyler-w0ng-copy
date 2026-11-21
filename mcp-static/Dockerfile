FROM python:3.13-slim

# The bundle includes the CLI and precompiled query packs for offline use.
ARG CODEQL_VERSION=2.20.7
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates zstd build-essential git libsqlite3-dev \
 && curl -fL --retry 3 "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.zst" \
    | tar --zstd -xf - -C /opt \
 && /opt/codeql/codeql version \
 && rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/codeql:${PATH}"

# MCP Python SDK 2.x, where the server class is MCPServer, at
# mcp.server.mcpserver. 1.x called it FastMCP and put it elsewhere.
# Pillow is the image parser - the reason this server is in a box at all.
RUN pip install --no-cache-dir "mcp>=2.2,<3" "pillow>=11" semgrep \
 && useradd --create-home --uid 1000 mcp

WORKDIR /app
COPY server.py .
COPY codeql_tools.py .
COPY source_tools.py .
USER mcp
EXPOSE 8000
CMD ["python", "server.py"]

# Add semgrep rules to container
COPY rules/ /app/rules/

# Redirect settings to writeable storage
ENV HOME=/tmp \
    SEMGREP_SETTINGS_FILE=/tmp/semgrep/settings.yml
