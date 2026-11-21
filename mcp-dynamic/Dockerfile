FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git build-essential clang libclang-rt-19-dev \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "mcp>=2.2,<3" \
 && useradd --create-home --uid 1000 mcp

WORKDIR /app
COPY server.py dynamic_tools.py ./
USER mcp
EXPOSE 8001
CMD ["python", "server.py"]
