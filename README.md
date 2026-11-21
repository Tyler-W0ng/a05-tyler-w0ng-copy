# CS279 A05

The assignment handout is in [HANDOUT.md](HANDOUT.md), and the report format
is in [FINDING_REPORT.md](FINDING_REPORT.md). Run the AgentLab stack using the
commands in [AGENTLAB.md](AGENTLAB.md). The course preflight checker is
available with `python3 .cs279/preflight.py`.

## Analysis MCP servers

Static and dynamic analysis run in separate containers. The static service is
built from `mcp-static/` and serves `http://mcp:8000/mcp`; the dynamic service
is built from `mcp-dynamic/` and serves `http://mcp-dynamic:8001/mcp`.
Each checks out exact GitHub commits into its own temporary workspace. A path
returned by one service is not valid in the other.

The static service wraps Semgrep and CodeQL. Its `static_checkout` tool fetches
the pinned repository commit. `scan_semgrep` returns structured rule IDs,
locations, messages, and source excerpts. `codeql_create_database` builds a
checkout and creates a reusable database; `codeql_analyze` runs one of the
bundled C/C++ suites or a selected query. CodeQL results include rule locations
and available data-flow paths. The full SARIF report remains in the service's
temporary workspace, so export anything needed after the container stops.

With `STATIC_ENABLED=true` and `AGENT_ENABLED=true`, reconnaissance runs the
security specialist using `PROMPTS["security"]`. The model receives the static
checkout path and build command, calls Semgrep first, and can create and analyze
a CodeQL database. Observed scanner findings feed the existing investigator;
the model's summary is not used as a substitute for scanner output.
The conversation, actual MCP tool calls, arguments, results, and runner errors
are saved in `output/items/<target-id>/static-analysis.json`. A run with no
Semgrep call records an explicit error. `AGENT_ENABLED=false` retains direct,
model-free static scanning; `STATIC_ENABLED=false` skips static analysis.
The bundled `mock-model` only supports the legacy processing tools, so use a
model supporting tool calls for security analysis.

Run the security-agent integration tests without external services:

```bash
cd agent
.venv/bin/python -m unittest discover -s tests -v
```

The dynamic service provides `dynamic_checkout`, `dynamic_build` (Clang with
AddressSanitizer and UndefinedBehaviorSanitizer), `dynamic_run` (bounded command
and optional stdin), and `dynamic_fuzz` (bounded existing harness command).
Results include exit status, captured output, sanitizer indicators, crashing
input paths, and coverage counters when present in the harness output.

Start the MCP services and run the CodeQL smoke test with:

```bash
docker compose --profile mcp up -d --build mcp mcp-dynamic
docker compose --profile mcp exec mcp codeql version
docker compose --profile mcp exec -T mcp python - < mcp-static/smoke_codeql.py
```

The MCP implementation supplies the static and dynamic analysis tools. The
agent's planning/reporting flow and the assignment's independent clean-checkout
validation are separate work and are not claimed as completed here.
