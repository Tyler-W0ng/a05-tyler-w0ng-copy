# Contributions

- **danielc-285 (Daniel Chang):** implemented the static MCP pinned-commit
  checkout and aligned its container with the `mcp-static/` handout layout;
  added the separate dynamic MCP for pinned checkout, ASan/UBSan builds,
  bounded execution, and bounded fuzzing; updated Compose and service
  documentation; built and exercised both MCPs in service-level smoke checks.

- **Karthik Bhattaram:** added Semgrep installation, bundled C rules, and the
  `scan_semgrep` MCP tool with an agent tool wrapper; fixed Semgrep's settings
  storage permissions in the container. Added the CodeQL CLI and query packs,
  MCP tools for C/C++ database creation and analysis, bounded execution and
  SARIF finding extraction, agent tool wrappers, a use-after-free smoke-check
  script, and a query-path fix. Added the security specialist prompt and wired
  its tool-calling loop into the analysis pipeline, recording actual tool
  calls, results, and transcripts while preserving model-free scanning for
  ablation runs; added tests for tool execution, failures, timeouts, and
  pipeline integration, and documented the static-analysis workflow.

The agent orchestration, static-guided planning, and independent replay
validation are being handled by the other group members and are not credited
as completed in Daniel's contribution entry.
