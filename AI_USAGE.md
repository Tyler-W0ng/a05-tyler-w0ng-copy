# AI usage

- **OpenAI Codex (GPT-6):** assisted with the static MCP's pinned GitHub
  checkout tool, the separate dynamic MCP's checkout/build/run/fuzz tools,
  Compose wiring, and this documentation. Codex also helped inspect target
  metadata and construct the MCP smoke checks.
- **Verification:** built both MCP images; checked Compose configuration and
  Python syntax; listed the tools served by each MCP; checked static checkout
  and Semgrep results on a pinned development target; and checked dynamic
  checkout, ASan/UBSan build, and a stdin sanitizer trigger through the dynamic
  MCP. A prior CodeQL smoke test checked that CodeQL could report a use-after-
  free in a small test program. These are MCP-level checks only; they do not
  verify the agent pipeline, independent finding validation, or full
  development-set performance.

AI-generated code and descriptions were reviewed against the handout and the
service outputs. No full-assignment results, independent replay results, or
unobserved findings are claimed in this report.
