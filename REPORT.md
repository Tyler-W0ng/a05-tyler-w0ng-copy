# A05 progress report: analysis MCP services

> **Status:** This report records the MCP implementation and its service-level
> checks. It is not the final assignment report. The agent strategy,
> independent clean-checkout replay, full development-set evaluation, and
> ablations are still pending integration by the other group members.

## Architecture implemented

The static analyzer runs as the `mcp` Compose service from `mcp-static/`.
`static_checkout` fetches a repository at a full pinned commit into a
service-local temporary directory. The existing Semgrep and CodeQL tools
analyze source in that workspace and return structured results. The container
has a read-only root filesystem, no added capabilities, and outbound network
access for fetching the target commit.

The dynamic analyzer runs separately as `mcp-dynamic` from `mcp-dynamic/`.
Its tools check out the same kind of pinned target into a different private
temporary directory, compile with Clang and ASan/UBSan, run a bounded command
with optional stdin, and run a bounded fuzz command. The tool results include
process status, captured output, sanitizer indicators, and available crash
file and coverage observations. Dynamic builds and executions occur inside the
dynamic MCP container, which has a read-only root, no added capabilities, and
temporary executable storage.

The MCP tools are present, but this change does not implement the agent's
static-guided plan, finding deduplication, report writing, or independent
validation. The assignment's full flow is not complete until those pieces are
connected and checked together.

## Service-level results

Both service images built and exposed their intended MCP tools. On the pinned
`d-02` development target, the static checkout and Semgrep scan succeeded and
Semgrep returned two potential results. The dynamic checkout and sanitizer
build succeeded; a stdin input triggered an AddressSanitizer report. This
confirms the MCP service path can perform each operation on that target. It
does not establish that either static result is a true vulnerability or that
the trigger passes the assignment's independent clean-checkout replay.

Compose configuration, Python syntax compilation, and `git diff --check` were
also clean. The services were exercised directly through their MCP interface.
No full agent run, complete development-set run, runtime/cost comparison, or
finding-schema/replay evaluation was performed for this MCP-only change.

## Ablations and discussion

The required ablations have not been run: there is no integrated pipeline yet
to compare with static analysis removed or with the agent removed. The MCP
smoke check only tests service boundaries and tool behavior; it cannot measure
whether static results improve target selection, whether dynamic analysis
confirms root causes, or how often the pipeline reports false positives.

The separation gives static scanning and dynamic execution distinct workspaces
and runtime environments. The current tools rely on the caller to provide
build, run, and fuzz commands. They do not independently rebuild and replay a
candidate finding. The final report should replace this progress account with
integrated development-set outcomes, ablations, validation results, costs, and
limitations after the agent and reproduction phases are complete.
