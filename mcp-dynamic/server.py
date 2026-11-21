"""Dynamic analysis MCP: pinned checkout, sanitizer build, replay and fuzz."""
import asyncio

from dynamic_tools import checkout, build, run_input, fuzz
from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

server = MCPServer(name="agentlab-dynamic-analysis", version="1.0.0")


@server.tool()
async def dynamic_checkout(repository: str, commit: str) -> dict:
    """Clone a GitHub target at an exact commit into disposable /tmp storage."""
    return await asyncio.to_thread(checkout, repository, commit)


@server.tool()
async def dynamic_build(target_path: str, build_command: str = "make", timeout_seconds: int = 300) -> dict:
    """Build a checked-out target with AddressSanitizer and UBSan enabled."""
    return await asyncio.to_thread(build, target_path, build_command, timeout_seconds)


@server.tool()
async def dynamic_run(target_path: str, command: str, input_data: str = "", timeout_seconds: int = 10) -> dict:
    """Run a target command with optional stdin; return status and sanitizer evidence."""
    return await asyncio.to_thread(run_input, target_path, command, input_data, timeout_seconds)


@server.tool()
async def dynamic_fuzz(target_path: str, fuzz_command: str, timeout_seconds: int = 60) -> dict:
    """Run a bounded fuzzing campaign and report crashes and coverage observations."""
    return await asyncio.to_thread(fuzz, target_path, fuzz_command, timeout_seconds)


@server.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


if __name__ == "__main__":
    server.run("streamable-http", host="0.0.0.0", port=8001)
