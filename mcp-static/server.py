"""Static analysis and demo processing tools behind MCP in their own container.

The agent's specialists call these over Streamable HTTP at
http://mcp:8000/mcp. Each tool receives an item's content and returns a fact
about it:

    process_text(text)                 how many characters
    process_image(data)                width, height and format
    process_binary(data, algorithm)    a hash of the bytes

Semgrep scans source with bundled rules. CodeQL can build C/C++ source under
/tmp, create a database, and run bundled query suites on it. Build commands
execute target code, so these operations remain in the tool container. Its
root filesystem is read-only, with writable temporary storage, no Linux
capabilities, no runtime internet route, and no model credentials.

Bytes cross the wire as base64 inside the JSON-RPC call. They never pass
through a language model: the agent's specialist decides *to* call a tool, and
the graph supplies the bytes (agent/app/specialists.py).
"""

import base64
import asyncio
import binascii
import hashlib
import io
import json
import subprocess
from pathlib import Path
from typing import Literal

from codeql_tools import create_database, analyze_database
from source_tools import checkout as checkout_source

from mcp.server.mcpserver import MCPServer
from PIL import Image, UnidentifiedImageError
from starlette.requests import Request
from starlette.responses import JSONResponse

# In mcp 2.x this class is MCPServer; it was called FastMCP in 1.x.
server = MCPServer(name="agentlab-static-analysis", version="2.1.0")


# A cap on what one call may ask this server to hold in memory. Inputs are
# untrusted; so is their size.
MAX_BYTES = 8 * 1024 * 1024


@server.tool()
async def static_checkout(repository: str, commit: str) -> dict:
    """Fetch the exact target commit into this static MCP's private /tmp workspace."""
    return await asyncio.to_thread(checkout_source, repository, commit)


@server.tool()
def read_source(target_path: str, file: str, line_start: int, line_end: int | None = None) -> dict:
    """Read at most 41 lines around a finding from a static checkout."""
    root = Path(target_path).resolve()
    if not root.is_relative_to(Path('/tmp/static-work')) or not root.is_dir():
        return {"error": "target_path must be a static checkout"}
    source = Path(file)
    if not source.is_absolute():
        source = root / source
    source = source.resolve()
    if not source.is_relative_to(root) or not source.is_file():
        return {"error": "file must be inside the static checkout"}
    if line_start < 1:
        return {"error": "line_start must be positive"}
    first = max(1, line_start - 20)
    last = min(max(line_end or line_start, line_start) + 20, first + 40)
    lines = source.read_text(errors="replace").splitlines()
    return {"file": str(source.relative_to(root)), "line_start": first,
            "line_end": min(last, len(lines)),
            "text": "\n".join(f"{i}: {lines[i-1]}" for i in range(first, min(last, len(lines)) + 1))}


def _decode(data: str) -> bytes | dict:
    """base64 -> bytes, or an error dict the caller can return as-is."""
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        return {"error": f"data is not valid base64: {exc}"}
    if len(raw) > MAX_BYTES:
        return {"error": f"item is {len(raw)} bytes; the limit is {MAX_BYTES}"}
    return raw

@server.tool()
async def codeql_create_database(
    target_path: str, build_command: str = 'make -B', timeout_seconds: int = 600,
) -> dict:
    """Build a C/C++ source checkout under /tmp and create a reusable CodeQL database.

    build_command runs inside the source directory and must recompile the code.
    Returns database_path for codeql_analyze. Does not clone the target.
    """
    return await asyncio.to_thread(create_database, target_path, build_command, timeout_seconds)


@server.tool()
async def codeql_analyze(
    database_path: str,
    suite: Literal['code-scanning', 'security-extended', 'security-and-quality'] = 'security-extended',
    timeout_seconds: int = 600,
    query: str | None = None,
) -> dict:
    """Run a bundled C/C++ query suite on an existing CodeQL database.

    Returns rules, locations, data-flow paths when available, and a SARIF artifact
    path. Warnings require dynamic validation; these are not confirmed bugs.

    query optionally selects one relative .ql file in the bundled cpp-queries
    pack instead of the entire suite.
    """
    return await asyncio.to_thread(analyze_database, database_path, suite, timeout_seconds, query)


@server.tool()
def scan_semgrep(target_path: str) -> dict:
    """Scan source code in continer using semgrep rules"""
    try:
        result = subprocess.run(
            [
                "semgrep", "scan",
                "--config", "/app/rules",
                "--json",
                "--metrics=off",
                target_path,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"error": "Semgrep expired"}

    return {
        "exit_code": result.returncode,
        "results": json.loads(result.stdout) if result.stdout.strip() else {},
        "stderr": result.stderr,
    }

@server.tool()
def process_text(text: str) -> dict:
    """Count the characters in a piece of text.

    Characters, not bytes: 'café' is 4 characters and 5 bytes of UTF-8.

    Args:
        text: The text to measure.
    """
    return {"characters": len(text),
            "bytes": len(text.encode("utf-8")),
            "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0)}


@server.tool()
def process_image(data: str) -> dict:
    """Report an image's size in pixels, and its format.

    Args:
        data: The image file's bytes, base64-encoded.
    """
    raw = _decode(data)
    if isinstance(raw, dict):
        return raw
    try:
        # `open` reads the header only, which is all the size needs - and is
        # why a decompression bomb costs nothing here until someone calls
        # .load(). Pillow's MAX_IMAGE_PIXELS guard backs that up.
        with Image.open(io.BytesIO(raw)) as image:
            width, height = image.size
            return {"width": width, "height": height,
                    "format": image.format, "mode": image.mode,
                    "bytes": len(raw)}
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        return {"error": f"not a readable image: {exc}", "bytes": len(raw)}


@server.tool()
def process_binary(data: str,
                   algorithm: Literal["sha256", "sha1", "md5"] = "sha256") -> dict:
    """Hash a block of binary data.

    Args:
        data: The bytes to hash, base64-encoded.
        algorithm: Which hash. Defaults to sha256; md5 and sha1 are offered
            for matching older systems, not for anything that must resist
            tampering.
    """
    raw = _decode(data)
    if isinstance(raw, dict):
        return raw
    return {"algorithm": algorithm,
            "hash": hashlib.new(algorithm, raw).hexdigest(),
            "bytes": len(raw)}


@server.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    """For the compose healthcheck. Not part of MCP, and not an MCP tool."""
    return JSONResponse({"status": "ok"})


if __name__ == "__main__":
    # 0.0.0.0 because the agent reaches it as `mcp`, from another container.
    # Its exposure is set by compose.yaml: `internal` only, no published port.
    server.run("streamable-http", host="0.0.0.0", port=8000)
