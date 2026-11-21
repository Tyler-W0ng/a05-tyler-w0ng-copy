"""The harness: connect the tool servers, run the pipeline once, report.

    python -m app.run                     # every item in input/items/
    python -m app.run logo.png hello.txt  # just these

The pipeline (app/graph.py) does the work and writes one output per item,
through the local MCP server. This file is the boring half around it, and the
half that decides whether anyone can trust a run:

  1. **Startup fails loudly.** No processing server, no I/O server, no
     knowledge base when the mode promises one: the run stops before the
     first item rather than three items in.
  2. **Every item is accounted for.** Each one ends up in output/items/,
     processed or with its error. run.json lists them all, with the trace.
  3. **The run is bounded.** AGENT_MAX_ITEMS caps the batch and
     AGENT_MAX_STEPS caps each specialist; the graph's recursion limit is
     derived from both.
"""

import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone

from app import clients, config, graph, kb, tracing, trace as traceutil

log = logging.getLogger("agent")


def _root(exc: BaseException) -> BaseException:
    """The first real exception inside anyio's exception groups."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


async def _main(argv: list[str]) -> int:
    run_id = traceutil.start_run()
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    trace_dir = config.OUTPUT_DIR / "logs"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"agent-{run_id}.log"
    logging.basicConfig(
        level=config.LOG_LEVEL,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(), logging.FileHandler(trace_path, encoding="utf-8")],
    )
    for noisy in ("httpx", "httpx2", "mcp", "openai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    log.info("mode: pipeline + processing server%s",
             "".join(f" + {c}" for c in sorted(config.capabilities())))
    log.info("model: %s via %s", config.MODEL, config.BASE_URL)
    traceutil.event(log, "run.start", argv=argv, model=config.MODEL,
                base_url=config.BASE_URL, static_enabled=config.STATIC_ENABLED,
                agent_enabled=config.AGENT_ENABLED, max_candidates=config.MAX_CANDIDATES,
                max_refinements=config.MAX_REFINEMENTS, max_findings=config.MAX_FINDINGS,
                target_timeout=config.TARGET_TIMEOUT, log_level=config.LOG_LEVEL)

    if config.KB_ENABLED:
        try:
            log.info("memory: %s", await kb.health())
        except Exception as exc:                    # noqa: BLE001
            log.error("knowledge base unreachable: %s", exc)
            return 2

    handler = tracing.callback_handler()
    log.info("tracing: %s", "on" if handler else "off")

    started = time.monotonic()
    trace_id = None
    try:
        async with clients.connect() as (local, remote, dynamic):
            traceutil.event(log, "mcp.connections.ready", static_url=config.MCP_URL,
                        dynamic_url=config.DYNAMIC_MCP_URL)
            pipeline = graph.build(local, remote, dynamic, set(argv) or None)
            run_config = {
                "recursion_limit": graph.recursion_limit(),
                "callbacks": [handler] if handler else [],
                "run_name": "pipeline",
                "tags": ["agentlab", "pipeline"],
                "metadata": {"langfuse_session_id": "pipeline"},
            }
            with tracing.task_trace("pipeline", "process input/items") as trace_handle:
                state = await pipeline.ainvoke({"queue": [], "done": []}, run_config)
                trace_id = trace_handle["trace_id"]
                tracing.record_output(trace_handle, graph.summarise(state["done"]))
    except Exception as exc:                        # noqa: BLE001
        root = _root(exc)
        log.error("pipeline failed before finishing: %s: %s",
                  type(root).__name__, root)
        traceutil.event(log, "run.exception", exception=type(root).__name__, message=str(root))
        return 2
    finally:
        if config.KB_ENABLED:
            await kb.close()
        tracing.flush()

    done = state["done"]
    trace_url = tracing.trace_url(trace_id)
    run = {
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "seconds": round(time.monotonic() - started, 2),
        "model": config.MODEL,
        "capabilities": sorted(config.capabilities()),
        "trace_url": trace_url,
        "run_id": run_id,
        "trace_log": str(trace_path.relative_to(config.OUTPUT_DIR)),
        "items": done,
    }
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (config.OUTPUT_DIR / "run.json").write_text(json.dumps(run, indent=2) + "\n")
    traceutil.event(log, "run.complete", run=run)

    print()
    print(f"{'target':<18} {'status':<10} findings")
    print("-" * 78)
    for d in done:
        print(f"{d['id']:<18} {d['status']:<10} {d['count']}")
    print()
    if trace_url:
        print(f"  trace  {trace_url}")
    print(f"  written to {config.OUTPUT_DIR}/items/ and run.json")
    print()
    return 0 if all(d["status"] == "ok" for d in done) else 1


def main(argv: list[str]) -> int:
    return asyncio.run(_main(argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
