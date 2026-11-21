"""Deterministic target loop; MCP servers perform checkout and analysis."""
import base64
import json
import logging
import operator
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph
from mcp import Client

from app import clients, config, investigator, report

log = logging.getLogger(__name__)


class State(TypedDict, total=False):
    queue: list[str]
    target: dict | None
    findings: list
    error: str | None
    done: Annotated[list[dict], operator.add]


def build(local: Client, remote: Client, dynamic: Client, only: set[str] | None = None):
    async def list_targets(state):
        ids = (await clients.call(local, "list_inputs", {}))["ids"]
        ids = [i for i in ids if i.endswith(".json") and (not only or i[:-5] in only)]
        return {"queue": ids[:config.MAX_ITEMS]}

    async def read_next(state):
        if not state.get("queue"):
            return {"target": None}
        filename, *rest = state["queue"]
        try:
            raw = await clients.call(local, "read_input", {"id": filename})
            target = json.loads(base64.b64decode(raw["data"]))
            target["id"] = target.get("id", filename[:-5])
            return {"queue": rest, "target": target, "findings": [], "error": None}
        except Exception as exc:
            return {"queue": rest, "target": {"id": filename[:-5]}, "findings": [], "error": str(exc)}

    async def recon(state):
        target = state["target"]
        if state.get("error"):
            return {"findings": [], "leads": []}
        static_path = dynamic_path = None
        try:
            if config.STATIC_ENABLED:
                checkout = await clients.call(remote, "static_checkout", {"repository": target["repository"], "commit": target["commit"]})
                static_path = checkout.get("target_path")
            checkout = await clients.call(dynamic, "dynamic_checkout", {"repository": target["repository"], "commit": target["commit"]})
            dynamic_path = checkout.get("target_path")
            leads = []
            if config.STATIC_ENABLED and static_path:
                sem = await clients.call(remote, "scan_semgrep", {"target_path": static_path})
                for hit in sem.get("results", {}).get("results", []):
                    extra, start = hit.get("extra", {}), hit.get("start", {})
                    leads.append({"tool":"semgrep", "rule":hit.get("check_id"), "file":hit.get("path"),
                        "line_start":start.get("line",1), "line_end":hit.get("end",{}).get("line", start.get("line",1)),
                        "message":extra.get("message", ""), "excerpt":extra.get("lines", "")})
                try:
                    db = await clients.call(remote, "codeql_create_database", {"target_path":static_path,
                        "build_command":target.get("build_hint", "make").split(";")[0], "timeout_seconds":240})
                    if db.get("database_path"):
                        ql = await clients.call(remote, "codeql_analyze", {"database_path":db["database_path"], "timeout_seconds":240})
                        leads.extend(ql.get("findings", [])[:20])
                except Exception as exc:
                    log.info("CodeQL skipped for %s: %s", target["id"], exc)
            return {"leads": leads[:40], "dynamic_path": dynamic_path}
        except Exception as exc:
            return {"leads": [], "dynamic_path": dynamic_path, "error": str(exc)}

    async def investigate_node(state):
        if state.get("error") or not config.AGENT_ENABLED or not state.get("dynamic_path"):
            return {"findings": []}
        found = await investigator.investigate(state["target"], state.get("leads", []), dynamic, state["dynamic_path"])
        # Reproduction is owned by the separate deliverable. Without its service
        # wired in, discoveries remain candidates and cannot claim reproducibility.
        return {"findings": [(note, {"state":"candidate", "attempts":1, "reproductions":0,
                                      "independent":False, "methods":["dynamic_run"]}) for note in found]}

    async def warnings_to_findings(state):
        return {"findings": [(dict(title=x.get("rule", "Static warning"), description=x.get("message", ""),
            type="static analysis warning", cwe=[], severity="unknown", confidence="low", file=x.get("file", "unknown"),
            line_start=x.get("line_start", 1), line_end=x.get("line_end", x.get("line_start", 1)),
            root_cause={"input":"Unknown", "flow":x.get("message", "Static warning"), "violated_property":"Requires validation"},
            impact={}, trigger={}, expect={}), {"state":"candidate", "attempts":0, "reproductions":0,
            "independent":False, "methods":["static_analysis"]}) for x in state.get("leads", [])]}

    def dedup(state):
        best = {}
        for item in state.get("findings", []):
            note = item[0]
            key = (note.get("type"), note.get("file"), note.get("function"))
            best.setdefault(key, item)
        return {"findings": list(best.values())[:config.MAX_FINDINGS]}

    async def finalize(state):
        target = state["target"]
        if not target:
            return {}
        if not target.get("repository"):
            summary = {"id": target["id"], "status": "failed", "findings": [], "count": 0,
                       "error": state.get("error", "unreadable target spec")}
            await clients.call(local, "write_file", {"relpath": f"{target['id']}/summary.json",
                "data_b64": base64.b64encode((json.dumps(summary, indent=2)+"\n").encode()).decode()})
            return {"done": [summary]}
        result = await report.write(local, target, state.get("findings", []), "failed" if state.get("error") else "ok")
        return {"done":[result]}

    def route(state):
        if state.get("target") is None:
            return END
        if not config.AGENT_ENABLED:
            return "warnings_to_findings"
        return "investigate"

    graph = StateGraph(State)
    for name, fn in (("list_targets",list_targets),("read_next",read_next),("recon",recon),
                     ("investigate",investigate_node),("warnings_to_findings",warnings_to_findings),
                     ("dedup",dedup),("finalize",finalize)):
        graph.add_node(name, fn)
    graph.add_edge(START,"list_targets"); graph.add_edge("list_targets","read_next")
    graph.add_conditional_edges("read_next", lambda s: END if s.get("target") is None else "recon", [END,"recon"])
    graph.add_conditional_edges("recon", route, ["investigate","warnings_to_findings",END])
    graph.add_edge("investigate","dedup"); graph.add_edge("warnings_to_findings","finalize")
    graph.add_edge("dedup","finalize"); graph.add_edge("finalize","read_next")
    return graph.compile(name="pipeline")


def recursion_limit():
    return max(100, config.MAX_ITEMS * 10)


def summarise(done):
    return "\n".join(f"{x['id']}: {x['status']} ({x['count']} findings)" for x in done)
