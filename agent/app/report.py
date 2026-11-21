"""Schema-shaped report assembly and output through the local MCP."""
import base64
import hashlib
import json
import logging

from app import clients, config

log = logging.getLogger(__name__)


def report(target: dict, note: dict, number: int, verdict: dict | None = None) -> dict:
    verdict = verdict or {"state": "candidate", "attempts": 1, "reproductions": 0,
                          "independent": False, "methods": ["dynamic_run"]}
    state = verdict.get("state", "candidate")
    impact = note.get("impact", {})
    root = note.get("root_cause", {})
    trigger = note.get("trigger", {})
    expect = note.get("expect", {})
    return {"schema_version": "cs279-finding/1", "id": f"finding-{number:03d}",
        "target": {"repository": target["repository"], "commit": target.get("commit"),
                   "build": trigger.get("build_command") or target.get("build_hint", "make").split(";")[0]},
        "finding": {"title": note.get("title", "Potential vulnerability"),
            "description": note.get("description", root.get("flow", "Observed during dynamic analysis.")),
            "type": note.get("type", "memory safety"), "cwe": note.get("cwe", []),
            "severity": note.get("severity", "unknown"), "confidence": note.get("confidence", "low")},
        "location": [{"file": note.get("file", "unknown"), "function": note.get("function", ""),
            "line_start": max(1, int(note.get("line_start", 1))), "line_end": max(1, int(note.get("line_end", note.get("line_start", 1))))}],
        "root_cause": {"input": root.get("input", "External input"), "flow": root.get("flow", "Observed input reached the reported behavior."),
            "violated_property": root.get("violated_property", "Input must be handled safely."),
            **{k: root[k] for k in ("source", "sink", "missing_check") if root.get(k)}},
        "evidence": [], "reproduction": {"steps": trigger.get("run_command", "Run the recorded trigger"),
            "expected": expect.get("regex", "observable output"),
            "replay": {"context": "artifacts/observed.json", "expect": {f"{expect.get('stream','stderr')}_regex": expect.get("regex", "")}}},
        "impact": {"attacker": impact.get("attacker", "User able to provide input"),
            "preconditions": impact.get("preconditions", "The target processes the trigger."),
            "privileges": impact.get("privileges", "None"), "boundary": impact.get("boundary", "Input to target process"),
            "confidentiality": impact.get("confidentiality", "unknown"), "integrity": impact.get("integrity", "unknown"),
            "availability": impact.get("availability", "unknown"), "consequences": impact.get("consequences", "Requires further validation.")},
        "validation": {"state": state, "attempts": verdict.get("attempts", 0),
            "reproductions": verdict.get("reproductions", 0), "methods": verdict.get("methods", []),
            "independent": verdict.get("independent", False)}}


async def write(local, target: dict, findings: list[dict], status="ok"):
    done = []
    base = f"items/{target['id']}/"
    for i, (note, verdict) in enumerate(findings[:config.MAX_FINDINGS], 1):
        document = report(target, note, i, verdict)
        folder = f"{base}findings/finding-{i:03d}/"
        observed = json.dumps(note.get("observed", {}), indent=2).encode()
        evidence_path = folder + "artifacts/observed.json"
        await clients.call(local, "write_file", {"relpath": evidence_path,
            "data_b64": base64.b64encode(observed).decode()})
        document["evidence"].append({"kind":"other", "path": evidence_path.split("/findings/", 1)[1].split("/", 1)[1],
            "sha256": hashlib.sha256(observed).hexdigest(), "description":"Trimmed dynamic execution output."})
        poc = base64.b64decode(note.get("trigger", {}).get("stdin_b64", ""))
        if poc:
            poc_path = folder + "artifacts/poc.bin"
            await clients.call(local, "write_file", {"relpath": poc_path, "data_b64": base64.b64encode(poc).decode()})
            document["evidence"].append({"kind":"input", "path":poc_path.split("/findings/", 1)[1].split("/", 1)[1],
                "sha256":hashlib.sha256(poc).hexdigest(), "description":"Standard input used for the observed run."})
        path = folder + "report.json"
        await clients.call(local, "write_file", {"relpath": path, "data_b64": base64.b64encode((json.dumps(document, indent=2)+"\n").encode()).decode()})
        done.append({"id": document["id"], "state": document["validation"]["state"]})
    summary = {"id": target["id"], "status": status, "findings": done, "count": len(done)}
    await clients.call(local, "write_file", {"relpath": f"{base}summary.json", "data_b64": base64.b64encode((json.dumps(summary, indent=2)+"\n").encode()).decode()})
    log.info("finalized %s: status=%s findings=%d", target["id"], status, len(done))
    return summary
