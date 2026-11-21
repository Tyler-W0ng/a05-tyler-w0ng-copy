"""Small plan/execute/refine controller for one target."""
import base64
import json
import re

from langchain_openai import ChatOpenAI

from app import clients, config


async def _ask(prompt: str) -> dict:
    model = ChatOpenAI(model=config.MODEL, base_url=config.BASE_URL,
                       api_key=config.API_KEY, temperature=0)
    response = await model.ainvoke(prompt)
    text = response.content if isinstance(response.content, str) else str(response.content)
    text = re.sub(r"^```(?:json)?|```$", "", text.strip())
    return json.loads(text)


def _summary(result: dict) -> dict:
    lines = (result.get("stdout", "") + "\n" + result.get("stderr", "")).splitlines()
    return {"exit_code": result.get("exit_code"), "sanitizer_report": result.get("sanitizer_report", False),
            "tail": "\n".join(lines[-30:])}


async def investigate(target: dict, leads: list[dict], dynamic, dynamic_path: str) -> list[dict]:
    prompt = ("Return JSON array, up to %d candidate vulnerability notes. Each object must include "
              "title,type,cwe(sequences),severity,confidence,file,function,line_start,line_end,"
              "root_cause(object input/source/sink/flow/missing_check/violated_property),impact(object),"
              "trigger(object build_command/run_command/stdin_b64),expect(object stream/regex). "
              "Use only provided leads and entry points; triggers must be shell commands and proof regex.\n"
              "Target: %s\nEntry points: %s\nLeads: %s" %
              (config.MAX_CANDIDATES, target, target.get("entry_points", []), json.dumps(leads[:15])))
    candidates = (await _ask(prompt))[:config.MAX_CANDIDATES]
    built = False
    accepted = []
    refinements = 0
    for note in candidates:
        for attempt in range(2):
            trigger = note.get("trigger", {})
            if not built:
                build = await clients.call(dynamic, "dynamic_build", {
                    "target_path": dynamic_path,
                    "build_command": trigger.get("build_command") or target.get("build_hint", "make").split(";")[0],
                    "timeout_seconds": 300})
                built = not build.get("error") and build.get("exit_code") == 0
            if not built:
                break
            data = base64.b64decode(trigger.get("stdin_b64", "")).decode("latin1")
            run = await clients.call(dynamic, "dynamic_run", {
                "target_path": dynamic_path, "command": trigger.get("run_command", ""), "input_data": data})
            observed = run.get("stdout" if note.get("expect", {}).get("stream") == "stdout" else "stderr", "")
            fired = bool(re.search(note.get("expect", {}).get("regex", r"(?!)"), observed)) or run.get("sanitizer_report")
            if fired:
                note["observed"] = _summary(run)
                accepted.append(note)
                break
            if attempt or refinements >= config.MAX_REFINEMENTS:
                break
            refinements += 1
            revision = await _ask("Return revised complete candidate JSON, or {\"give_up\":true}. Candidate: " +
                                  json.dumps(note) + "\nRun result: " + json.dumps(_summary(run)))
            if revision.get("give_up"):
                break
            note = revision
    return accepted
