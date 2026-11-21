"""Small plan/execute/refine controller for one target."""
import base64
import json
import re
import logging

from langchain_openai import ChatOpenAI

from app import clients, config

log = logging.getLogger(__name__)

NOTE_SCHEMA = {
    "type": "object",
    "required": ["title", "type", "cwe", "severity", "confidence", "file", "function",
                 "line_start", "line_end", "root_cause", "impact", "trigger", "expect"],
    "properties": {
        "title": {"type": "string"}, "type": {"type": "string"},
        "cwe": {"type": "array", "items": {"type": "string"}},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical", "unknown"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "file": {"type": "string"}, "function": {"type": "string"},
        "line_start": {"type": "integer", "minimum": 1}, "line_end": {"type": "integer", "minimum": 1},
        "root_cause": {"type": "object", "required": ["input", "flow", "violated_property"],
            "properties": {"input": {"type": "string"}, "source": {"type": "string"},
                "sink": {"type": "string"}, "flow": {"type": "string"},
                "missing_check": {"type": "string"}, "violated_property": {"type": "string"}}},
        "impact": {"type": "object"},
        "trigger": {"type": "object", "required": ["build_command", "run_command", "stdin_b64"],
            "properties": {"build_command": {"type": "string"}, "run_command": {"type": "string"},
                "stdin_b64": {"type": "string"}}},
        "expect": {"type": "object", "required": ["stream", "regex"],
            "properties": {"stream": {"type": "string", "enum": ["stdout", "stderr"]},
                "regex": {"type": "string"}}}
    }
}

async def _ask(prompt: str) -> str:
    model = ChatOpenAI(model=config.MODEL, base_url=config.BASE_URL,
                       api_key=config.API_KEY, temperature=0)
    log.info("MODEL INPUT BEGIN (%d chars)\n%s\nMODEL INPUT END", len(prompt), prompt)
    response = await model.ainvoke(prompt)
    text = response.content if isinstance(response.content, str) else str(response.content)
    text = re.sub(r"^```(?:json)?|```$", "", text.strip())
    log.info("MODEL OUTPUT BEGIN (%d chars)\n%s\nMODEL OUTPUT END", len(text), text)
    return text


def _parse_candidates(text: str) -> list[dict]:
    """Find a candidate JSON object even when the model adds leading prose."""
    decoder = json.JSONDecoder()
    values = []
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            values, _ = decoder.raw_decode(stripped)
        except json.JSONDecodeError:
            pass
    if not values:
        for index, char in enumerate(text):
            if char != "{":
                continue
            try:
                value, _ = decoder.raw_decode(text[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and isinstance(value.get("candidates"), list):
                values = value["candidates"]
                break
    if not values:
        return []
    required = NOTE_SCHEMA["required"]
    result = [item for item in values if isinstance(item, dict) and all(key in item for key in required)
            and isinstance(item.get("line_start"), int) and isinstance(item.get("line_end"), int)
            and isinstance(item.get("root_cause"), dict) and isinstance(item.get("trigger"), dict)
            and isinstance(item.get("expect"), dict)]
    if values and not result:
        missing = [[key for key in required if key not in item]
                   for item in values if isinstance(item, dict)]
        log.warning("candidate JSON found but failed required fields: %s", missing[:5])
    return result


async def _candidate_reply(prompt: str, target_id: str) -> list[dict]:
    text = await _ask(prompt)
    candidates = _parse_candidates(text)
    if candidates or '"candidates": []' in text or text.strip() == "[]":
        log.info("model response valid for %s: %d candidates", target_id, len(candidates))
        return candidates
    log.warning("model response invalid for %s (%d chars); treating as zero candidates",
                target_id, len(text))
    log.warning("no valid candidate JSON object found in model response for %s", target_id)
    return []


def _summary(result: dict) -> dict:
    lines = (result.get("stdout", "") + "\n" + result.get("stderr", "")).splitlines()
    return {"exit_code": result.get("exit_code"), "sanitizer_report": result.get("sanitizer_report", False),
            "tail": "\n".join(lines[-30:])}


async def investigate(target: dict, leads: list[dict], dynamic, dynamic_path: str) -> list[dict]:
    # SARIF codeFlows can be very large. Keep only concise location, flow, and
    # source-context details needed to choose a test location and trigger.
    compact_leads = []
    for lead in leads[:8]:
        compact = {key: lead[key] for key in
                   ("tool", "rule", "rule_id", "file", "path", "line_start", "line_end", "message", "excerpt", "source_context", "flow")
                   if key in lead}
        if not compact.get("message") and isinstance(lead.get("message"), dict):
            compact["message"] = lead["message"].get("text", "")
        if isinstance(compact.get("message"), str):
            compact["message"] = compact["message"][:350]
        if isinstance(compact.get("excerpt"), str):
            compact["excerpt"] = compact["excerpt"][:500]
        if isinstance(compact.get("source_context"), str):
            compact["source_context"] = compact["source_context"][:2200]
        compact_leads.append(compact)
    prompt = (
        "You are investigating one pinned C/C++ project for real, reproducible security bugs. "
        "Your task is to propose up to %d specific candidate triggers that can be run against this checkout. "
        "Use the static findings and entry points as evidence. Do not invent source facts or claim a bug solely "
        "because a pattern is suspicious. A candidate must name the vulnerable location, explain input-to-sink "
        "flow, provide a runnable command and stdin encoded as base64, and give an observable regex on stdout "
        "or stderr. If the evidence is insufficient to propose a testable candidate, return an empty candidates list. "
        "The dynamic tools run commands from the root of a separate dynamic checkout. Set build_command to the "
        "target build hint such as 'make'; do not use cd or a static checkout path. Set run_command to a relative "
        "executable command such as './scoreboard'; do not use echo or shell redirection for input because stdin_b64 "
        "is supplied separately.\n\n"
        "OUTPUT RULES: Your entire response must be the candidate JSON only. Do not output analysis, explanations, "
        "preambles, markdown, or text after it. If there are no testable candidates, output exactly "
        "{\"candidates\":[]}. Use the following schema (all listed keys are required):\n%s\n\n"
        "Target: %s\nEntry points: %s\nStatic findings: %s\n"
        % (config.MAX_CANDIDATES, json.dumps(NOTE_SCHEMA),
           json.dumps({k:v for k,v in target.items() if not k.startswith("_")}),
           json.dumps(target.get("entry_points", [])), json.dumps(compact_leads))
    )
    while len(prompt) > 18000 and compact_leads:
        compact_leads.pop()
        prompt = prompt.rsplit("Static findings: ", 1)[0] + "Static findings: " + json.dumps(compact_leads)
    log.info("investigator prompt for %s: %d chars, %d compact leads", target.get("id"),
             len(prompt), len(compact_leads))
    candidates = await _candidate_reply(prompt, target.get("id", "target"))
    candidates = candidates[:config.MAX_CANDIDATES]
    log.info("investigator received %d static leads and proposed %d candidates for %s",
             len(leads), len(candidates), target.get("id"))
    build_command = target.get("build_hint", "make").split(";")[0].strip() or "make"
    build = await clients.call(dynamic, "dynamic_build", {
        "target_path": dynamic_path, "build_command": build_command, "timeout_seconds": 300})
    built = not build.get("error") and build.get("exit_code") == 0
    log.info("dynamic build for %s: command=%s exit=%s error=%s", target.get("id"),
             build_command, build.get("exit_code"), (build.get("error") or "")[:180])
    accepted = []
    refinements = 0
    for note in candidates:
        for attempt in range(2):
            trigger = note.get("trigger", {})
            if not built:
                return accepted
            note.setdefault("trigger", {})["build_command"] = build_command
            run_command = trigger.get("run_command", "")
            run_command = re.sub(r"^\s*cd\s+[^;&]+\s*&&\s*", "", run_command)
            if "|" in run_command:
                run_command = run_command.rsplit("|", 1)[-1].strip()
            run_command = re.sub(r"\s+2>&1.*$", "", run_command).strip()
            data = base64.b64decode(trigger.get("stdin_b64", "")).decode("latin1")
            run = await clients.call(dynamic, "dynamic_run", {
                "target_path": dynamic_path, "command": run_command, "input_data": data})
            observed = run.get("stdout" if note.get("expect", {}).get("stream") == "stdout" else "stderr", "")
            fired = bool(re.search(note.get("expect", {}).get("regex", r"(?!)"), observed)) or run.get("sanitizer_report")
            log.info("trigger for %s (%s): exit=%s fired=%s sanitizer=%s", target.get("id"),
                     note.get("title", "candidate"), run.get("exit_code"), fired,
                     run.get("sanitizer_report", False))
            if fired:
                note["observed"] = _summary(run)
                accepted.append(note)
                break
            if attempt or refinements >= config.MAX_REFINEMENTS:
                break
            refinements += 1
            revision_prompt = ("You are refining one security test candidate after its first trigger did not produce "
                "the expected observable. Return exactly one JSON object {\"candidates\":[one revised candidate]} "
                "or {\"candidates\":[]} to give up. No prose. Follow this schema:\n" +
                json.dumps(NOTE_SCHEMA) + "\nCandidate:\n" + json.dumps(note) +
                "\nRun result:\n" + json.dumps(_summary(run)))
            revisions = await _candidate_reply(revision_prompt, target.get("id", "target"))
            if not revisions:
                break
            note = revisions[0]
    return accepted
