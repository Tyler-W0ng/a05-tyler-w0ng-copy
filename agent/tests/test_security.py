"""Exercise the real ReAct/tool loop and pipeline without external services.

Run: cd agent && .venv/bin/python -m unittest discover -s tests -v
"""
import asyncio
import base64
import json
import unittest
from unittest.mock import patch

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage

from app import config, graph, specialists


class ToolCallingModel(FakeMessagesListChatModel):
    bound_names: list[str] = []

    def bind_tools(self, tools, **kwargs):
        self.bound_names = [tool.name for tool in tools]
        return self


def request(name, args, number):
    return AIMessage(content="", tool_calls=[{
        "name": name, "args": args, "id": f"call-{number}",
    }])


SOURCE = "/tmp/static-work/example"
DATABASE = "/tmp/codeql-work/example"
SEMGREP = {"exit_code": 0, "results": {"results": [{
    "check_id": "unsafe-copy", "path": f"{SOURCE}/example.c",
    "start": {"line": 2}, "end": {"line": 2},
    "extra": {"message": "Unsafe copy", "lines": "strcpy(buf, s);"},
}]}}
CODEQL = {"exit_code": 0, "findings": [{
    "rule_id": "cpp/use-after-free", "message": {"text": "Use after free"},
    "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "example.c"}, "region": {"startLine": 6},
    }}],
}]}


def model():
    return ToolCallingModel(responses=[
        request("scan_semgrep", {"target_path": SOURCE}, 1),
        request("codeql_create_database", {"target_path": SOURCE, "build_command": "make -B"}, 2),
        request("codeql_analyze", {"database_path": DATABASE}, 3),
        AIMessage(content="Two potential issues require validation."),
    ])


async def static_call(client, name, args):
    return {
        "scan_semgrep": SEMGREP,
        "codeql_create_database": {"exit_code": 0, "database_path": DATABASE},
        "codeql_analyze": CODEQL,
    }[name]


class SecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_runner_executes_tools_and_keeps_transcript(self):
        llm = model()
        with patch.object(specialists, "_model", return_value=llm), patch.object(
                specialists.clients, "call", side_effect=static_call) as mcp:
            result = await specialists.run_security(SOURCE, "make -B", object())
        self.assertNotIn("error", result)
        self.assertEqual(llm.bound_names, ["scan_semgrep", "codeql_create_database", "codeql_analyze"])
        self.assertEqual(mcp.await_count, 3)
        self.assertEqual(result["tool_calls"][0]["result"], SEMGREP)
        self.assertEqual(result["tool_calls"][2]["result"], CODEQL)
        supplied = json.loads(result["transcript"][1]["content"])
        self.assertEqual(supplied, {"target_path": SOURCE, "build_command": "make -B"})
        self.assertEqual(result["transcript"][0]["content"], specialists.PROMPTS["security"])
        self.assertEqual(len([m for m in result["transcript"] if m["type"] == "tool"]), 3)

    async def test_no_calls_is_an_explicit_error(self):
        llm = ToolCallingModel(responses=[AIMessage(content="Done")])
        with patch.object(specialists, "_model", return_value=llm):
            result = await specialists.run_security(SOURCE, None, object())
        self.assertIn("without calling scan_semgrep", result["error"])
        self.assertEqual(result["tool_calls"], [])

    async def test_build_failure_is_returned_to_model_and_recorded(self):
        llm = ToolCallingModel(responses=[
            request("scan_semgrep", {"target_path": SOURCE}, 1),
            request("codeql_create_database", {"target_path": SOURCE}, 2),
            AIMessage(content="CodeQL skipped because the build failed."),
        ])

        async def failed_build(client, name, args):
            if name == "codeql_create_database":
                raise RuntimeError("Build failed")
            return SEMGREP

        with patch.object(specialists, "_model", return_value=llm), patch.object(
                specialists.clients, "call", side_effect=failed_build):
            result = await specialists.run_security(SOURCE, "make", object())
        self.assertEqual(result["tool_calls"][1]["result"], {"error": "Build failed"})
        self.assertEqual(len(result["tool_calls"]), 2)
        self.assertIn("skipped", result["summary"])

    async def test_timeout_preserves_attempted_calls(self):
        llm = ToolCallingModel(responses=[request("scan_semgrep", {"target_path": SOURCE}, 1)])

        async def blocked(client, name, args):
            await asyncio.Event().wait()

        with patch.object(specialists, "_model", return_value=llm), patch.object(
                specialists.clients, "call", side_effect=blocked):
            result = await specialists.run_security(SOURCE, "make", object(), timeout_seconds=0.2)
        self.assertEqual(result["error"], "TimeoutError")
        self.assertEqual(result["tool_calls"][0]["name"], "scan_semgrep")
        self.assertIn("cancelled", result["tool_calls"][0]["result"]["error"])
        self.assertTrue(any(m.get("tool_calls") for m in result["transcript"]))

    async def _pipeline(self, agent_enabled=True, static_enabled=True):
        local, remote, dynamic = object(), object(), object()
        writes = {}
        target = {"id": "example", "repository": "org/example", "commit": "abc", "build_hint": "make -B"}

        async def call(client, name, args):
            if name == "list_inputs":
                return {"ids": ["example.json"]}
            if name == "read_input":
                return {"data": base64.b64encode(json.dumps(target).encode()).decode()}
            if name == "static_checkout":
                return {"target_path": SOURCE, "exit_code": 0}
            if name == "dynamic_checkout":
                return {"target_path": "/tmp/dynamic-work/example", "exit_code": 0}
            if name == "read_source":
                return {"file": "example.c", "text": "source context"}
            if name == "write_file":
                writes[args["relpath"]] = json.loads(base64.b64decode(args["data_b64"]))
                return {}
            return await static_call(client, name, args)

        with patch.object(config, "STATIC_ENABLED", static_enabled), patch.object(config, "AGENT_ENABLED", agent_enabled), patch.object(
                specialists, "_model", return_value=model()), patch.object(
                graph.clients, "call", side_effect=call), patch.object(
                graph.investigator, "investigate", return_value=[]) as investigate:
            state = await graph.build(local, remote, dynamic).ainvoke({"queue": [], "done": []})
        return state, writes, investigate

    async def test_pipeline_passes_observed_findings_to_investigator(self):
        state, writes, investigate = await self._pipeline()
        self.assertEqual(state["done"][0]["status"], "ok")
        leads = investigate.call_args.args[1]
        self.assertEqual([lead["tool"] for lead in leads], ["semgrep", "codeql"])
        self.assertEqual(leads[0]["source_context"], "source context")
        artifact = writes["items/example/static-analysis.json"]
        self.assertEqual(len(artifact["tool_calls"]), 3)
        self.assertTrue(artifact["transcript"])

    async def test_agent_disabled_preserves_direct_scanning(self):
        with patch.object(specialists, "run_security") as security:
            state, writes, investigate = await self._pipeline(agent_enabled=False)
        security.assert_not_called()
        investigate.assert_not_called()
        self.assertEqual([lead["tool"] for lead in state["leads"]], ["semgrep", "codeql"])
        self.assertNotIn("items/example/static-analysis.json", writes)

    async def test_static_disabled_skips_security_agent(self):
        with patch.object(specialists, "run_security") as security:
            state, writes, investigate = await self._pipeline(static_enabled=False)
        security.assert_not_called()
        self.assertEqual(investigate.call_args.args[1], [])
        self.assertNotIn("items/example/static-analysis.json", writes)


if __name__ == "__main__":
    unittest.main()
