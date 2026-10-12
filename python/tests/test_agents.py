"""
The Python agent adapters (docs/agent-adapters.md) against a real log and the real frameworks:
tests/agents.test.mjs starts the Worker on the local harness and runs this file with
RISKROUTER_BASE and RISKROUTER_API_KEY set. A framework that is not installed is skipped, and
REQUIRE_AGENTS (CI) turns that skip into a failure in tests/agents.test.mjs.

    python3 -m unittest discover -s recorders/python/tests -p test_agents.py
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from riskrouter_recorder import Recorder  # noqa: E402
from riskrouter_recorder.agents import EvidenceCallbackHandler, EvidenceTracingProcessor, content_digest  # noqa: E402

BASE = os.environ.get("RISKROUTER_BASE")
KEY = os.environ.get("RISKROUTER_API_KEY")
SECRET = "applicant-SECRET-4471"

try:
    import langchain_core  # noqa: F401
    from langchain_core.runnables import RunnableLambda
    from langchain_core.tools import tool
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
except ImportError:
    langchain_core = None
try:
    from langgraph.graph import StateGraph, START, END
except ImportError:
    StateGraph = None
try:
    import agents as openai_agents
    from agents.tracing import set_trace_processors, trace, function_span, handoff_span, guardrail_span, agent_span
except ImportError:
    openai_agents = None


class CapturingRecorder(Recorder):
    """A Recorder that keeps every body it sends, to check none of them holds the conversation."""

    def __init__(self, **kw):
        self.sent = []
        super().__init__(api=BASE, api_key=KEY, journal=os.path.join(tempfile.mkdtemp(prefix="rr-agent-"), "evidence.jsonl"),
                         start_thread=False, **kw)

    def _call(self, method, path, body=None):
        if body is not None:
            self.sent.append(json.dumps(body))
        return super()._call(method, path, body)

    def journal(self):
        with open(self._journal.path, encoding="utf-8") as fh:
            return [json.loads(l) for l in fh if l.strip()][1:]

    def records(self):
        return [l["record"] for l in self.journal() if l["type"] == "pending"]


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


live = unittest.skipUnless(BASE and KEY, "no log to record to (run through tests/agents.test.mjs)")


class ContentDigest(unittest.TestCase):
    def test_the_rule(self):
        self.assertEqual(content_digest("refer"), sha("refer"))
        self.assertEqual(content_digest({"b": 1, "a": "é"}), sha('{"a":"é","b":1}'))

        class Msg:
            content = "hello"
        self.assertEqual(content_digest(Msg()), sha("hello"))


@live
@unittest.skipUnless(langchain_core, "langchain-core not installed")
class LangChain(unittest.TestCase):
    def test_a_run_with_a_tool_and_a_model_becomes_one_recorded_record_of_digests(self):
        r = CapturingRecorder()

        @tool
        def score_applicant(ref: str) -> str:
            """Score an applicant by reference."""
            return "612 for " + ref

        model = FakeListChatModel(responses=["refer to a person"])

        def decide(ref):
            scored = score_applicant.invoke({"ref": ref})
            return model.invoke("Decide on: " + scored).content

        handler = EvidenceCallbackHandler(r, fields={"system_ref": "credit-agent", "system_version": "1.0"})
        out = RunnableLambda(decide, name="credit_decision").invoke(SECRET, config={"callbacks": [handler]})
        self.assertEqual(out, "refer to a person")
        records = r.records()
        self.assertEqual(len(records), 1, "one record per run, not per step")
        rec = records[0]
        self.assertEqual((rec["kind"], rec["framework"], rec["name"], rec["outcome"]), ("ai.agent-run", "langchain", "credit_decision", "completed"))
        self.assertEqual((rec["system_ref"], rec["system_version"]), ("credit-agent", "1.0"))
        self.assertEqual([s["type"] for s in rec["steps"]], ["tool", "generation"])
        tool_step = rec["steps"][0]
        self.assertEqual(tool_step["name"], "score_applicant")
        self.assertEqual(tool_step["output_digest"], sha("612 for " + SECRET))
        self.assertEqual(rec["steps"][1]["output_digest"], sha("refer to a person"))
        self.assertEqual(rec["output_digest"], sha("refer to a person"))
        self.assertNotIn(SECRET, json.dumps(rec), "digests, not content, by default")
        self.assertEqual(r.flush()["recorded"], 1)
        for body in r.sent:
            self.assertNotIn(SECRET, body)
            self.assertNotIn("refer to a person", body)
        r.close()

    def test_include_content_keeps_the_text_in_the_journal_and_still_sends_none(self):
        r = CapturingRecorder()

        @tool
        def lookup(ref: str) -> str:
            """Look up a case."""
            return "case " + ref

        lookup.invoke({"ref": SECRET}, config={"callbacks": [EvidenceCallbackHandler(r, include_content=True)]})
        rec = r.records()[0]
        self.assertEqual(rec["steps"][0]["output"], "case " + SECRET)
        r.flush()
        self.assertTrue(r.sent and all(SECRET not in b for b in r.sent))
        r.close()

    def test_a_failing_run_is_recorded_as_an_error_and_the_error_still_reaches_the_caller(self):
        r = CapturingRecorder()

        def boom(_):
            raise ValueError("income could not be verified")

        with self.assertRaises(ValueError):
            RunnableLambda(boom, name="assess").invoke("x", config={"callbacks": [EvidenceCallbackHandler(r)]})
        rec = r.records()[0]
        self.assertEqual(rec["outcome"], "error")
        self.assertIn("income could not be verified", rec["error"])
        r.close()

    def test_a_fault_in_the_adapter_never_reaches_the_agent(self):
        r = CapturingRecorder()
        handler = EvidenceCallbackHandler(r, build=lambda run: {"kind": "NOT A KIND"})
        self.assertEqual(RunnableLambda(lambda x: x + 1, name="inc").invoke(1, config={"callbacks": [handler]}), 2)
        self.assertEqual(r.records(), [])
        r.close()

    @unittest.skipUnless(StateGraph, "langgraph not installed")
    def test_langgraph_nodes_are_steps_in_order(self):
        r = CapturingRecorder()

        def triage(state):
            return {"route": "manual", "trail": state["trail"] + ["triage"]}

        def review(state):
            return {"trail": state["trail"] + ["review"]}

        from typing import TypedDict

        class State(TypedDict, total=False):
            route: str
            trail: list

        g = StateGraph(State)
        g.add_node("triage", triage)
        g.add_node("review", review)
        g.add_edge(START, "triage")
        g.add_edge("triage", "review")
        g.add_edge("review", END)
        out = g.compile().invoke({"trail": []}, config={"callbacks": [EvidenceCallbackHandler(r)]})
        self.assertEqual(out["trail"], ["triage", "review"])
        rec = r.records()[0]
        self.assertEqual([(s["type"], s["name"]) for s in rec["steps"]], [("node", "triage"), ("node", "review")])
        self.assertEqual(r.flush()["recorded"], 1)
        r.close()


@live
@unittest.skipUnless(openai_agents, "openai-agents not installed")
class OpenAIAgents(unittest.TestCase):
    def tearDown(self):
        set_trace_processors([])

    def test_a_traced_run_becomes_one_record_with_its_tool_call_handoff_and_guardrail(self):
        r = CapturingRecorder()
        # set_trace_processors replaces the SDK's exporter, so nothing is sent to OpenAI either.
        set_trace_processors([EvidenceTracingProcessor(r, fields={"system_ref": "claims-agent"})])
        with trace("claim-review", group_id="claim-88"):
            with agent_span(name="triage"):
                with guardrail_span(name="no-personal-data", triggered=True):
                    pass
                with function_span(name="fetch_policy", input='{"ref": "%s"}' % SECRET) as s:
                    s.span_data.output = "policy P-1 for " + SECRET
                with handoff_span(from_agent="triage", to_agent="adjuster"):
                    pass
        rec = r.records()[0]
        self.assertEqual((rec["framework"], rec["name"], rec["group_id"], rec["system_ref"]), ("openai-agents", "claim-review", "claim-88", "claims-agent"))
        steps = rec["steps"]
        self.assertEqual([s["type"] for s in steps], ["guardrail", "tool", "handoff", "agent"])
        self.assertTrue(steps[0]["triggered"])
        self.assertEqual(steps[1]["output_digest"], sha("policy P-1 for " + SECRET))
        self.assertEqual((steps[2]["from_agent"], steps[2]["to_agent"]), ("triage", "adjuster"))
        self.assertNotIn(SECRET, json.dumps(rec))
        self.assertEqual(r.flush()["recorded"], 1)
        self.assertTrue(all(SECRET not in b for b in r.sent))
        r.close()


if __name__ == "__main__":
    unittest.main()
