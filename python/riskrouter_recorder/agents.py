"""
Agent adapters: each agent run becomes one evidence record (docs/agent-adapters.md).

    from riskrouter_recorder import Recorder
    from riskrouter_recorder.agents import EvidenceCallbackHandler, EvidenceTracingProcessor

    recorder = Recorder(journal="evidence.jsonl")

    # LangChain and LangGraph: a callback handler
    graph.invoke(state, config={"callbacks": [EvidenceCallbackHandler(recorder, fields={"system_ref": "claims-agent"})]})

    # The OpenAI Agents SDK: a tracing processor
    from agents import add_trace_processor
    add_trace_processor(EvidenceTracingProcessor(recorder, fields={"system_ref": "claims-agent"}))

One leaf per run, not per step. By default each step keeps content digests,
SHA-256 of the text the framework handed over, never the text: prompts, tool
arguments and outputs stay in your own logs (include_content=True keeps them in
your journal instead; they are still never sent). Neither framework is a
dependency, and a failure in an adapter never reaches the agent.
"""
import hashlib
import json
import logging
import threading
from datetime import datetime, timezone

__all__ = ["EvidenceCallbackHandler", "EvidenceTracingProcessor", "content_digest", "RUN_KIND"]

RUN_KIND = "ai.agent-run"
_ERROR_MAX = 300
_log = logging.getLogger("riskrouter_recorder")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _text(value):
    """The text a content digest is taken of (docs/agent-adapters.md)."""
    if isinstance(value, str):
        return value
    content = getattr(value, "content", None)
    if isinstance(content, str):
        return content
    if hasattr(value, "model_dump"):
        try:
            value = value.model_dump()
        except Exception:
            pass
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def content_digest(value):
    """SHA-256 of the UTF-8 text of a value, as every adapter computes it."""
    return hashlib.sha256(_text(value).encode("utf-8")).hexdigest()


def _error_text(error):
    text = "%s: %s" % (type(error).__name__, error) if isinstance(error, BaseException) else str(error)
    return text[:_ERROR_MAX]


class _Runs:
    """Runs in progress, and turning a finished one into a record."""

    def __init__(self, recorder, framework, kind, fields, build, include_content, max_steps):
        self.recorder, self.framework, self.kind = recorder, framework, kind
        self.fields, self.build = dict(fields or {}), build
        self.include_content, self.max_steps = include_content, max_steps
        self.lock = threading.Lock()
        self.runs = {}

    def content(self, step, prefix, value):
        if value is None:
            return
        step[prefix + "_digest"] = content_digest(value)
        if self.include_content:
            step[prefix] = _text(value)

    def start(self, run_id, name, started_at=None):
        with self.lock:
            self.runs[run_id] = {"run_id": str(run_id), "name": name or "run", "started_at": started_at or _now(),
                                 "steps": [], "left_out": 0}

    def step(self, run_id, step):
        with self.lock:
            run = self.runs.get(run_id)
            if run is None:
                return
            if len(run["steps"]) < self.max_steps:
                run["steps"].append({k: v for k, v in step.items() if v is not None})
            else:
                run["left_out"] += 1

    def finish(self, run_id, error=None, ended_at=None, **extra):
        with self.lock:
            run = self.runs.pop(run_id, None)
        if run is None:
            return None
        record = dict(self.fields)
        record.update(kind=self.kind, framework=self.framework, run_id=run["run_id"], name=run["name"],
                      started_at=run["started_at"], ended_at=ended_at or _now(),
                      outcome="error" if error is not None else "completed", steps=run["steps"])
        if error is not None:
            record["error"] = _error_text(error)
        if run["left_out"]:
            record["steps_left_out"] = run["left_out"]
        for key, value in extra.items():
            if value is not None:
                record[key] = value
        if self.build is not None:
            record = self.build(record)
        return self.recorder.record(record, kind=record.get("kind", self.kind))


def _quietly(method):
    def guarded(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except Exception as e:  # never into the agent
            _log.warning("riskrouter-recorder: an agent event was not recorded: %s", e)
    guarded.__name__ = method.__name__
    guarded.__doc__ = method.__doc__
    return guarded


# ------------------------------------------------------------ LangChain / LangGraph

try:  # the framework's own base when it is installed; never required
    from langchain_core.callbacks import BaseCallbackHandler as _CallbackBase
except ImportError:  # pragma: no cover
    _CallbackBase = object


class EvidenceCallbackHandler(_CallbackBase):
    """A LangChain callback handler (LangGraph uses the same callbacks). The outermost run, whatever
    it is (a graph, a chain, an agent, a tool called on its own), becomes one record when it ends;
    tool calls, model calls, retrievals and LangGraph nodes inside it become its steps.

        EvidenceCallbackHandler(recorder, kind="ai.agent-run", fields={"system_ref": "..."}, include_content=False)
    """

    raise_error = False
    run_inline = True

    def __init__(self, recorder, kind=RUN_KIND, fields=None, build=None, include_content=False, max_steps=500):
        self._runs = _Runs(recorder, "langchain", kind, fields, build, include_content, max_steps)
        self._root = {}      # run id -> the outermost run it belongs to
        self._open = {}      # run id -> the step being built
        self._inputs = {}    # outermost run id -> digest of its input

    def _enter(self, run_id, parent_run_id, name, step=None, inputs=None):
        if parent_run_id is None:
            self._root[run_id] = run_id
            self._runs.start(run_id, name)
            if inputs is not None:
                self._inputs[run_id] = content_digest(inputs)
        else:
            self._root[run_id] = self._root.get(parent_run_id, parent_run_id)
        if step is not None:
            step.setdefault("name", name)
            step["started_at"] = _now()
            self._open[run_id] = step

    def _leave(self, run_id, output=None, error=None, output_key="output"):
        step = self._open.pop(run_id, None)
        root = self._root.pop(run_id, None)
        if step is not None and root is not None:
            step["ended_at"] = _now()
            if error is not None:
                step["error"] = _error_text(error)
            else:
                self._runs.content(step, output_key, output)
            self._runs.step(root, step)
        if root is not None and root == run_id:
            inputs = self._inputs.pop(run_id, None)
            self._runs.finish(run_id, error=error, input_digest=inputs,
                              output_digest=None if error is not None or output is None else content_digest(output))

    @staticmethod
    def _name(serialized, kwargs, fallback):
        return kwargs.get("name") or (serialized or {}).get("name") or ((serialized or {}).get("id") or [fallback])[-1]

    # chains: the outermost is the run; a LangGraph node is a step
    @_quietly
    def on_chain_start(self, serialized, inputs, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        node = (metadata or {}).get("langgraph_node")
        name = self._name(serialized, kwargs, "chain")
        step = {"type": "node", "name": node} if node and parent_run_id is not None and name == node else None
        if step is not None:
            self._runs.content(step, "input", inputs)
        self._enter(run_id, parent_run_id, name, step, inputs=inputs)

    @_quietly
    def on_chain_end(self, outputs, *, run_id, parent_run_id=None, **kwargs):
        self._leave(run_id, output=outputs)

    @_quietly
    def on_chain_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._leave(run_id, error=error)

    # tools
    @_quietly
    def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None, tags=None, metadata=None, inputs=None, **kwargs):
        step = {"type": "tool"}
        self._runs.content(step, "input", input_str)
        self._enter(run_id, parent_run_id, self._name(serialized, kwargs, "tool"), step, inputs=input_str)

    @_quietly
    def on_tool_end(self, output, *, run_id, parent_run_id=None, **kwargs):
        self._leave(run_id, output=output)

    @_quietly
    def on_tool_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._leave(run_id, error=error)

    # models
    def _model_start(self, serialized, prompt, run_id, parent_run_id, metadata, kwargs):
        params = kwargs.get("invocation_params") or {}
        step = {"type": "generation", "model": (metadata or {}).get("ls_model_name") or params.get("model") or params.get("model_name")}
        self._runs.content(step, "input", prompt)
        self._enter(run_id, parent_run_id, self._name(serialized, kwargs, "model"), step, inputs=prompt)

    @_quietly
    def on_llm_start(self, serialized, prompts, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._model_start(serialized, prompts, run_id, parent_run_id, metadata, kwargs)

    @_quietly
    def on_chat_model_start(self, serialized, messages, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._model_start(serialized, [[_text(m) for m in batch] for batch in messages], run_id, parent_run_id, metadata, kwargs)

    @_quietly
    def on_llm_end(self, response, *, run_id, parent_run_id=None, **kwargs):
        texts = [[g.text for g in batch] for batch in (getattr(response, "generations", None) or [])]
        self._leave(run_id, output=texts[0][0] if len(texts) == 1 and len(texts[0]) == 1 else texts)

    @_quietly
    def on_llm_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._leave(run_id, error=error)

    # retrievers
    @_quietly
    def on_retriever_start(self, serialized, query, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        step = {"type": "retriever"}
        self._runs.content(step, "input", query)
        self._enter(run_id, parent_run_id, self._name(serialized, kwargs, "retriever"), step, inputs=query)

    @_quietly
    def on_retriever_end(self, documents, *, run_id, parent_run_id=None, **kwargs):
        self._leave(run_id, output=[getattr(d, "page_content", d) for d in documents])

    @_quietly
    def on_retriever_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._leave(run_id, error=error)


# ---------------------------------------------------------------- OpenAI Agents SDK

try:  # the SDK's own base when it is installed; never required
    from agents.tracing import TracingProcessor as _TracingBase
except ImportError:  # pragma: no cover
    _TracingBase = object


class EvidenceTracingProcessor(_TracingBase):
    """A tracing processor for the OpenAI Agents SDK. Each trace (one Runner.run, or a `with trace(...)`
    around several) becomes one record when it ends; function calls, model generations, handoffs,
    guardrails and agent spans inside it become its steps.

        from agents import add_trace_processor
        add_trace_processor(EvidenceTracingProcessor(recorder, fields={"system_ref": "..."}))

    add_trace_processor keeps the SDK's own exporter, which sends traces to OpenAI; use
    set_trace_processors([...]) instead if nothing should be sent there.
    """

    def __init__(self, recorder, kind=RUN_KIND, fields=None, build=None, include_content=False, max_steps=500):
        self.recorder = recorder
        self._runs = _Runs(recorder, "openai-agents", kind, fields, build, include_content, max_steps)

    @_quietly
    def on_trace_start(self, trace):
        self._runs.start(trace.trace_id, getattr(trace, "name", None))

    @_quietly
    def on_trace_end(self, trace):
        self._runs.finish(trace.trace_id, group_id=getattr(trace, "group_id", None))

    def on_span_start(self, span):
        pass

    @_quietly
    def on_span_end(self, span):
        data = span.span_data
        kind = getattr(data, "type", "custom")
        step = {"type": {"function": "tool"}.get(kind, kind), "name": getattr(data, "name", None),
                "started_at": span.started_at, "ended_at": span.ended_at}
        if kind == "function":
            self._runs.content(step, "input", data.input)
            self._runs.content(step, "output", data.output)
        elif kind == "generation":
            step["model"] = data.model
            self._runs.content(step, "input", data.input)
            self._runs.content(step, "output", data.output)
        elif kind == "response":
            response = getattr(data, "response", None)
            step["model"] = getattr(response, "model", None)
            step["name"] = getattr(response, "id", None)
            self._runs.content(step, "output", getattr(response, "output", None))
        elif kind == "handoff":
            step.update(from_agent=data.from_agent, to_agent=data.to_agent)
        elif kind == "guardrail":
            step["triggered"] = bool(data.triggered)
        elif kind == "mcp_tools":
            step["name"] = data.server
        elif kind == "custom":
            self._runs.content(step, "output", data.data)
        elif kind not in ("agent",):
            return  # speech, transcription, turns and tasks are not steps of a decision
        if span.error:
            step["error"] = _error_text((span.error or {}).get("message") if isinstance(span.error, dict) else span.error)
        self._runs.step(span.trace_id, step)

    def shutdown(self):
        self.recorder.flush()

    def force_flush(self):
        self.recorder.flush()
