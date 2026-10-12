/**
 * Agent adapters: each agent run becomes one evidence record (docs/agent-adapters.md).
 *
 *   import { createRecorder } from './recorder.mjs';
 *   import { evidenceCallbackHandler, EvidenceTracingProcessor } from './agents.mjs';
 *   const recorder = createRecorder({ journal: './evidence.jsonl' });
 *
 *   // LangChain.js and LangGraph.js: a callback handler
 *   await graph.invoke(state, { callbacks: [evidenceCallbackHandler(recorder, { fields: { system_ref: 'claims-agent' } })] });
 *
 *   // The OpenAI Agents SDK: a tracing processor
 *   import { addTraceProcessor } from '@openai/agents';
 *   addTraceProcessor(new EvidenceTracingProcessor(recorder, { fields: { system_ref: 'claims-agent' } }));
 *
 * One leaf per run, not per step. By default each step keeps content digests,
 * SHA-256 of the text the framework handed over, never the text: prompts,
 * tool arguments and outputs stay in your own logs (includeContent keeps them
 * in your journal instead; they are still never sent). Neither framework is a
 * dependency, and a failure in an adapter never reaches the agent.
 */
import crypto from 'node:crypto';

export const RUN_KIND = 'ai.agent-run';
const ERROR_MAX = 300;
const warn = (e) => console.error(`riskrouter-recorder: an agent event was not recorded: ${e.message}`);

function sortedJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (typeof value.toJSON === 'function') return sortedJson(value.toJSON());
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? 'null' : sortedJson(v))).join(',')}]`;
  return `{${Object.keys(value).filter((k) => value[k] !== undefined && typeof value[k] !== 'function').sort()
    .map((k) => `${JSON.stringify(k)}:${sortedJson(value[k])}`).join(',')}}`;
}

/** The text a content digest is taken of (docs/agent-adapters.md). */
function text(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value.content === 'string') return value.content;
  return sortedJson(value);
}

/** SHA-256 of the UTF-8 text of a value, as every adapter computes it. */
export const contentDigest = (value) => crypto.createHash('sha256').update(text(value), 'utf8').digest('hex');

const errorText = (e) => (e instanceof Error ? `${e.name}: ${e.message}` : String(e?.message ?? e)).slice(0, ERROR_MAX);
const now = () => new Date().toISOString();

/** Runs in progress, and turning a finished one into a record. */
class Runs {
  constructor(recorder, framework, { kind = RUN_KIND, fields = {}, build = null, includeContent = false, maxSteps = 500 } = {}) {
    Object.assign(this, { recorder, framework, kind, fields, build, includeContent, maxSteps });
    this.runs = new Map();
  }

  content(step, prefix, value) {
    if (value === undefined || value === null) return;
    step[`${prefix}_digest`] = contentDigest(value);
    if (this.includeContent) step[prefix] = text(value);
  }

  start(id, name, startedAt) {
    this.runs.set(id, { run_id: String(id), name: name || 'run', started_at: startedAt || now(), steps: [], leftOut: 0 });
  }

  step(id, step) {
    const run = this.runs.get(id);
    if (!run) return;
    if (run.steps.length < this.maxSteps) run.steps.push(Object.fromEntries(Object.entries(step).filter(([, v]) => v !== undefined && v !== null)));
    else run.leftOut++;
  }

  finish(id, { error = null, endedAt = null, ...extra } = {}) {
    const run = this.runs.get(id);
    if (!run) return null;
    this.runs.delete(id);
    let record = {
      ...this.fields, kind: this.kind, framework: this.framework, run_id: run.run_id, name: run.name,
      started_at: run.started_at, ended_at: endedAt || now(), outcome: error !== null ? 'error' : 'completed', steps: run.steps
    };
    if (error !== null) record.error = errorText(error);
    if (run.leftOut) record.steps_left_out = run.leftOut;
    for (const [k, v] of Object.entries(extra)) if (v !== undefined && v !== null) record[k] = v;
    if (this.build) record = this.build(record);
    return this.recorder.record(record, { kind: record.kind ?? this.kind });
  }
}

const quietly = (onError, fn) => (...args) => { try { fn(...args); } catch (e) { onError(e); } };

/* ------------------------------------------------ LangChain.js / LangGraph.js */

/**
 * A LangChain.js callback handler, as the plain object of handler methods
 * LangChain accepts, so @langchain/core is not a dependency. The outermost run,
 * whatever it is (a graph, a chain, an agent, a tool called on its own),
 * becomes one record when it ends; tool calls, model calls, retrievals and
 * LangGraph nodes inside it become its steps.
 */
export function evidenceCallbackHandler(recorder, { onError = warn, ...options } = {}) {
  const runs = new Runs(recorder, 'langchain', options);
  const root = new Map();      // run id -> the outermost run it belongs to
  const open = new Map();      // run id -> the step being built
  const inputs = new Map();    // outermost run id -> digest of its input
  const nameOf = (serialized, runName, fallback) => runName || serialized?.name || serialized?.id?.at?.(-1) || fallback;
  // LangChain.js reports a chain's plain value as { input } or { output }; Python passes the value
  // itself. Unwrapped, both languages digest the same text.
  const unwrap = (v, key) => (v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 1 && key in v ? v[key] : v);

  const enter = (runId, parentRunId, name, step, input) => {
    if (!parentRunId) {
      root.set(runId, runId);
      runs.start(runId, name);
      if (input !== undefined) inputs.set(runId, contentDigest(input));
    } else root.set(runId, root.get(parentRunId) ?? parentRunId);
    if (step) open.set(runId, { name, ...step, started_at: now() });
  };
  const leave = (runId, { output, error = null } = {}) => {
    const step = open.get(runId);
    const top = root.get(runId);
    open.delete(runId);
    root.delete(runId);
    if (step && top !== undefined) {
      step.ended_at = now();
      if (error !== null) step.error = errorText(error);
      else runs.content(step, 'output', output);
      runs.step(top, step);
    }
    if (top !== undefined && top === runId) {
      const input_digest = inputs.get(runId);
      inputs.delete(runId);
      runs.finish(runId, { error, input_digest, output_digest: error === null && output !== undefined ? contentDigest(output) : null });
    }
  };
  const modelStart = (serialized, prompt, runId, parentRunId, extraParams, metadata, runName) => {
    const params = extraParams?.invocation_params || {};
    const step = { type: 'generation', model: metadata?.ls_model_name || params.model || params.model_name };
    runs.content(step, 'input', prompt);
    enter(runId, parentRunId, nameOf(serialized, runName, 'model'), step, prompt);
  };

  return {
    name: 'riskrouter-evidence',
    awaitHandlers: true,
    // The order the callback manager passes, which is not the order its type declaration names.
    handleChainStart: quietly(onError, (chain, chainInputs, runId, parentRunId, tags, metadata, runType, runName) => {
      const name = nameOf(chain, runName, 'chain');
      const node = metadata?.langgraph_node;
      const step = node && parentRunId && name === node ? { type: 'node', name: node } : null;
      if (step) runs.content(step, 'input', unwrap(chainInputs, 'input'));
      enter(runId, parentRunId, name, step, unwrap(chainInputs, 'input'));
    }),
    handleChainEnd: quietly(onError, (outputs, runId) => leave(runId, { output: unwrap(outputs, 'output') })),
    handleChainError: quietly(onError, (err, runId) => leave(runId, { error: err })),
    handleToolStart: quietly(onError, (tool, input, runId, parentRunId, tags, metadata, runName) => {
      const step = { type: 'tool' };
      runs.content(step, 'input', input);
      enter(runId, parentRunId, nameOf(tool, runName, 'tool'), step, input);
    }),
    handleToolEnd: quietly(onError, (output, runId) => leave(runId, { output })),
    handleToolError: quietly(onError, (err, runId) => leave(runId, { error: err })),
    handleLLMStart: quietly(onError, (llm, prompts, runId, parentRunId, extraParams, tags, metadata, runName) =>
      modelStart(llm, prompts, runId, parentRunId, extraParams, metadata, runName)),
    handleChatModelStart: quietly(onError, (llm, messages, runId, parentRunId, extraParams, tags, metadata, runName) =>
      modelStart(llm, messages.map((batch) => batch.map(text)), runId, parentRunId, extraParams, metadata, runName)),
    handleLLMEnd: quietly(onError, (output, runId) => {
      const texts = (output?.generations || []).map((batch) => batch.map((g) => g.text));
      leave(runId, { output: texts.length === 1 && texts[0].length === 1 ? texts[0][0] : texts });
    }),
    handleLLMError: quietly(onError, (err, runId) => leave(runId, { error: err })),
    handleRetrieverStart: quietly(onError, (retriever, query, runId, parentRunId, tags, metadata, name) => {
      const step = { type: 'retriever' };
      runs.content(step, 'input', query);
      enter(runId, parentRunId, nameOf(retriever, name, 'retriever'), step, query);
    }),
    handleRetrieverEnd: quietly(onError, (documents, runId) => leave(runId, { output: documents.map((d) => d?.pageContent ?? d) })),
    handleRetrieverError: quietly(onError, (err, runId) => leave(runId, { error: err }))
  };
}

/* ------------------------------------------------------- OpenAI Agents SDK */

/**
 * A tracing processor for the OpenAI Agents SDK (JavaScript). Each trace (one
 * run, or a withTrace() around several) becomes one record when it ends;
 * function calls, model generations, handoffs, guardrails and agent spans
 * inside it become its steps.
 *
 * addTraceProcessor keeps the SDK's own exporter, which sends traces to
 * OpenAI; use setTraceProcessors([...]) if nothing should be sent there.
 */
export class EvidenceTracingProcessor {
  constructor(recorder, { onError = warn, ...options } = {}) {
    this.recorder = recorder;
    this.onError = onError;
    this.runs = new Runs(recorder, 'openai-agents', options);
  }

  async onTraceStart(trace) {
    try { this.runs.start(trace.traceId, trace.name); } catch (e) { this.onError(e); }
  }

  async onTraceEnd(trace) {
    try { this.runs.finish(trace.traceId, { group_id: trace.groupId }); } catch (e) { this.onError(e); }
  }

  async onSpanStart() {}

  async onSpanEnd(span) {
    try {
      const data = span.spanData || {};
      const type = data.type || 'custom';
      const step = { type: type === 'function' ? 'tool' : type, name: data.name, started_at: span.startedAt, ended_at: span.endedAt };
      if (type === 'function' || type === 'generation') {
        if (type === 'generation') step.model = data.model;
        this.runs.content(step, 'input', data.input);
        this.runs.content(step, 'output', data.output);
      } else if (type === 'response') {
        step.name = data.response_id;
        step.model = data._response?.model;
        this.runs.content(step, 'output', data._response?.output);
      } else if (type === 'handoff') Object.assign(step, { from_agent: data.from_agent, to_agent: data.to_agent });
      else if (type === 'guardrail') step.triggered = Boolean(data.triggered);
      else if (type === 'mcp_tools') step.name = data.server;
      else if (type === 'custom') this.runs.content(step, 'output', data.data);
      else if (type !== 'agent') return; // speech, transcription, turns and tasks are not steps of a decision
      if (span.error) step.error = errorText(span.error);
      this.runs.step(span.traceId, step);
    } catch (e) { this.onError(e); }
  }

  async shutdown() { await this.recorder.flush(); }

  async forceFlush() { await this.recorder.flush(); }
}
