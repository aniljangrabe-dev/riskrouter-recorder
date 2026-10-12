#!/usr/bin/env node
/**
 * riskrouter-recorder-mcp: an MCP server that gives an AI agent a tool to
 * record its decisions as evidence (docs/agent-adapters.md).
 *
 *   {"mcpServers": {"evidence": {"command": "npx", "args": ["-y", "-p", "riskrouter-recorder", "riskrouter-recorder-mcp"],
 *     "env": {"RISKROUTER_API_KEY": "...", "RISKROUTER_JOURNAL": "/var/lib/agent/evidence.jsonl"}}}}
 *
 * What it records is the agent's own statement of what it decided, not an
 * observation of it, and every record says so (source: "mcp.agent-statement").
 * For what the agent actually did, use the framework adapters in agents.mjs.
 *
 * The record stays in the operator's journal; only its salted digest leaves,
 * as with every recorder. The server never hands a record or a salt back to
 * the agent: the journal is the operator's, not the model's.
 *
 * Environment: RISKROUTER_API_KEY (without one, nothing is sent), RISKROUTER_BASE,
 * RISKROUTER_JOURNAL (default ./evidence-journal.jsonl), RISKROUTER_KINDS (the
 * kinds the agent may use, comma-separated; default ai.decision).
 *
 * Transport: stdio, newline-delimited JSON-RPC 2.0. Node 20+, no dependencies.
 */
import fs from 'node:fs';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { createRecorder, KIND } from './recorder.mjs';

export const SOURCE = 'mcp.agent-statement';
const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const log = (m) => process.stderr.write(`riskrouter-recorder-mcp: ${m}\n`);

const TOOLS = [
  {
    name: 'record_decision',
    title: 'Record a decision as evidence',
    description: 'Record, as evidence, a decision you have taken: what you decided, about which case (a reference, never a name or an email), and why. ' +
      'The record is kept in the operator\'s journal and only its salted digest is sent to the evidence log, so it can later be shown to be unchanged. ' +
      'Keys are lower-case letters, digits and underscores; numbers are whole. Returns the record\'s digest.',
    inputSchema: {
      type: 'object',
      properties: {
        kind: { type: 'string', description: 'The kind of record. Allowed kinds are listed by the operator; the default is the first of them.' },
        record: { type: 'object', description: 'The decision record, for example {"case_ref": "app-552091", "decision": "refer to a person", "reason": "income could not be verified"}.' },
        wait: { type: 'boolean', description: 'Wait until the log has the digest and return its position. Default false.' }
      },
      required: ['record']
    }
  },
  {
    name: 'evidence_lookup',
    title: 'Where a recorded decision stands',
    description: 'Given a record_digest returned by record_decision, say whether it is pending, recorded (with its position in the log) or refused.',
    inputSchema: { type: 'object', properties: { record_digest: { type: 'string' } }, required: ['record_digest'] }
  },
  {
    name: 'evidence_status',
    title: 'Evidence recorder status',
    description: 'How many decisions are pending, recorded and refused in this journal, and whether a log is configured.',
    inputSchema: { type: 'object', properties: {} }
  }
];

export function createServer({ recorder, kinds }) {
  const allowed = kinds.length ? kinds : ['ai.decision'];

  async function call(name, args = {}) {
    if (name === 'record_decision') {
      const kind = args.kind ?? allowed[0];
      if (!allowed.includes(kind)) throw new Error(`kind ${JSON.stringify(kind)} is not one this server records (${allowed.join(', ')})`);
      const record = args.record;
      if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('record must be an object');
      const kept = recorder.record({ ...record, kind, source: SOURCE, stated_at: new Date().toISOString() }, { kind });
      if (args.wait) await recorder.flush();
      return recorder.lookup(kept.record_digest);
    }
    if (name === 'evidence_lookup') {
      const found = recorder.lookup(String(args.record_digest || ''));
      if (!found) throw new Error('no record with that digest in this journal');
      return found;
    }
    if (name === 'evidence_status') return recorder.status();
    throw Object.assign(new Error(`no tool named ${name}`), { rpc: -32602 });
  }

  return async function handle(msg) {
    const { id, method, params } = msg;
    const reply = (result) => ({ jsonrpc: '2.0', id, result });
    const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
    if (id === undefined || id === null) return null;           // a notification: nothing to answer
    if (method === 'initialize') {
      const asked = params?.protocolVersion;
      return reply({
        protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'riskrouter-recorder', version: '0.1.1' },
        instructions: 'Use record_decision each time you take a decision the operator must be able to evidence later. ' +
          'Refer to people by reference, never by name or email.'
      });
    }
    if (method === 'ping') return reply({});
    if (method === 'tools/list') return reply({ tools: TOOLS });
    if (method === 'tools/call') {
      try {
        const out = await call(params?.name, params?.arguments);
        return reply({ content: [{ type: 'text', text: JSON.stringify(out) }], structuredContent: out, isError: false });
      } catch (e) {
        if (e.rpc) return fail(e.rpc, e.message);
        return reply({ content: [{ type: 'text', text: e.message }], isError: true });
      }
    }
    return fail(-32601, `method not found: ${method}`);
  };
}

async function main() {
  const kinds = (process.env.RISKROUTER_KINDS || 'ai.decision').split(',').map((k) => k.trim()).filter(Boolean);
  for (const k of kinds) if (!KIND.test(k)) throw new Error(`RISKROUTER_KINDS: ${JSON.stringify(k)} is not a kind`);
  const recorder = createRecorder({ journal: process.env.RISKROUTER_JOURNAL || 'evidence-journal.jsonl', onError: (e) => log(e.message) });
  const handle = createServer({ recorder, kinds });
  const rl = readline.createInterface({ input: process.stdin });
  const pending = new Set();
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }) + '\n');
      return;
    }
    const p = handle(msg).then((out) => { if (out) process.stdout.write(JSON.stringify(out) + '\n'); })
      .catch((e) => log(e.message)).finally(() => pending.delete(p));
    pending.add(p);
  });
  rl.on('close', async () => {
    await Promise.allSettled([...pending]);
    await recorder.close();
    process.exit(0);
  });
}

const invoked = (() => { try { return fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })();
if (invoked) {
  main().catch((e) => { log(e.message); process.exit(1); });
}
