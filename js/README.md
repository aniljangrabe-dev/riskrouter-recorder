# riskrouter-recorder (Node)

Evidence from where decisions are already made. Each record stays in your own journal; only
SHA-256(salt || RFC 8785 of the record) and its kind are sent, in batches, to a log that speaks the
RiskRouter evidence API (https://riskrouter.eu/spec), or to none. Node 20 or later, no dependencies.

    npm install riskrouter-recorder

The same files are published at https://riskrouter.eu/kit/recorder/js/ if you would rather copy them into
your project: import them by path (`./recorder.mjs`) and run the tools as `node <file>.mjs`.

The command-line tools are run with the package named: `npx -p riskrouter-recorder riskrouter-logseal`.
A bare `npx riskrouter-logseal` would look for a different package called `riskrouter-logseal`, which is
not ours.

```js
import { createRecorder, withEvidence, EvidenceSpanProcessor } from 'riskrouter-recorder';

const recorder = createRecorder({ apiKey: process.env.RISKROUTER_API_KEY, journal: './evidence.jsonl' });

// 1. Directly
recorder.record({ kind: 'ai.decision', record_id: 'dec-2291', model: 'credit-v4', outcome: 'refer' });

// 2. Around a function that decides (digests of arguments and result by default)
const decide = withEvidence(recorder, scoreApplication, { kind: 'ai.decision' });

// 3. From OpenTelemetry: spans with evidence.kind become records
provider.addSpanProcessor(new EvidenceSpanProcessor(recorder));
span.setAttributes({ 'evidence.kind': 'ai.decision', 'evidence.outcome': 'refer' });

// Later: what a supervisor checks offline, with either RiskRouter verifier
const bundle = await recorder.bundle(record_digest);
await recorder.close();   // sends what is pending
```

## Files you keep elsewhere

A record can name a file it does not contain, such as a call recording (`mifid.call-recording`), an
invoice or a release: `await digestFile(path)` streams its SHA-256, and the file stays where it is.

## Completeness chains

With a chain secret, every record goes in a numbered chain, so a record later left out is a gap an
auditor sees (https://riskrouter.eu/spec#chains). The recorder adds `chain_tag`, `chain_seq` and
`chain_prev` itself, and carries on from its journal after a restart. One process writes a given chain.

```js
const recorder = createRecorder({ chainSecret: process.env.RISKROUTER_CHAIN_SECRET, chain: 'advice-desk' });
recorder.record({ kind: 'mifid.suitability', record_id: 'stmt-4411', advice: '...' });
const bundle = await recorder.completeness();   // the log's signed statement and every record of the chain
```

## Sealing at the OpenTelemetry Collector: `otlp-sealer`

No recorder library inside the application: the Collector exports to the sealer like to any OTLP/HTTP
backend, and spans and log records with the attribute `evidence.kind` become records. Everything else is
acknowledged and dropped.

```sh
RISKROUTER_API_KEY=... npx -p riskrouter-recorder riskrouter-otlp-sealer --port 4319 --journal /var/lib/evidence/journal.jsonl [--chain otel]
```

```yaml
exporters:
  otlphttp/riskrouter: { endpoint: http://127.0.0.1:4319, encoding: json, compression: none }
```

A batch is answered only after it is journalled, so the Collector retries what was not kept. Set
`RISKROUTER_SEALER_TOKEN` to require a bearer token. JSON encoding only.

## Agents: LangChain.js, LangGraph.js, the OpenAI Agents SDK, and MCP

Each agent run becomes one record, with its tool calls, model calls, handoffs, guardrails and graph
nodes as steps. Steps keep content digests (SHA-256 of the text), never the text, unless you pass
`includeContent: true`, which keeps the text in your journal; it is still never sent. No framework is a
dependency. More: https://riskrouter.eu/integrate#recorders.

```js
import { evidenceCallbackHandler, EvidenceTracingProcessor } from 'riskrouter-recorder/agents';
const fields = { system_ref: 'claims-agent', system_version: '2.3' };

await graph.invoke(state, { callbacks: [evidenceCallbackHandler(recorder, { fields })] });   // LangChain.js / LangGraph.js
addTraceProcessor(new EvidenceTracingProcessor(recorder, { fields }));                       // @openai/agents
```

In LangChain.js a nested call is part of the run only when it is given the run's config, as LangChain
asks: `RunnableLambda.from(async (input, config) => tool.invoke(args, config))`.

**MCP.** `riskrouter-recorder-mcp` (`mcp-server.mjs`) gives any MCP client (Claude, an IDE, an agent framework) a
`record_decision` tool. What it records is the agent's own statement of what it decided, and each record
says so (`source: "mcp.agent-statement"`); the framework adapters above record what the agent did. It
never returns a record or a salt to the agent.

```json
{ "mcpServers": { "evidence": { "command": "npx", "args": ["-y", "-p", "riskrouter-recorder", "riskrouter-recorder-mcp"],
  "env": { "RISKROUTER_API_KEY": "...", "RISKROUTER_JOURNAL": "/var/lib/agent/evidence.jsonl", "RISKROUTER_KINDS": "ai.decision" } } } }
```

- **Nothing is lost.** A record is written to the journal, and synced, before its digest is sent; an
  outage leaves it pending and the next flush sends it. A digest whose confirmation was lost in
  transit may be sent twice; both leaves prove the record.
- **Nothing is claimed.** `recorded` is written only from the log's answer, with its leaf index.
- **No lock-in.** Any compatible log (`api`, or `RISKROUTER_BASE`), including your own instance; with
  no key, nothing is sent and the journal keeps everything.
- **Your journal is yours.** It holds your records (mode 0600): keep it, back it up, and erase from it
  what data-protection law requires you to erase. It is not the append-only log.

Source: https://github.com/aniljangrabe-dev/riskrouter-recorder. Licence: Apache-2.0 (`LICENSE`), like the verifiers,
the conformance suite and the integration kit (https://github.com/aniljangrabe-dev/riskrouter-verify); the service itself is not licensed.

## Sealed security logs: `logseal`

Seal any log stream segment by segment, so that after an incident you can show that no sealed segment was
changed, removed or added. Each segment is written once to your own archive; only the salted digest of its
`security.log-segment` record (pack `nis2`) is sent. The log lines never leave your storage.

    journalctl -f -o short-iso | npx -p riskrouter-recorder riskrouter-logseal --source auth-server --archive /var/lib/logseal --lines 1000 --seconds 60
    npx -p riskrouter-recorder riskrouter-logseal verify --archive /var/lib/logseal --journal evidence-journal.jsonl

For an investigator, export a range: the segments, each segment's bundle with the log's proof, and a
manifest of every file's SHA-256, whose own digest is sealed so the handover is evidence too.

    npx -p riskrouter-recorder riskrouter-logseal export --source auth-server --archive /var/lib/logseal --from 240 --to 260 --out ./export-sec-0007 --by soc-analyst-4
    npx -p riskrouter-recorder riskrouter-logseal verify-export ./export-sec-0007

It detects nothing and names no attacker, and it cannot protect lines a machine writes after it has been
taken over: run it on a log collector the watched systems cannot reach. https://riskrouter.eu/security-logs
