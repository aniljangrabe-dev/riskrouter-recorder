#!/usr/bin/env node
/**
 * otlp-sealer: seal evidence at the OpenTelemetry Collector, with no change to
 * application code. docs/recorders.md#collector in the RiskRouter repository.
 *
 * The Collector exports to it like to any OTLP/HTTP backend; it keeps every
 * span and log record that carries the attribute `evidence.kind` as a record
 * in your journal, and sends only the digests (the recorder in ./recorder.mjs
 * does the keeping and the sending). Everything else is acknowledged and
 * dropped: it never leaves the machine.
 *
 *   RISKROUTER_API_KEY=... node otlp-sealer.mjs --port 4319 --journal /var/lib/evidence/journal.jsonl
 *
 *   # in the Collector's configuration:
 *   exporters:
 *     otlphttp/riskrouter:
 *       endpoint: http://127.0.0.1:4319
 *       encoding: json
 *       compression: none
 *   service:
 *     pipelines:
 *       traces: { receivers: [otlp], exporters: [otlphttp/riskrouter, ...] }
 *       logs:   { receivers: [otlp], exporters: [otlphttp/riskrouter, ...] }
 *
 * A batch is acknowledged only after each of its records is written to the
 * journal and synced, so if the sealer stops first the Collector retries and
 * nothing is lost; the digests are sent after, in batches, as by any recorder.
 * It listens on 127.0.0.1 unless told otherwise, and with RISKROUTER_SEALER_TOKEN
 * set it accepts only requests carrying that bearer token.
 *
 * OTLP/HTTP with JSON encoding only (the Collector's `encoding: json`): a
 * protobuf body is refused with 415 and a message saying so. Node 20 or later,
 * no dependencies.
 */
import http from 'node:http';
import crypto from 'node:crypto';
import { createRecorder } from './recorder.mjs';

const MAX_BODY = 4 * 1024 * 1024;
const RECORD_KEY = /^[a-z][a-z0-9_]{0,63}$/;

/** An OTLP AnyValue as a record value: whole numbers stay numbers, anything else is written as text. */
function anyValue(v) {
  if (!v || typeof v !== 'object') return null;
  if ('stringValue' in v) return String(v.stringValue);
  if ('boolValue' in v) return Boolean(v.boolValue);
  if ('intValue' in v) {
    const n = Number(v.intValue);
    return Number.isSafeInteger(n) ? n : String(v.intValue);
  }
  if ('doubleValue' in v) return Number.isSafeInteger(v.doubleValue) ? v.doubleValue : String(v.doubleValue);
  if ('arrayValue' in v) return (v.arrayValue?.values || []).map(anyValue);
  if ('kvlistValue' in v) return Object.fromEntries((v.kvlistValue?.values || []).map((kv) => [fieldName(kv.key), anyValue(kv.value)]).filter(([k]) => k));
  if ('bytesValue' in v) return String(v.bytesValue);
  return null;
}

function fieldName(name) {
  const k = String(name).toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^[^a-z]+/, '').slice(0, 64);
  return RECORD_KEY.test(k) ? k : null;
}

const nanosToIso = (n) => {
  if (n == null || n === '' || n === '0') return null;
  const ns = BigInt(n);
  const ms = Number(ns / 1000000n);
  const micros = String(ns % 1000000000n / 1000n).padStart(6, '0');
  return `${new Date(ms).toISOString().slice(0, 19)}.${micros}Z`;
};

/** The evidence.* attributes of one span or log record, or null when it carries no evidence.kind. */
function evidenceOf(attributes) {
  const attrs = new Map((attributes || []).map((a) => [a.key, anyValue(a.value)]));
  const kind = attrs.get('evidence.kind');
  if (typeof kind !== 'string') return null;
  const fields = {};
  for (const [name, value] of attrs) {
    if (!name.startsWith('evidence.') || name === 'evidence.kind') continue;
    const key = fieldName(name.slice('evidence.'.length));
    if (key && value !== null) fields[key] = value;
  }
  return { kind, fields };
}

/** Records from one OTLP/JSON export request: spans and log records that carry evidence.kind. */
export function recordsFromOtlp(body) {
  const out = [];
  for (const rs of body?.resourceSpans || []) {
    const service = (rs.resource?.attributes || []).find((a) => a.key === 'service.name');
    for (const ss of rs.scopeSpans || []) {
      for (const span of ss.spans || []) {
        const ev = evidenceOf(span.attributes);
        if (!ev) continue;
        out.push({
          kind: ev.kind, source: 'otel.span', name: String(span.name || ''), service: service ? anyValue(service.value) : null,
          trace_id: String(span.traceId || ''), span_id: String(span.spanId || ''),
          started_at: nanosToIso(span.startTimeUnixNano), ended_at: nanosToIso(span.endTimeUnixNano),
          status: Number(span.status?.code ?? 0), fields: ev.fields
        });
      }
    }
  }
  for (const rl of body?.resourceLogs || []) {
    const service = (rl.resource?.attributes || []).find((a) => a.key === 'service.name');
    for (const sl of rl.scopeLogs || []) {
      for (const lr of sl.logRecords || []) {
        const ev = evidenceOf(lr.attributes);
        if (!ev) continue;
        out.push({
          kind: ev.kind, source: 'otel.log', service: service ? anyValue(service.value) : null,
          trace_id: String(lr.traceId || ''), span_id: String(lr.spanId || ''),
          observed_at: nanosToIso(lr.timeUnixNano || lr.observedTimeUnixNano),
          severity: String(lr.severityText || ''), fields: ev.fields
        });
      }
    }
  }
  // A record holds no nulls the source did not send: drop empty optional fields.
  return out.map((r) => Object.fromEntries(Object.entries(r).filter(([, v]) => v !== null && v !== '')));
}

/**
 * The sealer as a request handler, around a recorder you made. Returns the
 * http server (not yet listening).
 */
export function createSealer(recorder, { token = null, chain = null, onError = (e) => console.error(`otlp-sealer: ${e.message}`) } = {}) {
  const expected = token ? Buffer.from(`Bearer ${token}`) : null;
  return http.createServer((req, res) => {
    const answer = (status, doc) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(doc));
    };
    if (req.method !== 'POST' || !['/v1/traces', '/v1/logs'].includes(req.url.split('?')[0])) return answer(404, { message: 'POST /v1/traces or /v1/logs' });
    if (expected) {
      const got = Buffer.from(String(req.headers.authorization || ''));
      if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return answer(401, { message: 'a bearer token is required' });
    }
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) {
      return answer(415, { message: 'send OTLP/HTTP with JSON encoding: set encoding: json and compression: none on the exporter' });
    }
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size <= MAX_BODY) chunks.push(c); });
    req.on('end', () => {
      if (size > MAX_BODY) return answer(413, { message: `a request is at most ${MAX_BODY} bytes; lower the exporter's batch size` });
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return answer(400, { message: 'not JSON' }); }
      let kept = 0;
      let rejected = 0;
      for (const record of recordsFromOtlp(body)) {
        try {
          recorder.record(record, { kind: record.kind, ...(chain ? { chain } : {}) });
          kept++;
        } catch (e) {
          // A record that has no canonical form (a bad kind, an unrepresentable value) is reported, not retried for ever.
          rejected++;
          onError(e);
        }
      }
      // Journalled and synced before this answer: an unacknowledged batch is retried by the Collector.
      const partial = req.url.startsWith('/v1/traces') ? { partialSuccess: rejected ? { rejectedSpans: String(rejected), errorMessage: 'records without a canonical form' } : {} }
        : { partialSuccess: rejected ? { rejectedLogRecords: String(rejected), errorMessage: 'records without a canonical form' } : {} };
      answer(200, kept || rejected ? partial : {});
    });
  });
}

/* -------------------------------------------------------------------- cli */

function opt(name, fallback) {
  const i = process.argv.indexOf(name);
  return i === -1 ? fallback : process.argv[i + 1];
}

if (process.argv[1] && process.argv[1].endsWith('otlp-sealer.mjs')) {
  const recorder = createRecorder({ journal: opt('--journal', 'evidence-journal.jsonl'), chain: opt('--chain', null) });
  const server = createSealer(recorder, { token: process.env.RISKROUTER_SEALER_TOKEN || null });
  const port = Number(opt('--port', 4319));
  const host = opt('--host', '127.0.0.1');
  server.listen(port, host, () => {
    console.error(`otlp-sealer: listening on http://${host}:${port} (OTLP/HTTP JSON); ${recorder.status().local_only ? 'no key: journal only, nothing is sent' : 'digests go to the log'}`);
  });
  const stop = async () => { server.close(); await recorder.close(); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
