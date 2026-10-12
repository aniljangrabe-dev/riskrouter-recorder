/**
 * riskrouter-recorder: evidence from where decisions are already made.
 * docs/recorders.md in the RiskRouter repository; https://riskrouter.eu/integrate#recorders
 *
 *   const recorder = createRecorder({ apiKey: process.env.RISKROUTER_API_KEY, journal: './evidence.jsonl' });
 *   recorder.record({ kind: 'ai.decision', record_id: 'dec-2291', model: 'credit-v4', outcome: 'refer' });
 *   await recorder.close();                         // on shutdown: sends what is pending
 *
 * The record and its salt stay here, in your journal. Only SHA-256(salt ||
 * RFC 8785 of the record) and the kind are sent, in batches, to any log that
 * speaks the RiskRouter evidence API: ours, your own instance, or none (with
 * no key, the journal is kept and nothing leaves this process).
 *
 * A record is written to the journal, and synced to disk, before its digest
 * is sent, so a crash or an outage never loses one: the next flush sends it.
 * If a confirmation is lost in transit, a digest may be sent twice and
 * becomes two leaves; either one proves the record.
 *
 * Node 20 or later. No dependencies: the OpenTelemetry span processor below
 * implements the interface by shape.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

export const JOURNAL_FORMAT = 'riskrouter-evidence-journal|1';
export const BUNDLE_FORMAT = 'riskrouter-record-bundle|1';
export const KIND = /^[a-z0-9][a-z0-9.-]{0,39}$/;
const RECORD_KEY = /^[a-z][a-z0-9_]{0,63}$/;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const BATCH_MAX = 500;

export class RecordError extends Error {}

/* ------------------------------------------------ the canonical record */

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

function serialise(value, depth, where) {
  if (depth > 32) throw new RecordError(`${where}: nested more than 32 deep`);
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new RecordError(`${where}: numbers must be whole and within ±(2^53 − 1); write money as integer cents`);
    return String(value);
  }
  if (typeof value === 'string') {
    if (LONE_SURROGATE.test(value)) throw new RecordError(`${where}: the string is not valid Unicode`);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v, i) => serialise(v, depth + 1, `${where}[${i}]`)).join(',')}]`;
  if (isObject(value)) {
    const keys = Object.keys(value);
    for (const k of keys) if (!RECORD_KEY.test(k)) throw new RecordError(`${where}: key ${JSON.stringify(k)} is not lower-case a-z, 0-9 and _ starting with a letter`);
    return `{${keys.sort().map((k) => `${JSON.stringify(k)}:${serialise(value[k], depth + 1, `${where}.${k}`)}`).join(',')}}`;
  }
  throw new RecordError(`${where}: ${typeof value} is not a JSON value a record may hold`);
}

/** RFC 8785 of a record, under the profile the specification fixes (https://riskrouter.eu/spec#records). */
export function canonicalRecord(record) {
  if (!isObject(record)) throw new RecordError('a record is a JSON object');
  return serialise(record, 1, '$');
}

/** SHA-256(salt || UTF-8(canonical)), lowercase hex. */
export function recordDigest(saltHex, record) {
  return crypto.createHash('sha256').update(Buffer.concat([Buffer.from(saltHex, 'hex'), Buffer.from(canonicalRecord(record), 'utf8')])).digest('hex');
}

/**
 * SHA-256 of a file, read as a stream, for a record that names a file it does
 * not contain: a call recording (mifid.call-recording), an invoice, a release.
 * The file stays where it is; only its digest goes in the record.
 */
export function digestFile(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (c) => h.update(c)).on('error', reject).on('end', () => resolve(h.digest('hex')));
  });
}

/* -------------------------------------------------------------- signing */

/**
 * An optional signer for v3 leaves: your own P-256 key, registered once with
 * POST /api/v2/evidence/keys. The signature goes inside the leaf.
 */
export async function createSigner(pkcs8B64) {
  const der = Buffer.from(pkcs8B64, 'base64');
  const P256 = { name: 'ECDSA', namedCurve: 'P-256' };
  const jwk = await crypto.webcrypto.subtle.exportKey('jwk', await crypto.webcrypto.subtle.importKey('pkcs8', der, P256, true, ['sign']));
  const key = await crypto.webcrypto.subtle.importKey('pkcs8', der, P256, false, ['sign']);
  const public_key = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  const key_id = crypto.createHash('sha256').update(JSON.stringify([jwk.x, jwk.y])).digest('hex').slice(0, 16);
  return {
    public_key, key_id,
    async signClaim(kind, record_digest) {
      const iso = new Date().toISOString();
      const claimed_at = `${iso.slice(0, 23)}${String(process.hrtime.bigint() % 1000n).padStart(3, '0')}Z`;
      const payload = ['riskrouter-evidence-claim', 'v3', kind, record_digest, key_id, claimed_at].join('|');
      const sig = await crypto.webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(payload));
      return { signer_key_id: key_id, claimed_at, client_signature: Buffer.from(sig).toString('base64') };
    }
  };
}

/* ------------------------------------------------------------- journal */

function openJournal(file) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify({ format: JOURNAL_FORMAT }) + '\n', { mode: 0o600, flag: 'wx' });
  }
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l, i) => {
    try { return JSON.parse(l); } catch { throw new Error(`${file}: line ${i + 1} is not JSON`); }
  });
  if (lines[0]?.format !== JOURNAL_FORMAT) throw new Error(`${file} is not a ${JOURNAL_FORMAT} journal`);
  const entries = new Map();
  const chains = new Map();   // chain_tag -> { seq, digest } of the last record journalled in it
  for (const l of lines.slice(1)) {
    const e = entries.get(l.record_digest) || {};
    if (l.type === 'pending' && l.chain_tag) {
      Object.assign(e, { chain_tag: l.chain_tag, chain_seq: l.chain_seq });
      if (!chains.has(l.chain_tag) || chains.get(l.chain_tag).seq < l.chain_seq) chains.set(l.chain_tag, { seq: l.chain_seq, digest: l.record_digest });
    }
    if (l.type === 'pending') Object.assign(e, { state: e.state || 'pending', kind: l.kind, salt_hex: l.salt_hex, record: l.record, at: l.at });
    else if (l.type === 'recorded') Object.assign(e, { state: 'recorded', leaf_index: l.leaf_index, created_at: l.created_at });
    else if (l.type === 'refused') Object.assign(e, { state: 'refused', code: l.code, reason: l.reason });
    entries.set(l.record_digest, e);
  }
  const fd = fs.openSync(file, 'a', 0o600);
  return {
    entries,
    chains,
    append(line) {
      fs.writeSync(fd, JSON.stringify({ ...line, at: new Date().toISOString() }) + '\n');
      fs.fsyncSync(fd);
    },
    close() { fs.closeSync(fd); }
  };
}

/* ------------------------------------------------------------ recorder */

/**
 * @param {object} o
 * @param {string} [o.apiKey]    your key; without one, nothing is sent (RISKROUTER_API_KEY)
 * @param {string} [o.api]       the log's base URL (RISKROUTER_BASE, default https://api.riskrouter.eu)
 * @param {string} [o.journal]   where records, salts and outcomes are kept (default ./evidence-journal.jsonl)
 * @param {string} [o.chainSecret]  hex; with it, records go in numbered completeness chains (docs/completeness.md)
 * @param {string} [o.chain]     the chain a record goes in when record() names none
 */
export function createRecorder({
  apiKey = process.env.RISKROUTER_API_KEY || null,
  api = process.env.RISKROUTER_BASE || 'https://api.riskrouter.eu',
  journal = 'evidence-journal.jsonl',
  batchSize = BATCH_MAX,
  flushIntervalMs = 5000,
  signer = null,
  chainSecret = process.env.RISKROUTER_CHAIN_SECRET || null,
  chain: defaultChain = null,
  fetchImpl = globalThis.fetch,
  onError = (e) => console.error(`riskrouter-recorder: ${e.message}`)
} = {}) {
  const base = String(api).replace(/\/+$/, '');
  const j = openJournal(journal);
  const size = Math.max(1, Math.min(BATCH_MAX, batchSize));
  let flushing = null;
  let lastError = null;
  let closed = false;

  const pending = () => [...j.entries].filter(([, e]) => e.state === 'pending').map(([record_digest, e]) => ({ record_digest, ...e }));

  async function call(method, path, body) {
    const r = await fetchImpl(base + path, {
      method,
      headers: { Accept: 'application/json', Authorization: `Bearer ${apiKey}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(20000)
    });
    let json = null;
    try { json = await r.json(); } catch { json = null; }
    return { status: r.status, body: json };
  }

  async function send(batch) {
    const entries = [];
    for (const e of batch) {
      entries.push({ record_digest: e.record_digest, kind: e.kind, ...(e.chain_tag ? { chain_tag: e.chain_tag, chain_seq: e.chain_seq } : {}),
        ...(signer ? await signer.signClaim(e.kind, e.record_digest) : {}) });
    }
    const r = await call('POST', '/api/v2/evidence/batch', { entries });
    if (r.status === 201 && Array.isArray(r.body?.entries) && r.body.entries.length === batch.length) {
      r.body.entries.forEach((got, i) => {
        if (got.record_digest !== batch[i].record_digest) throw new Error('the log answered for a different digest than was sent');
        j.append({ type: 'recorded', record_digest: got.record_digest, leaf_index: got.leaf_index, created_at: got.created_at, leaf_version: got.leaf_version ?? 2 });
        Object.assign(j.entries.get(got.record_digest), { state: 'recorded', leaf_index: got.leaf_index, created_at: got.created_at });
      });
      return { recorded: batch.length };
    }
    const code = r.body?.error?.code || `HTTP_${r.status}`;
    const message = r.body?.error?.message || '';
    if (r.status === 400) {
      // One entry the log will never accept: mark it, and keep the rest pending.
      const named = message.match(/^Entry (\d+):/);
      const bad = named ? batch[Number(named[1])] : batch.length === 1 ? batch[0] : null;
      if (bad) {
        j.append({ type: 'refused', record_digest: bad.record_digest, code, reason: message.slice(0, 300) });
        Object.assign(j.entries.get(bad.record_digest), { state: 'refused', code, reason: message });
        return { refused: 1, retry: batch.length > 1 };
      }
      return { split: true };
    }
    throw Object.assign(new Error(`the log answered ${r.status} ${code}${message ? `: ${message}` : ''}; ${batch.length} entr${batch.length === 1 ? 'y stays' : 'ies stay'} pending`), { status: r.status, code });
  }

  async function flushOnce() {
    if (!apiKey) return { sent: 0, local_only: true, pending: pending().length };
    let recorded = 0;
    let refused = 0;
    let queue = pending();
    let width = size;
    while (queue.length) {
      const batch = queue.slice(0, width);
      const r = await send(batch);
      if (r.split) { width = 1; continue; }
      recorded += r.recorded || 0;
      refused += r.refused || 0;
      queue = pending();
    }
    lastError = null;
    return { sent: recorded + refused, recorded, refused, pending: 0 };
  }

  if (chainSecret !== null && !/^(?:[0-9a-f]{2}){16,64}$/.test(chainSecret)) throw new Error('chainSecret is 16 to 64 bytes written as lowercase hex');
  const tagOf = (name) => crypto.createHmac('sha256', Buffer.from(chainSecret, 'hex')).update(`riskrouter-chain-tag|1|${name}`, 'utf8').digest('hex');

  const recorder = {
    /**
     * Keep a record; returns its digest and salt at once. The digest is sent at the next flush.
     * With a chain secret, the record goes in a completeness chain (`chain`, or the recorder's default):
     * chain_tag, chain_seq and chain_prev are added to it, so a record later left out is a gap.
     * One recorder process writes a given chain.
     */
    record(record, { kind, chain } = {}) {
      if (closed) throw new Error('the recorder is closed');
      const k = kind ?? record?.kind;
      if (typeof k !== 'string' || !KIND.test(k)) throw new RecordError('a record needs a kind: lower-case letters, digits, dots and hyphens, up to 40 characters');
      const chainName = chain ?? defaultChain;
      let link = null;
      if (chainName != null) {
        if (!chainSecret) throw new RecordError('a chain needs the recorder\'s chainSecret (RISKROUTER_CHAIN_SECRET)');
        if (['chain_tag', 'chain_seq', 'chain_prev'].some((f) => f in (record || {}))) throw new RecordError('the recorder sets chain_tag, chain_seq and chain_prev itself');
        const chain_tag = tagOf(String(chainName));
        const last = j.chains.get(chain_tag);
        link = { chain_tag, chain_seq: (last?.seq ?? 0) + 1, chain_prev: last?.digest ?? '0'.repeat(64) };
        record = { ...record, ...link };
      }
      const salt_hex = crypto.randomBytes(16).toString('hex');
      const record_digest = recordDigest(salt_hex, record);
      // A copy: what the caller changes afterwards is not what was digested.
      record = JSON.parse(canonicalRecord(record));
      const chained = link ? { chain_tag: link.chain_tag, chain_seq: link.chain_seq } : {};
      j.append({ type: 'pending', record_digest, kind: k, salt_hex, record, ...chained });
      j.entries.set(record_digest, { state: 'pending', kind: k, salt_hex, record, ...chained });
      if (link) j.chains.set(link.chain_tag, { seq: link.chain_seq, digest: record_digest });
      return { record_digest, kind: k, salt_hex, ...chained };
    },

    /** The chain_tag of a named chain, to give an auditor so they can ask the log about it. */
    chainTag(name = defaultChain) {
      if (!chainSecret || name == null) throw new Error('no chain: the recorder needs a chainSecret and a chain name');
      return tagOf(String(name));
    },

    /**
     * What you hand an auditor to show a chain is complete: the log's signed statement of the
     * chain and every record in it from this journal (riskrouter-completeness-bundle|1).
     */
    async completeness(name = defaultChain) {
      const tag = recorder.chainTag(name);
      const pages = [];
      let path = `/api/v2/evidence/chain?chain_tag=${tag}`;
      while (path) {
        const r = await call('GET', path);
        if (r.status !== 200) throw new Error(`the chain statement answered ${r.status}`);
        pages.push(r.body);
        path = r.body.next || null;
      }
      const records = [...j.entries.values()].filter((e) => e.chain_tag === tag).map((e) => ({ record: e.record, salt_hex: e.salt_hex }));
      return { format: 'riskrouter-completeness-bundle|1', chain: pages, records };
    },

    /** Send every pending digest. Never throws: a failure leaves entries pending and is returned. */
    async flush() {
      if (flushing) return flushing;
      flushing = flushOnce().catch((e) => { lastError = e; onError(e); return { error: e.message, pending: pending().length }; })
        .finally(() => { flushing = null; });
      return flushing;
    },

    /** What you hand a supervisor: the record, its salt and the proof. Both verifiers check it offline. */
    async bundle(record_digest) {
      const e = j.entries.get(record_digest);
      if (!e) throw new Error('no such record in this journal');
      if (e.state !== 'recorded') throw new Error(`that record is ${e.state}, not recorded yet`);
      const r = await call('GET', `/api/v2/evidence/proof?leaf_index=${e.leaf_index}`);
      if (r.status !== 200) throw new Error(`the proof answered ${r.status}`);
      return { format: BUNDLE_FORMAT, record: e.record, salt_hex: e.salt_hex, proof: r.body };
    },

    /** Where one record stands, without the record or its salt. */
    lookup(record_digest) {
      const e = j.entries.get(record_digest);
      if (!e) return null;
      return { record_digest, kind: e.kind, state: e.state, ...(e.state === 'recorded' ? { leaf_index: e.leaf_index, created_at: e.created_at } : {}),
        ...(e.state === 'refused' ? { code: e.code } : {}) };
    },

    status() {
      const counts = { pending: 0, recorded: 0, refused: 0 };
      for (const e of j.entries.values()) counts[e.state]++;
      return { ...counts, local_only: !apiKey, last_error: lastError?.message || null };
    },

    async close() {
      if (closed) return;
      closed = true;
      clearInterval(timer);
      await recorder.flush();
      j.close();
    }
  };

  const timer = setInterval(() => { if (pending().length) recorder.flush(); }, flushIntervalMs);
  timer.unref?.();
  return recorder;
}

/* ------------------------------------------------- drop-in: a function */

const digestOf = (value) => {
  try { return { form: 'rfc8785', digest: crypto.createHash('sha256').update(canonicalRecord({ value })).digest('hex') }; } catch {
    return { form: 'json', digest: crypto.createHash('sha256').update(JSON.stringify(value) ?? 'undefined').digest('hex') };
  }
};

/**
 * Wrap a function that makes a decision. By default the record holds digests
 * of its arguments and result, not the values: pass `build` to record the
 * fields a regime pack asks for. Recording never throws into the caller.
 */
export function withEvidence(recorder, fn, { kind, build, onError = (e) => console.error(`riskrouter-recorder: ${e.message}`) } = {}) {
  const keep = (args, result) => {
    try {
      const record = build ? build({ args, result }) : {
        kind, decision: fn.name || 'anonymous', decided_at: new Date().toISOString(),
        input_digest: digestOf(args).digest, output_digest: digestOf(result).digest
      };
      recorder.record(record, { kind });
    } catch (e) { onError(e); }
  };
  return function evidenced(...args) {
    const result = fn.apply(this, args);
    if (result && typeof result.then === 'function') return result.then((v) => { keep(args, v); return v; });
    keep(args, result);
    return result;
  };
}

/* ----------------------------------------- drop-in: OpenTelemetry spans */

const recordKey = (name) => {
  const k = name.toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^[^a-z]+/, '').slice(0, 64);
  return RECORD_KEY.test(k) ? k : null;
};
const recordValue = (v) => (typeof v === 'number' && !Number.isSafeInteger(v) ? String(v)
  : Array.isArray(v) ? v.map(recordValue) : v);
const hrToIso = (t) => (Array.isArray(t) ? new Date(t[0] * 1000 + t[1] / 1e6).toISOString() : null);

/**
 * An OpenTelemetry span processor (onStart, onEnd, forceFlush, shutdown). A
 * span with the attribute `evidence.kind` becomes a record: its name, trace
 * and span ids, times, status, and every other `evidence.*` attribute. Other
 * attributes are not recorded.
 *
 *   provider.addSpanProcessor(new EvidenceSpanProcessor(recorder));
 *   span.setAttributes({ 'evidence.kind': 'ai.decision', 'evidence.model': 'credit-v4', 'evidence.outcome': 'refer' });
 */
export class EvidenceSpanProcessor {
  constructor(recorder, { onError = (e) => console.error(`riskrouter-recorder: ${e.message}`) } = {}) {
    this.recorder = recorder;
    this.onError = onError;
  }

  onStart() {}

  onEnd(span) {
    try {
      const attrs = span.attributes || {};
      const kind = attrs['evidence.kind'];
      if (!kind) return;
      const fields = {};
      for (const [name, value] of Object.entries(attrs)) {
        if (!name.startsWith('evidence.') || name === 'evidence.kind') continue;
        const key = recordKey(name.slice('evidence.'.length));
        if (key) fields[key] = recordValue(value);
      }
      const ctx = span.spanContext();
      this.recorder.record({
        kind, name: span.name, trace_id: ctx.traceId, span_id: ctx.spanId,
        started_at: hrToIso(span.startTime), ended_at: hrToIso(span.endTime),
        status: span.status?.code ?? 0, fields
      }, { kind });
    } catch (e) { this.onError(e); }
  }

  forceFlush() { return this.recorder.flush().then(() => undefined); }

  shutdown() { return this.recorder.close(); }
}
