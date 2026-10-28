#!/usr/bin/env node
/**
 * inspector: the file you hand a supervisor, an auditor or a court, in one
 * command. Everything a recorder journal sealed in a period (from any of the
 * recorders: decisions, files from folderseal, rows from dbseal, log segments)
 * goes into one new folder that anyone can check without us:
 *
 *   RISKROUTER_API_KEY=rr_... npx -p riskrouter-recorder riskrouter-inspector \
 *     --journal evidence-journal.jsonl --from 2026-10-01 --to 2026-10-31 --out ./inspector-2026-10 \
 *     [--kind file.seal] [--chain folder:advice-files] [--title "Advice files, October 2026"] [--by <your ref>]
 *   npx -p riskrouter-recorder riskrouter-inspector verify ./inspector-2026-10
 *
 * The folder holds a receipt for each record (riskrouter-record-bundle|1: the
 * record, its salt and the log's proof), a completeness statement for each
 * chain named (none of its records left out), the log's public signing key,
 * an index.html that lists every record and says how to check them (it runs
 * no script and makes no request), and MANIFEST.json, which lists every file
 * with its SHA-256. The manifest's own digest is sealed too, as an
 * `evidence.export` record, so the handover is itself evidence of what was
 * handed over and when.
 *
 * It holds your records and their salts: hand it only to whom you would show
 * the records. Written to a new folder, never into one that exists.
 * No dependencies. Apache-2.0, like the rest of recorders/.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRecorder, recordDigest, KIND as KIND_PATTERN } from './recorder.mjs';

export const FORMAT = 'riskrouter-inspector-file|1';
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const REF = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Every recorded entry of the journal, with its record and salt. */
function journalRecorded(journal) {
  const byDigest = new Map();
  for (const l of fs.readFileSync(journal, 'utf8').split('\n').filter(Boolean).slice(1).map((x) => JSON.parse(x))) {
    const e = byDigest.get(l.record_digest) || { record_digest: l.record_digest };
    if (l.type === 'pending') Object.assign(e, { record: l.record, kind: l.kind, state: e.state || 'pending' });
    else if (l.type === 'recorded') Object.assign(e, { state: 'recorded', leaf_index: l.leaf_index, created_at: l.created_at });
    else if (l.type === 'refused') Object.assign(e, { state: 'refused' });
    byDigest.set(l.record_digest, e);
  }
  return [...byDigest.values()];
}

/** What a reader sees first about a record: its own reference, or the file or row it is about. */
const labelOf = (r) => r.record_id || r.file_name || (r.table_ref ? `${r.table_ref} ${r.row_key}` : '') || r.source_ref || '';

const HOW = [
  'Each file in receipts/ is a receipt: a record, its salt and the log’s proof. Three ways to check one, none of which needs us:',
  '1. Open https://riskrouter.eu/check, drop the receipt (and, for a file seal, the file itself). The page checks it in the browser; nothing is uploaded.',
  '2. Offline: python3 riskrouter_verify.py receipts/<n>.json --key signing-key.json  (the verifier is one file, standard library only:',
  '   https://riskrouter.eu/kit/verifier/riskrouter_verify.py, and at https://github.com/aniljangrabe-dev/riskrouter-verify).',
  '3. Compare signing-key.json with the key published at https://github.com/aniljangrabe-dev/riskrouter-verify (anchors/), so the key is not only ours to vouch for.',
  'Each file in completeness/ shows a chain is complete: python3 riskrouter_verify.py completeness/<name>.json --key signing-key.json.',
  'MANIFEST.json lists every file here with its SHA-256; its own digest is sealed (MANIFEST.riskrouter-receipt.json), so the file set cannot be changed unseen.'
];

function indexHtml({ title, period, rows, chains, exportedAt }) {
  const tr = rows.map((r) => `<tr><td>${esc(r.leaf_index)}</td><td>${esc(r.created_at)}</td><td>${esc(r.kind)}</td><td>${esc(r.label)}</td>` +
    `<td><code>${esc(r.record_digest.slice(0, 16))}…</code></td><td><a href="${esc(r.receipt)}">${esc(r.receipt)}</a></td></tr>`).join('\n');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:72rem;padding:0 1rem;color:#1a1a1a;background:#fff}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}
code{font-family:ui-monospace,monospace}.lede{color:#444}</style></head>
<body>
<h1>${esc(title)}</h1>
<p class="lede">${esc(rows.length)} sealed record(s), ${esc(period)}. Exported ${esc(exportedAt)}. Every record here is in an append-only
public log as a salted SHA-256 digest; the record itself never left its holder. This page runs no script and makes no request.</p>
<h2>How to check it</h2>
${HOW.map((l) => `<p>${esc(l)}</p>`).join('\n')}
${chains.length ? `<h2>Completeness</h2>\n<ul>${chains.map((c) => `<li><a href="${esc(c.file)}">${esc(c.name)}</a>: ${esc(c.records)} record(s) in the chain</li>`).join('')}</ul>` : ''}
<h2>Records</h2>
<table><thead><tr><th>Entry</th><th>Sealed at</th><th>Kind</th><th>About</th><th>Digest</th><th>Receipt</th></tr></thead>
<tbody>
${tr}
</tbody></table>
</body></html>
`;
}

/**
 * @param {object} o
 * @param {object} o.recorder   a recorder on the same journal (it fetches the proofs, and seals the manifest)
 * @param {string} o.journal
 * @param {string} o.out        a folder that does not exist yet
 * @param {string} [o.from]     YYYY-MM-DD, the first day sealed (log time, UTC)
 * @param {string} [o.to]       YYYY-MM-DD, the last day sealed
 * @param {string[]} [o.kinds]  only records of these kinds
 * @param {string[]} [o.chains] completeness chains to include, by name (needs the recorder's chainSecret)
 */
export async function exportInspectorFile({ recorder, journal, out, from = null, to = null, kinds = [], chains = [], title = null, exportedBy = null,
  api = process.env.RISKROUTER_BASE || 'https://api.riskrouter.eu', fetchImpl = globalThis.fetch, now = () => new Date() }) {
  if (from !== null && !DATE.test(from)) throw new Error('--from is YYYY-MM-DD');
  if (to !== null && !DATE.test(to)) throw new Error('--to is YYYY-MM-DD');
  for (const k of kinds) if (!KIND_PATTERN.test(k)) throw new Error(`${k} is not a kind`);
  if (exportedBy !== null && !REF.test(exportedBy)) throw new Error('--by is your own reference for the person, never a name');
  if (fs.existsSync(out)) throw new Error(`${out} exists: an inspector's file is written to a new folder`);
  const inPeriod = (t) => (!from || t.slice(0, 10) >= from) && (!to || t.slice(0, 10) <= to);
  const all = journalRecorded(journal).filter((e) => e.record && e.kind !== 'evidence.export' && (!kinds.length || kinds.includes(e.kind)));
  const waiting = all.filter((e) => e.state === 'pending');
  if (waiting.length) throw new Error(`${waiting.length} record(s) are not recorded in the log yet; run the recorder (flush) first`);
  const chosen = all.filter((e) => e.state === 'recorded' && inPeriod(e.created_at)).sort((a, b) => a.leaf_index - b.leaf_index);
  if (!chosen.length && !chains.length) throw new Error('no recorded record in that period');

  fs.mkdirSync(path.join(out, 'receipts'), { recursive: true });
  const files = [];
  const keep = (rel, bytes) => {
    fs.mkdirSync(path.dirname(path.join(out, rel)), { recursive: true });
    fs.writeFileSync(path.join(out, rel), bytes, { flag: 'wx', mode: 0o440 });
    files.push({ path: rel, sha256: sha256(bytes), bytes: bytes.length });
  };
  const json = (v) => Buffer.from(`${JSON.stringify(v, null, 2)}\n`);

  const rows = [];
  for (const e of chosen) {
    const receipt = `receipts/${String(e.leaf_index).padStart(10, '0')}.json`;
    keep(receipt, json(await recorder.bundle(e.record_digest)));
    rows.push({ leaf_index: e.leaf_index, created_at: e.created_at, kind: e.kind, label: labelOf(e.record), record_digest: e.record_digest, receipt });
  }
  const chainRows = [];
  for (const name of chains) {
    const bundle = await recorder.completeness(name);
    const file = `completeness/${sha256(name).slice(0, 16)}.json`;
    keep(file, json({ ...bundle, chain_name: name }));
    chainRows.push({ name, file, records: bundle.records.length });
  }
  const key = await fetchImpl(`${String(api).replace(/\/+$/, '')}/api/v1/ledger/pubkey`, { signal: AbortSignal.timeout(20000) });
  if (!key.ok) throw new Error(`the log's public key answered ${key.status}`);
  keep('signing-key.json', Buffer.from(await key.text()));

  const exportedAt = now().toISOString();
  const period = `${from ? `from ${from}` : 'from the first record'} ${to ? `to ${to}` : 'to the last'}`;
  const heading = title || `Sealed records, ${period}`;
  keep('README.txt', Buffer.from(`${heading}\n\n${rows.length} sealed record(s), ${period}. Exported ${exportedAt}.\n\n${HOW.join('\n')}\n`));
  keep('index.html', Buffer.from(indexHtml({ title: heading, period, rows, chains: chainRows, exportedAt })));

  const manifest = { format: FORMAT, title: heading, from, to, kinds, exported_at: exportedAt, ...(exportedBy ? { exported_by: exportedBy } : {}),
    records: rows.length, chains: chainRows.map((c) => ({ name: c.name, file: c.file })), files };
  const manifestBytes = json(manifest);
  fs.writeFileSync(path.join(out, 'MANIFEST.json'), manifestBytes, { flag: 'wx', mode: 0o440 });
  const sealed = recorder.record({ kind: 'evidence.export', record_id: `inspector-${exportedAt.replace(/[^0-9]/g, '').slice(0, 14)}`,
    manifest_digest: sha256(manifestBytes), records: rows.length, exported_at: exportedAt, ...(from ? { period_from: from } : {}), ...(to ? { period_to: to } : {}),
    ...(exportedBy ? { exported_by: exportedBy } : {}) }, { kind: 'evidence.export' });
  const flushed = await recorder.flush();
  let manifestReceipt = null;
  if (recorder.lookup(sealed.record_digest)?.state === 'recorded') {
    manifestReceipt = 'MANIFEST.riskrouter-receipt.json';
    fs.writeFileSync(path.join(out, manifestReceipt), json(await recorder.bundle(sealed.record_digest)), { flag: 'wx', mode: 0o440 });
  }
  return { out, records: rows.length, chains: chainRows.length, manifest_record_digest: sealed.record_digest, manifest_receipt: manifestReceipt,
    error: manifestReceipt ? null : (flushed?.error || 'the manifest seal is not recorded yet') };
}

/**
 * The folder's own half: every listed file present and unchanged, each receipt's
 * record and salt giving the digest its proof names, and the manifest's seal
 * naming this manifest. The log's half (proof, signature) is the verifiers'.
 */
export function verifyInspectorFile(dir) {
  const problems = [];
  const manifestBytes = fs.readFileSync(path.join(dir, 'MANIFEST.json'));
  const manifest = JSON.parse(manifestBytes);
  if (manifest.format !== FORMAT) return { ok: false, problems: [`not a ${FORMAT}`] };
  for (const f of manifest.files) {
    const file = path.join(dir, f.path);
    if (!fs.existsSync(file)) { problems.push(`${f.path}: listed, but missing`); continue; }
    if (sha256(fs.readFileSync(file)) !== f.sha256) { problems.push(`${f.path}: changed since the export`); continue; }
    if (f.path.startsWith('receipts/')) {
      const b = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (recordDigest(b.salt_hex, b.record) !== b.proof?.entry?.record_digest) problems.push(`${f.path}: its record and salt do not give the digest its proof names`);
    }
  }
  const listed = new Set(manifest.files.map((f) => f.path));
  const walk = (rel) => fs.readdirSync(path.join(dir, rel), { withFileTypes: true }).flatMap((d) => {
    const p = rel ? `${rel}/${d.name}` : d.name;
    return d.isDirectory() ? walk(p) : [p];
  });
  for (const p of walk('')) if (!listed.has(p) && p !== 'MANIFEST.json' && p !== 'MANIFEST.riskrouter-receipt.json') problems.push(`${p}: not in the manifest`);
  const mr = path.join(dir, 'MANIFEST.riskrouter-receipt.json');
  if (!fs.existsSync(mr)) problems.push('MANIFEST.riskrouter-receipt.json: missing, so the file set itself is not sealed');
  else {
    const b = JSON.parse(fs.readFileSync(mr, 'utf8'));
    if (b.record?.manifest_digest !== sha256(manifestBytes)) problems.push('MANIFEST.json: not the manifest that was sealed');
    if (recordDigest(b.salt_hex, b.record) !== b.proof?.entry?.record_digest) problems.push('MANIFEST.riskrouter-receipt.json: its record and salt do not give the digest its proof names');
  }
  return { ok: problems.length === 0, problems, manifest };
}

async function main() {
  const args = process.argv.slice(2);
  const flag = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const all = (n) => args.flatMap((a, i) => (a === n ? [args[i + 1]] : []));
  if (args[0] === 'verify') {
    const r = verifyInspectorFile(args[1]);
    for (const p of r.problems) console.log(`PROBLEM ${p}`);
    console.log(r.ok ? `Every file is intact and listed, each receipt's record gives its digest, and the manifest is the one sealed (${r.manifest.records} record(s)). ` +
      'Check each receipt with a verifier too (README.txt).' : `${r.problems.length} problem(s).`);
    process.exit(r.ok ? 0 : 1);
  }
  if (!flag('--out') || !flag('--journal')) {
    console.error('usage: riskrouter-inspector --journal <file> --out <new folder> [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--kind k]... [--chain name]... [--title text] [--by <your ref>]\n' +
      '       riskrouter-inspector verify <folder>');
    process.exit(2);
  }
  if (!process.env.RISKROUTER_API_KEY) {
    console.error('riskrouter-inspector: RISKROUTER_API_KEY is not set (the proofs are fetched with it)');
    process.exit(1);
  }
  const recorder = createRecorder({ journal: flag('--journal'), flushIntervalMs: 3_600_000 });
  try {
    const r = await exportInspectorFile({ recorder, journal: flag('--journal'), out: flag('--out'), from: flag('--from', null), to: flag('--to', null),
      kinds: all('--kind'), chains: all('--chain'), title: flag('--title', null), exportedBy: flag('--by', null) });
    console.log(`wrote ${r.records} receipt(s) and ${r.chains} completeness statement(s) to ${r.out}; open ${path.join(r.out, 'index.html')}`);
    if (r.error) { console.error(`riskrouter-inspector: the manifest is written but not sealed yet (${r.error})`); process.exitCode = 1; }
  } finally {
    await recorder.close();
  }
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((e) => { console.error(`riskrouter-inspector: ${e.message}`); process.exit(1); });
}
