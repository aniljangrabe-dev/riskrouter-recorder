#!/usr/bin/env node
/**
 * logseal: seal a stream of log lines, segment by segment, so that later
 * anyone can show a segment is exactly what was written at the time, and that
 * none is missing. Each closed segment is written once to your own archive
 * (never overwritten), and a `security.log-segment` record of it (pack nis2)
 * goes through the recorder: the record and its salt stay in your journal,
 * only the record's salted digest is sent. The log lines never leave you.
 *
 *   journalctl -f -o short-iso | riskrouter-logseal --source auth-server --archive /var/lib/logseal
 *   tail -F /var/log/auth.log    | riskrouter-logseal --source auth-server --archive /var/lib/logseal --lines 1000 --seconds 60
 *   riskrouter-logseal verify --archive /var/lib/logseal --journal evidence-journal.jsonl
 *   riskrouter-logseal export --source auth-server --archive /var/lib/logseal --from 240 --to 260 --out ./export-sec-0007
 *   riskrouter-logseal verify-export ./export-sec-0007
 *
 * What it proves, and what it cannot: a segment sealed before an intruder
 * controlled the machine that writes it cannot be changed, removed or
 * reordered afterwards without it showing. Lines that machine writes once it
 * is controlled can be forged at the source. Run the sealer somewhere the
 * systems it watches cannot reach (a log collector), not on each of them.
 *
 * No dependencies. Apache-2.0, like the rest of recorders/.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { createRecorder } from './recorder.mjs';

export const KIND = 'security.log-segment';
const PACK = 'nis2';
const PACK_VERSION = 1;
const SOURCE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const pad = (i) => String(i).padStart(10, '0');
export const recordIdOf = (source, index) => `${source}-seg-${pad(index)}`;
const segmentFile = (archive, source, index) => path.join(archive, source, `${pad(index)}.log`);

/** The segments already in the archive for a source, by index. */
function archived(archive, source) {
  const dir = path.join(archive, source);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => /^\d{10}\.log$/.test(f)).map((f) => Number(f.slice(0, 10))).sort((a, b) => a - b);
}

/**
 * @param {object} o
 * @param {object} o.recorder   a recorder from ./recorder.mjs
 * @param {string} o.source     your reference for the log source: letters, digits, . _ -
 * @param {string} o.archive    where segments are written, once each
 * @param {number} [o.lines]    close a segment after this many lines (default 1000)
 * @param {number} [o.seconds]  close a segment after this many seconds, if it has any line (default 60)
 * @param {string} [o.format]   the format of the lines, recorded as log_format
 */
export function createSealer({ recorder, source, archive, lines = 1000, seconds = 60, format, now = () => new Date() }) {
  if (!SOURCE.test(source || '')) throw new Error('a source is your own reference: letters, digits, . _ - only, at most 64');
  fs.mkdirSync(path.join(archive, source), { recursive: true });
  // Carry on after the last segment already archived, so a restart neither reuses an index nor breaks the chain.
  const done = archived(archive, source);
  let index = done.length ? done.at(-1) + 1 : 0;
  let buffer = [];
  let openedAt = null;
  let timer = null;
  const sealed = [];

  function close() {
    clearTimeout(timer); timer = null;
    if (!buffer.length) return null;
    const bytes = Buffer.from(buffer.join('\n') + '\n', 'utf8');
    const file = segmentFile(archive, source, index);
    // Written once, synced, then recorded: a record never points at a segment that is not on disk.
    const fd = fs.openSync(file, 'wx', 0o440);
    try { fs.writeSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const record = {
      pack: PACK, pack_version: PACK_VERSION, kind: KIND, record_id: recordIdOf(source, index),
      source_ref: source, segment_index: index,
      segment_start: openedAt.toISOString(), segment_end: now().toISOString(),
      line_count: buffer.length, log_digest: sha256(bytes),
      ...(format ? { log_format: format } : {}),
      ...(index > 0 ? { previous_segment_record_id: recordIdOf(source, index - 1) } : {})
    };
    const kept = recorder.record(record, { kind: KIND });
    sealed.push({ index, file, record_digest: kept.record_digest });
    index++; buffer = []; openedAt = null;
    return sealed.at(-1);
  }

  return {
    /** Add one line (without its newline). */
    write(line) {
      if (buffer.length === 0) {
        openedAt = now();
        if (seconds > 0) { timer = setTimeout(close, seconds * 1000); timer.unref?.(); }
      }
      buffer.push(String(line).replace(/\r?\n$/, ''));
      if (buffer.length >= lines) close();
    },
    /** Close the open segment now, if it has any line. */
    close,
    get sealed() { return sealed.slice(); },
    get nextIndex() { return index; }
  };
}

/** Every journal record of this kind, by record_id, with its state. */
function journalSegments(journal) {
  const byDigest = new Map();
  for (const l of fs.readFileSync(journal, 'utf8').split('\n').filter(Boolean).slice(1).map((x) => JSON.parse(x))) {
    const e = byDigest.get(l.record_digest) || {};
    if (l.type === 'pending') Object.assign(e, { record: l.record, state: e.state || 'pending' });
    else if (l.type === 'recorded') Object.assign(e, { state: 'recorded', leaf_index: l.leaf_index });
    else if (l.type === 'refused') Object.assign(e, { state: 'refused' });
    byDigest.set(l.record_digest, e);
  }
  const out = new Map();
  for (const [record_digest, e] of byDigest) if (e.record?.kind === KIND) out.set(e.record.record_id, { ...e, record_digest });
  return out;
}

/**
 * Check every archived segment against the journal: the bytes give the sealed
 * digest and line count, the indexes run without a gap, and every sealed
 * segment is still in the archive. Returns { ok, sources, problems }.
 */
export function verifyArchive({ archive, journal }) {
  const records = journalSegments(journal);
  const problems = [];
  const sources = {};
  const bySource = new Map();
  for (const e of records.values()) {
    const s = e.record.source_ref;
    if (!bySource.has(s)) bySource.set(s, []);
    bySource.get(s).push(e);
  }
  const onDisk = fs.existsSync(archive) ? fs.readdirSync(archive).filter((d) => SOURCE.test(d) && fs.statSync(path.join(archive, d)).isDirectory()) : [];
  for (const source of new Set([...bySource.keys(), ...onDisk])) {
    const sealedHere = (bySource.get(source) || []).sort((a, b) => a.record.segment_index - b.record.segment_index);
    const files = archived(archive, source);
    let checked = 0;
    const recorded = sealedHere.filter((e) => e.state === 'recorded').length;
    for (const e of sealedHere) {
      const i = e.record.segment_index;
      const file = segmentFile(archive, source, i);
      if (!fs.existsSync(file)) { problems.push(`${source} segment ${i}: sealed, but missing from the archive`); continue; }
      const bytes = fs.readFileSync(file);
      if (sha256(bytes) !== e.record.log_digest) problems.push(`${source} segment ${i}: changed since it was sealed`);
      else if (bytes.toString('utf8').split('\n').length - 1 !== e.record.line_count) problems.push(`${source} segment ${i}: line count differs from the seal`);
      else checked++;
      if (i > 0 && e.record.previous_segment_record_id !== recordIdOf(source, i - 1)) problems.push(`${source} segment ${i}: does not name segment ${i - 1} as the one before it`);
    }
    const indexes = sealedHere.map((e) => e.record.segment_index);
    for (let i = 1; i < indexes.length; i++) if (indexes[i] !== indexes[i - 1] + 1) problems.push(`${source}: no sealed segment between ${indexes[i - 1]} and ${indexes[i]}`);
    for (const i of files) if (!indexes.includes(i)) problems.push(`${source} segment ${i}: in the archive, but never sealed`);
    sources[source] = { sealed: sealedHere.length, intact: checked, recorded_in_log: recorded };
  }
  return { ok: problems.length === 0, sources, problems };
}

export const EXPORT_FORMAT = 'riskrouter-logseal-export|1';

/**
 * A forensic export: the sealed segments of one source from `from` to `to`,
 * each with its record bundle (record, salt, the log's proof), and a manifest
 * listing every file with its SHA-256. The manifest's own digest is sealed as
 * a `security.evidence-export` record, so the handover itself is evidence of
 * what was handed over and when. Written to a new directory, never into one
 * that exists.
 */
export async function exportSegments({ recorder, archive, journal, source, from = 0, to = Infinity, out, exportedBy = null, now = () => new Date() }) {
  if (!SOURCE.test(source || '')) throw new Error('a source is your own reference: letters, digits, . _ - only, at most 64');
  if (exportedBy !== null && !SOURCE.test(exportedBy)) throw new Error('exported_by is your own reference for the person, never a name');
  if (fs.existsSync(out)) throw new Error(`${out} exists: an export is written to a new directory`);
  const records = [...journalSegments(journal).values()]
    .filter((e) => e.record.source_ref === source && e.record.segment_index >= from && e.record.segment_index <= to)
    .sort((a, b) => a.record.segment_index - b.record.segment_index);
  if (!records.length) throw new Error(`no sealed segment of ${source} in that range`);
  const pending = records.filter((e) => e.state !== 'recorded');
  if (pending.length) throw new Error(`${pending.length} segment(s) in that range are not recorded in the log yet; flush the recorder first`);
  fs.mkdirSync(path.join(out, 'segments'), { recursive: true });
  fs.mkdirSync(path.join(out, 'bundles'));
  const files = [];
  const keep = (rel, bytes) => { fs.writeFileSync(path.join(out, rel), bytes, { flag: 'wx', mode: 0o440 }); files.push({ path: rel, sha256: sha256(bytes), bytes: bytes.length }); };
  for (const e of records) {
    const i = e.record.segment_index;
    const bytes = fs.readFileSync(segmentFile(archive, source, i));
    if (sha256(bytes) !== e.record.log_digest) throw new Error(`${source} segment ${i} has changed since it was sealed; it is not exported`);
    keep(`segments/${pad(i)}.log`, bytes);
    keep(`bundles/${pad(i)}.json`, Buffer.from(JSON.stringify(await recorder.bundle(e.record_digest), null, 2) + '\n'));
  }
  const manifest = {
    format: EXPORT_FORMAT, source_ref: source, exported_at: now().toISOString(), ...(exportedBy ? { exported_by: exportedBy } : {}),
    segments: { from: records[0].record.segment_index, to: records.at(-1).record.segment_index, count: records.length },
    files,
    how_to_verify: 'For each segment: SHA-256 of segments/N.log equals bundles/N.json record.log_digest, and its line count equals record.line_count; ' +
      'each bundle verifies offline with riskrouter_verify.py or tools/records.mjs check (https://riskrouter.eu/verify); the segment indexes run without a gap ' +
      'and each names the one before it. riskrouter-logseal verify-export <dir> checks the first and last of these.'
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
  fs.writeFileSync(path.join(out, 'MANIFEST.json'), manifestBytes, { flag: 'wx', mode: 0o440 });
  const sealedExport = recorder.record({
    kind: 'security.evidence-export', record_id: `${source}-export-${manifest.exported_at.replace(/[^0-9]/g, '').slice(0, 14)}`,
    source_ref: source, manifest_digest: sha256(manifestBytes), segments_from: manifest.segments.from, segments_to: manifest.segments.to,
    exported_at: manifest.exported_at, ...(exportedBy ? { exported_by: exportedBy } : {})
  }, { kind: 'security.evidence-export' });
  return { out, manifest, manifest_record_digest: sealedExport.record_digest };
}

/** The file half of an export: every listed file present and unchanged, every segment matching its sealed record, no gap. */
export function verifyExport(dir) {
  const problems = [];
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'MANIFEST.json'), 'utf8'));
  if (manifest.format !== EXPORT_FORMAT) return { ok: false, problems: [`not a ${EXPORT_FORMAT} export`] };
  for (const f of manifest.files) {
    const file = path.join(dir, f.path);
    if (!fs.existsSync(file)) { problems.push(`${f.path}: listed, but missing`); continue; }
    if (sha256(fs.readFileSync(file)) !== f.sha256) problems.push(`${f.path}: changed since the export`);
  }
  let previous = null;
  for (let i = manifest.segments.from; i <= manifest.segments.to; i++) {
    const seg = path.join(dir, 'segments', `${pad(i)}.log`);
    const bun = path.join(dir, 'bundles', `${pad(i)}.json`);
    if (!fs.existsSync(seg) || !fs.existsSync(bun)) { problems.push(`segment ${i}: missing from the export`); continue; }
    const bytes = fs.readFileSync(seg);
    const record = JSON.parse(fs.readFileSync(bun, 'utf8')).record || {};
    if (record.log_digest !== sha256(bytes)) problems.push(`segment ${i}: does not match its sealed record`);
    if (record.line_count !== bytes.toString('utf8').split('\n').length - 1) problems.push(`segment ${i}: line count differs from its sealed record`);
    if (previous !== null && record.previous_segment_record_id !== previous) problems.push(`segment ${i}: does not name segment ${i - 1} as the one before it`);
    previous = record.record_id;
  }
  return { ok: problems.length === 0, problems, manifest };
}

async function main() {
  const args = process.argv.slice(2);
  const flag = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  if (args[0] === 'export') {
    const recorder = createRecorder({ journal: flag('--journal', 'evidence-journal.jsonl') });
    const r = await exportSegments({ recorder, archive: flag('--archive'), journal: flag('--journal', 'evidence-journal.jsonl'), source: flag('--source'),
      from: Number(flag('--from', 0)), to: flag('--to') === undefined ? Infinity : Number(flag('--to')), out: flag('--out'), exportedBy: flag('--by', null) });
    await recorder.close();
    console.log(`exported segments ${r.manifest.segments.from} to ${r.manifest.segments.to} of ${r.manifest.source_ref} to ${r.out}; the manifest is sealed as ${r.manifest_record_digest}`);
    return;
  }
  if (args[0] === 'verify-export') {
    const r = verifyExport(args[1]);
    for (const p of r.problems) console.log(`PROBLEM ${p}`);
    console.log(r.ok ? `Every file in the export is intact, and segments ${r.manifest.segments.from} to ${r.manifest.segments.to} match their seals with no gap. Check each bundle with a verifier too.` : `${r.problems.length} problem(s).`);
    process.exit(r.ok ? 0 : 1);
  }
  if (args[0] === 'verify') {
    const r = verifyArchive({ archive: flag('--archive'), journal: flag('--journal', 'evidence-journal.jsonl') });
    for (const [s, c] of Object.entries(r.sources)) console.log(`${s}: ${c.intact} of ${c.sealed} sealed segments intact, ${c.recorded_in_log} recorded in the log`);
    for (const p of r.problems) console.log(`PROBLEM ${p}`);
    console.log(r.ok ? 'Every sealed segment is intact, and none is missing.' : `${r.problems.length} problem(s).`);
    process.exit(r.ok ? 0 : 1);
  }
  const archive = flag('--archive');
  if (!archive || !flag('--source')) {
    console.error('usage: riskrouter-logseal --source <ref> --archive <dir> [--lines 1000] [--seconds 60] [--format syslog] [--journal file]\n' +
      '       riskrouter-logseal verify --archive <dir> [--journal file]\n' +
      '       riskrouter-logseal export --source <ref> --archive <dir> --out <new dir> [--from N] [--to N] [--by <your ref>] [--journal file]\n' +
      '       riskrouter-logseal verify-export <dir>');
    process.exit(2);
  }
  // Refuse a bad source before anything, so a mistyped command leaves no journal behind.
  if (!SOURCE.test(flag('--source'))) throw new Error('a source is your own reference: letters, digits, . _ - only, at most 64');
  const recorder = createRecorder({ journal: flag('--journal', 'evidence-journal.jsonl') });
  const sealer = createSealer({ recorder, source: flag('--source'), archive, lines: Number(flag('--lines', 1000)), seconds: Number(flag('--seconds', 60)), format: flag('--format') });
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const stop = async () => { sealer.close(); await recorder.close(); };
  process.on('SIGTERM', () => stop().then(() => process.exit(0)));
  process.on('SIGINT', () => stop().then(() => process.exit(0)));
  for await (const line of rl) sealer.write(line);
  await stop();
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((e) => { console.error(`riskrouter-logseal: ${e.message}`); process.exit(1); });
}
