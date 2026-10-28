#!/usr/bin/env node
/**
 * folderseal: seal each file that lands in a folder, as it lands, so that
 * later anyone can show a file is exactly the one that was there on that day.
 * For the folders records already live in (a shared drive, a synced SharePoint
 * or OneDrive library, a scanner's output), with nobody remembering to seal.
 *
 *   RISKROUTER_API_KEY=rr_... npx -p riskrouter-recorder riskrouter-folderseal --folder ./advice-files
 *   ... --once                       seal what is new or changed, then stop (for a scheduled task)
 *   npx -p riskrouter-recorder riskrouter-folderseal verify --folder ./advice-files
 *
 * Each new or changed file gets the record /seal makes (kind file.seal: the
 * file's SHA-256, its size and its path in the folder), kept in the journal;
 * only the record's salted digest is sent. Once the log has confirmed it, a
 * receipt (riskrouter-record-bundle|1) is written to the receipts folder, and
 * riskrouter.eu/check or the published verifiers check it offline. Nothing is
 * uploaded, and a file is never touched: receipts go beside it, never into it.
 *
 * With RISKROUTER_CHAIN_SECRET, the folder's seals are one completeness chain
 * (docs/completeness.md), so a seal later left out shows as a gap. A file is
 * sealed once it has not changed for --settle seconds, so one still being
 * written is not sealed half-way. A changed file is sealed again; both seals
 * stay, which is the history of the file.
 *
 * No dependencies. Apache-2.0, like the rest of recorders/.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRecorder, digestFile } from './recorder.mjs';

export const KIND = 'file.seal';
/** Files the system writes when a folder is only opened, and office lock files: never sealed (the same list /seal skips, and more). */
const SKIP = (name) => ['.DS_Store', 'Thumbs.db', 'desktop.ini'].includes(name) || name.startsWith('~$') || name.startsWith('.~lock.') ||
  name.endsWith('.tmp') || name.endsWith('.partial') || name.endsWith('.crdownload');
const RECEIPTS = '.riskrouter-receipts';
const MAX_NAME = 255;

/** Every file under `folder`, as paths inside it with '/', leaving out hidden folders (the receipts among them) and SKIP. */
export function listFiles(folder) {
  const out = [];
  const walk = (rel) => {
    for (const d of fs.readdirSync(path.join(folder, rel), { withFileTypes: true })) {
      if (d.name.startsWith('.') || SKIP(d.name)) continue;
      const p = rel ? `${rel}/${d.name}` : d.name;
      if (d.isDirectory()) walk(p);
      else if (d.isFile()) out.push(p);
    }
  };
  walk('');
  return out.sort();
}

/** What the journal holds for this folder: every file.seal record, newest last, with its state. */
function journalSeals(journal, folderRef) {
  if (!fs.existsSync(journal)) return [];
  const byDigest = new Map();
  for (const l of fs.readFileSync(journal, 'utf8').split('\n').filter(Boolean).slice(1).map((x) => JSON.parse(x))) {
    const e = byDigest.get(l.record_digest) || { record_digest: l.record_digest };
    if (l.type === 'pending') Object.assign(e, { record: l.record, state: e.state || 'pending' });
    else if (l.type === 'recorded') Object.assign(e, { state: 'recorded', leaf_index: l.leaf_index, created_at: l.created_at });
    else if (l.type === 'refused') Object.assign(e, { state: 'refused' });
    byDigest.set(l.record_digest, e);
  }
  return [...byDigest.values()].filter((e) => e.record?.kind === KIND && e.record.folder_ref === folderRef);
}

const receiptName = (rel, sha) => `${rel}.${sha.slice(0, 12)}.riskrouter-receipt.json`;

/**
 * @param {object} o
 * @param {object} o.recorder    a recorder from ./recorder.mjs
 * @param {string} o.folder      the folder to watch
 * @param {string} [o.receipts]  where receipts go (default <folder>/.riskrouter-receipts)
 * @param {string} [o.folderRef] your reference for the folder, recorded with each seal (default its name)
 * @param {number} [o.settle]    seconds a file must be unchanged before it is sealed (default 5)
 * @param {boolean} [o.chain]    seal into a completeness chain named after the folder (needs the recorder's chainSecret)
 */
export function createFolderSealer({ recorder, folder, receipts = path.join(folder, RECEIPTS), folderRef = path.basename(path.resolve(folder)),
  journal, settle = 5, chain = false, now = () => Date.now() }) {
  if (!fs.statSync(folder).isDirectory()) throw new Error(`${folder} is not a folder`);
  fs.mkdirSync(receipts, { recursive: true });
  // The newest seal of each path, from the journal: a restart neither reseals a file nor forgets one waiting for its receipt.
  const latest = new Map();
  for (const e of journalSeals(journal, folderRef)) latest.set(e.record.file_name, e);
  const seen = new Map();   // path -> { size, mtimeMs } at the last scan, for the settle rule

  async function scan() {
    const sealed = [];
    for (const rel of listFiles(folder)) {
      if (rel.length > MAX_NAME) continue;
      const file = path.join(folder, rel);
      let st;
      try { st = fs.statSync(file); } catch { continue; }
      const before = seen.get(rel);
      seen.set(rel, { size: st.size, mtimeMs: st.mtimeMs });
      if (now() - st.mtimeMs < settle * 1000 || (before && (before.size !== st.size || before.mtimeMs !== st.mtimeMs) && settle > 0)) continue;
      const known = latest.get(rel);
      if (known && known.record.file_size === st.size && known.mtimeMs === st.mtimeMs) continue;
      const file_sha256 = await digestFile(file);
      if (known && known.record.file_sha256 === file_sha256) { known.mtimeMs = st.mtimeMs; continue; }
      const record = { kind: KIND, file_sha256, file_size: st.size, file_name: rel, folder_ref: folderRef,
        sealed_from: 'riskrouter-folderseal', ...(known ? { previous_file_sha256: known.record.file_sha256 } : {}) };
      const kept = recorder.record(record, chain ? { chain: `folder:${folderRef}` } : {});
      const entry = { record_digest: kept.record_digest, record: { ...record, ...(kept.chain_tag ? { chain_tag: kept.chain_tag, chain_seq: kept.chain_seq } : {}) },
        state: 'pending', mtimeMs: st.mtimeMs };
      latest.set(rel, entry);
      sealed.push(entry);
    }
    const flushed = await recorder.flush();
    const receiptsWritten = await writeReceipts();
    return { sealed: sealed.length, receipts: receiptsWritten, error: flushed?.error || null };
  }

  /** A receipt for every recorded seal that has none yet. Only from the log's answer: a pending seal never gets one. */
  async function writeReceipts() {
    let n = 0;
    for (const e of journalSeals(journal, folderRef)) {
      const out = path.join(receipts, receiptName(e.record.file_name, e.record.file_sha256));
      if (fs.existsSync(out)) continue;
      if (recorder.lookup(e.record_digest)?.state !== 'recorded') continue;
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, `${JSON.stringify(await recorder.bundle(e.record_digest), null, 2)}\n`, { flag: 'wx' });
      n++;
    }
    return n;
  }

  return { scan, writeReceipts, get receipts() { return receipts; } };
}

/**
 * Check the folder against what was sealed: every file's newest seal matches it,
 * every sealed file is still there, every file has been sealed, and every
 * recorded seal has its receipt. Returns { ok, files, problems }.
 */
export function verifyFolder({ folder, journal, receipts = path.join(folder, RECEIPTS), folderRef = path.basename(path.resolve(folder)) }) {
  const problems = [];
  const newest = new Map();
  const seals = journalSeals(journal, folderRef);
  for (const e of seals) newest.set(e.record.file_name, e);
  const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
  const here = listFiles(folder);
  let intact = 0;
  for (const rel of here) {
    const e = newest.get(rel);
    if (!e) { problems.push(`${rel}: in the folder, but never sealed`); continue; }
    if (sha(path.join(folder, rel)) !== e.record.file_sha256) problems.push(`${rel}: changed since its last seal`);
    else intact++;
  }
  for (const rel of newest.keys()) if (!here.includes(rel)) problems.push(`${rel}: sealed, but no longer in the folder`);
  for (const e of seals) {
    if (e.state === 'recorded' && !fs.existsSync(path.join(receipts, receiptName(e.record.file_name, e.record.file_sha256)))) {
      problems.push(`${e.record.file_name}: recorded in the log, but its receipt is missing`);
    }
    if (e.state !== 'recorded') problems.push(`${e.record.file_name}: sealed, but not yet recorded in the log (${e.state})`);
  }
  return { ok: problems.length === 0, files: { in_folder: here.length, intact, seals: seals.length }, problems };
}

async function main() {
  const args = process.argv.slice(2);
  const flag = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const folder = flag('--folder');
  if (!folder) {
    console.error('usage: riskrouter-folderseal --folder <dir> [--receipts <dir>] [--ref <your ref>] [--interval 30] [--settle 5] [--chain] [--once] [--journal file]\n' +
      '       riskrouter-folderseal verify --folder <dir> [--receipts <dir>] [--ref <your ref>] [--journal file]');
    process.exit(2);
  }
  const receipts = flag('--receipts', path.join(folder, RECEIPTS));
  const journal = flag('--journal', path.join(receipts, 'evidence-journal.jsonl'));
  const folderRef = flag('--ref', path.basename(path.resolve(folder)));
  if (args[0] === 'verify') {
    const r = verifyFolder({ folder, journal, receipts, folderRef });
    for (const p of r.problems) console.log(`PROBLEM ${p}`);
    console.log(`${r.files.intact} of ${r.files.in_folder} file(s) match their last seal; ${r.files.seals} seal(s) in the journal.`);
    console.log(r.ok ? 'Every file is sealed and unchanged, and every seal has its receipt.' : `${r.problems.length} problem(s).`);
    process.exit(r.ok ? 0 : 1);
  }
  if (!process.env.RISKROUTER_API_KEY) {
    console.error('riskrouter-folderseal: RISKROUTER_API_KEY is not set; a free sandbox key is at https://riskrouter.eu/integrate');
    process.exit(1);
  }
  fs.mkdirSync(receipts, { recursive: true });
  const recorder = createRecorder({ journal, flushIntervalMs: 3_600_000 });
  const sealer = createFolderSealer({ recorder, folder, receipts, folderRef, journal, settle: Number(flag('--settle', 5)), chain: args.includes('--chain') });
  const report = (r) => {
    if (r.sealed || r.receipts) console.log(`sealed ${r.sealed} file(s); wrote ${r.receipts} receipt(s) to ${sealer.receipts}`);
    if (r.error) console.error(`riskrouter-folderseal: ${r.error}; the seals stay pending and are sent next time`);
  };
  if (args.includes('--once')) {
    // Twice, so a file is sealed in this run once it has settled, not only on the next.
    const settle = Number(flag('--settle', 5));
    report(await sealer.scan());
    if (settle > 0) { await new Promise((r) => setTimeout(r, settle * 1000)); report(await sealer.scan()); }
    await recorder.close();
    process.exit(recorder.status().pending ? 1 : 0);
  }
  let stopping = false;
  const stop = async () => { stopping = true; await recorder.close(); process.exit(0); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
  const every = Math.max(5, Number(flag('--interval', 30))) * 1000;
  while (!stopping) {
    report(await sealer.scan());
    await new Promise((r) => setTimeout(r, every));
  }
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((e) => { console.error(`riskrouter-folderseal: ${e.message}`); process.exit(1); });
}
