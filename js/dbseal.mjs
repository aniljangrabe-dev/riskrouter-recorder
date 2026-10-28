#!/usr/bin/env node
/**
 * dbseal: seal the rows of a PostgreSQL table as they are written, so that
 * later anyone can show a row is exactly what was written on that day, and
 * that none was changed or removed without it showing. For software whose
 * records live in a database, not in files: no integration code.
 *
 *   npx -p riskrouter-recorder riskrouter-dbseal install --table public.suitability_reports --key id | psql "$DATABASE_URL"
 *   RISKROUTER_API_KEY=rr_... npx -p riskrouter-recorder riskrouter-dbseal run --db "$DATABASE_URL"
 *   ... run --once                   seal what is queued, then stop (for a scheduled task)
 *   npx -p riskrouter-recorder riskrouter-dbseal verify --db "$DATABASE_URL" --table public.suitability_reports
 *
 * `install` prints SQL you read and apply yourself: a queue table in a schema
 * `riskrouter`, and a trigger on your table that, in the same transaction as
 * each insert, update or delete, copies the row as PostgreSQL renders it
 * (to_jsonb(row)::text) into the queue. Nothing else in your database changes.
 *
 * `run` takes each queued row in order and keeps a `db.row` record of it in
 * the journal: the table, the row's key, the operation, the SHA-256 of the
 * row's text and when it was queued. The row's text stays in your database;
 * only the record's salted digest is sent. A row is marked sealed in
 * riskrouter.seal_done only once the log has recorded it (never before), so
 * a crash or an outage loses nothing: the next run sends it. With
 * RISKROUTER_CHAIN_SECRET, each table is one completeness chain, so a sealed
 * row later deleted from the queue shows as a gap.
 *
 * `verify` checks the queue against the journal (every sealed row's text
 * still gives its sealed SHA-256, no queued row was skipped) and the table
 * against the queue (each row as it is now is the row as last sealed; one that
 * differs was changed with the trigger switched off).
 *
 * It talks to your database through `psql`, which must be on the PATH: no
 * driver, no dependencies. The connection is --db or the usual PG* variables.
 * Apache-2.0, like the rest of recorders/.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRecorder } from './recorder.mjs';

export const KIND = 'db.row';
const IDENT = /^[a-z_][a-z0-9_]{0,62}$/;
const TABLE = /^(?:[a-z_][a-z0-9_]{0,62}\.)?[a-z_][a-z0-9_]{0,62}$/;
const BATCH = 500;
const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/** schema.table, with `public` when no schema is named; refused unless plain lower-case identifiers. */
export function tableRef(table) {
  if (!TABLE.test(table || '')) throw new Error('--table is schema.table in lower-case letters, digits and _ (quoted identifiers are not supported)');
  return table.includes('.') ? table : `public.${table}`;
}

/** The SQL `install` prints. Idempotent: run it again for another table. */
export function installSql(table, key) {
  const t = tableRef(table);
  if (!IDENT.test(key || '')) throw new Error('--key is the column that identifies a row, in lower-case letters, digits and _');
  const trigger = `riskrouter_seal_${t.replace('.', '_')}`.slice(0, 63);
  return `-- riskrouter-dbseal: seal the rows of ${t} as they are written (https://riskrouter.eu/integrate#recorders).
-- Read it before you apply it. It adds a schema riskrouter, a queue, and one trigger on ${t}; nothing else changes.
begin;
create schema if not exists riskrouter;
create table if not exists riskrouter.seal_queue (
  seq        bigserial primary key,
  table_ref  text not null,
  row_key    text not null,
  operation  text not null check (operation in ('insert', 'update', 'delete')),
  row_text   text not null,
  queued_at  timestamptz not null default clock_timestamp()
);
create table if not exists riskrouter.sealed_tables (
  table_ref   text primary key,
  key_column  text not null
);
insert into riskrouter.sealed_tables (table_ref, key_column) values ('${t}', '${key}')
  on conflict (table_ref) do update set key_column = excluded.key_column;
create table if not exists riskrouter.seal_done (
  seq            bigint primary key references riskrouter.seal_queue (seq),
  record_digest  text not null check (record_digest ~ '^[0-9a-f]{64}$'),
  leaf_index     bigint not null,
  sealed_at      timestamptz not null default clock_timestamp()
);
-- The queue is evidence: rows are added, never changed. (Removing one shows as a gap when the table is chained.)
create or replace function riskrouter.refuse_change() returns trigger language plpgsql as $$
begin
  raise exception 'riskrouter.%: rows are only added', tg_table_name;
end $$;
drop trigger if exists riskrouter_append_only on riskrouter.seal_queue;
create trigger riskrouter_append_only before update on riskrouter.seal_queue for each row execute function riskrouter.refuse_change();
drop trigger if exists riskrouter_append_only on riskrouter.seal_done;
create trigger riskrouter_append_only before update on riskrouter.seal_done for each row execute function riskrouter.refuse_change();
create or replace function riskrouter.enqueue() returns trigger language plpgsql as $$
declare
  r jsonb := to_jsonb(case when tg_op = 'DELETE' then old else new end);
begin
  insert into riskrouter.seal_queue (table_ref, row_key, operation, row_text)
  values (tg_table_schema || '.' || tg_table_name, coalesce(r ->> tg_argv[0], ''), lower(tg_op), r::text);
  return null;
end $$;
drop trigger if exists ${trigger} on ${t};
create trigger ${trigger} after insert or update or delete on ${t}
  for each row execute function riskrouter.enqueue('${key}');
commit;
`;
}

/** Run SQL through psql and return its rows, each a JSON object (the query selects one json column). */
export function psqlRows(sql, { db = null, psql = process.env.RISKROUTER_PSQL || 'psql' } = {}) {
  const args = ['-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', ...(db ? ['-d', db] : []), '-c', sql];
  const r = spawnSync(psql, args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  if (r.error) throw new Error(`psql could not be run (${r.error.code || r.error.message}); install the PostgreSQL client or set RISKROUTER_PSQL`);
  if (r.status !== 0) throw new Error(`psql: ${(r.stderr || '').trim().split('\n')[0]}`);
  return r.stdout.split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

/** Every db.row record in the journal, with its state. */
function journalRows(journal) {
  if (!fs.existsSync(journal)) return [];
  const byDigest = new Map();
  for (const l of fs.readFileSync(journal, 'utf8').split('\n').filter(Boolean).slice(1).map((x) => JSON.parse(x))) {
    const e = byDigest.get(l.record_digest) || { record_digest: l.record_digest };
    if (l.type === 'pending') Object.assign(e, { record: l.record, state: e.state || 'pending' });
    else if (l.type === 'recorded') Object.assign(e, { state: 'recorded', leaf_index: l.leaf_index });
    else if (l.type === 'refused') Object.assign(e, { state: 'refused' });
    byDigest.set(l.record_digest, e);
  }
  return [...byDigest.values()].filter((e) => e.record?.kind === KIND);
}

const QUEUED = (after, limit) => `select json_build_object('seq', q.seq, 'table_ref', q.table_ref, 'row_key', q.row_key, 'operation', q.operation,
  'row_text', q.row_text, 'queued_at', to_char(q.queued_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
  from riskrouter.seal_queue q left join riskrouter.seal_done d using (seq)
  where d.seq is null and q.seq > ${after} order by q.seq limit ${limit}`;

/**
 * Seal what is queued. Returns { sealed, marked, pending, error }.
 * @param {object} o
 * @param {object} o.recorder   a recorder from ./recorder.mjs
 * @param {string} o.journal    the recorder's journal (to know what was already kept, across restarts)
 * @param {boolean} [o.chain]   one completeness chain per table (needs the recorder's chainSecret)
 */
export async function sealQueued({ recorder, journal, db = null, chain = false, psql }) {
  const opts = { db, psql };
  const kept = new Map(journalRows(journal).map((e) => [e.record.queue_seq, e]));
  let sealed = 0;
  let after = 0;
  for (;;) {
    const rows = psqlRows(QUEUED(after, BATCH), opts);
    if (!rows.length) break;
    for (const q of rows) {
      after = q.seq;
      if (kept.has(q.seq)) continue;   // kept before a restart: it is sent, not kept again
      const record = { kind: KIND, record_id: `${q.table_ref}#${q.seq}`, table_ref: q.table_ref, row_key: q.row_key, operation: q.operation,
        row_sha256: sha256(q.row_text), row_bytes: Buffer.byteLength(q.row_text, 'utf8'), queued_at: q.queued_at, queue_seq: q.seq };
      const k = recorder.record(record, chain ? { chain: `table:${q.table_ref}` } : {});
      kept.set(q.seq, { record_digest: k.record_digest, record });
      sealed++;
    }
  }
  const flushed = await recorder.flush();
  // Marked sealed only from the log's answer (a pending or refused one is never marked).
  const done = new Set(psqlRows(`select json_build_object('seq', seq) from riskrouter.seal_done`, opts).map((r) => r.seq));
  const marks = [];
  for (const [seq, e] of kept) {
    if (done.has(seq)) continue;
    const s = recorder.lookup(e.record_digest);
    if (s?.state === 'recorded') marks.push(`(${Number(seq)}, '${e.record_digest}', ${Number(s.leaf_index)})`);
  }
  for (let i = 0; i < marks.length; i += BATCH) {
    psqlRows(`insert into riskrouter.seal_done (seq, record_digest, leaf_index) values ${marks.slice(i, i + BATCH).join(', ')} on conflict (seq) do nothing`, opts);
  }
  return { sealed, marked: marks.length, pending: recorder.status().pending, error: flushed?.error || null };
}

/**
 * Check one table: every sealed row's text still gives its sealed SHA-256, no
 * queued row was left unsealed before the last one sealed, and each row of the
 * table as it is now is the row as last queued. Returns { ok, counts, problems }.
 */
export function verifyTable({ table, journal, db = null, psql }) {
  const t = tableRef(table);
  const opts = { db, psql };
  const problems = [];
  const sealedRows = journalRows(journal).filter((e) => e.record.table_ref === t);
  const bySeq = new Map(sealedRows.map((e) => [e.record.queue_seq, e]));
  const queue = psqlRows(`select json_build_object('seq', seq, 'row_key', row_key, 'operation', operation, 'row_text', row_text)
    from riskrouter.seal_queue where table_ref = '${t}' order by seq`, opts);
  const inQueue = new Set(queue.map((q) => q.seq));
  const lastSealed = Math.max(0, ...bySeq.keys());
  let intact = 0;
  for (const q of queue) {
    const e = bySeq.get(q.seq);
    if (!e) { if (q.seq < lastSealed) problems.push(`queue row ${q.seq} (${q.row_key}): queued, but never sealed`); continue; }
    if (sha256(q.row_text) !== e.record.row_sha256) problems.push(`queue row ${q.seq} (${q.row_key}): its text has changed since it was sealed`);
    else intact++;
  }
  for (const [seq, e] of bySeq) if (!inQueue.has(seq)) problems.push(`queue row ${seq} (${e.record.row_key}): sealed, but no longer in the queue`);
  for (const e of sealedRows) if (e.state !== 'recorded') problems.push(`queue row ${e.record.queue_seq}: sealed, but not yet recorded in the log (${e.state})`);
  // The table now, against the newest queued version of each row.
  const newest = new Map();
  for (const q of queue) newest.set(q.row_key, q);
  const found = psqlRows(`select json_build_object('key', s.key_column, 'trigger', exists (select 1 from pg_trigger
    where tgrelid = '${t}'::regclass and tgname like 'riskrouter_seal_%' and tgenabled <> 'D'))
    from riskrouter.sealed_tables s where s.table_ref = '${t}'`, opts)[0];
  const key = found?.key;
  if (!found?.trigger) problems.push(`${t}: no enabled riskrouter_seal trigger; rows changed now are not sealed`);
  if (!key || !IDENT.test(key)) problems.push(`${t}: not installed (riskrouter.sealed_tables has no row for it)`);
  else {
    const now = psqlRows(`select json_build_object('row_key', coalesce(to_jsonb(t) ->> '${key}', ''), 'row_text', to_jsonb(t)::text) from ${t} t`, opts);
    const present = new Set();
    for (const r of now) {
      present.add(r.row_key);
      const q = newest.get(r.row_key);
      if (!q || q.operation === 'delete') problems.push(`${t} row ${r.row_key}: in the table, but never queued (written with the trigger off?)`);
      else if (q.row_text !== r.row_text) problems.push(`${t} row ${r.row_key}: differs from its last queued version (changed with the trigger off?)`);
    }
    for (const [k, q] of newest) if (q.operation !== 'delete' && !present.has(k)) problems.push(`${t} row ${k}: removed without a queued delete`);
  }
  return { ok: problems.length === 0, counts: { queued: queue.length, sealed: sealedRows.length, intact }, problems };
}

async function main() {
  const args = process.argv.slice(2);
  const flag = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const db = flag('--db', process.env.DATABASE_URL || null);
  const journal = flag('--journal', 'evidence-journal.jsonl');
  if (args[0] === 'install') {
    process.stdout.write(installSql(flag('--table'), flag('--key', 'id')));
    return;
  }
  if (args[0] === 'verify') {
    const r = verifyTable({ table: flag('--table'), journal, db });
    for (const p of r.problems) console.log(`PROBLEM ${p}`);
    console.log(`${r.counts.intact} of ${r.counts.sealed} sealed row version(s) intact; ${r.counts.queued} queued.`);
    console.log(r.ok ? 'Every sealed row is intact, none was skipped, and the table matches its last seals.' : `${r.problems.length} problem(s).`);
    process.exit(r.ok ? 0 : 1);
  }
  if (args[0] !== 'run') {
    console.error('usage: riskrouter-dbseal install --table <schema.table> [--key id]          (prints SQL to apply with psql)\n' +
      '       riskrouter-dbseal run [--db <url>] [--interval 10] [--chain] [--once] [--journal file]\n' +
      '       riskrouter-dbseal verify --table <schema.table> [--db <url>] [--journal file]');
    process.exit(2);
  }
  if (!process.env.RISKROUTER_API_KEY) {
    console.error('riskrouter-dbseal: RISKROUTER_API_KEY is not set; a free sandbox key is at https://riskrouter.eu/integrate');
    process.exit(1);
  }
  const recorder = createRecorder({ journal, flushIntervalMs: 3_600_000 });
  const chain = args.includes('--chain');
  const report = (r) => {
    if (r.sealed || r.marked) console.log(`sealed ${r.sealed} row version(s); ${r.marked} marked in riskrouter.seal_done`);
    if (r.error) console.error(`riskrouter-dbseal: ${r.error}; the rows stay queued and are sent next time`);
  };
  if (args.includes('--once')) {
    report(await sealQueued({ recorder, journal, db, chain }));
    await recorder.close();
    process.exit(recorder.status().pending ? 1 : 0);
  }
  let stopping = false;
  const stop = async () => { stopping = true; await recorder.close(); process.exit(0); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
  const every = Math.max(1, Number(flag('--interval', 10))) * 1000;
  while (!stopping) {
    try { report(await sealQueued({ recorder, journal, db, chain })); } catch (e) { console.error(`riskrouter-dbseal: ${e.message}`); }
    await new Promise((r) => setTimeout(r, every));
  }
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((e) => { console.error(`riskrouter-dbseal: ${e.message}`); process.exit(1); });
}

