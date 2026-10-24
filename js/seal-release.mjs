#!/usr/bin/env node
/**
 * seal-release: seal each file of a software release, so that later anyone can
 * show the artefact they hold is the one that shipped, on the day it shipped.
 * Used by the GitHub Action in ../github-action, and runnable on its own:
 *
 *   RISKROUTER_API_KEY=rr_... node seal-release.mjs --product acme/gateway --version 4.2.1 \
 *     [--sbom sbom.cdx.json] [--out riskrouter-receipts] dist/*.tar.gz dist/*.zip
 *
 * For each file, a record naming it (product, version, file name, its SHA-256,
 * the commit) is kept in the journal and in a receipt next to it; only the
 * record's salted digest and its kind are sent. With an SBOM, the record is a
 * `cra.release` of the `cra` pack (Cyber Resilience Act, Articles 13, 14 and
 * 31); without one, it is a plain `release.artefact`. Nothing is uploaded: the
 * files and their receipts stay where they are.
 *
 * A receipt is a riskrouter-record-bundle|1 the published verifiers check
 * offline. Keep it with the release (attach it, or upload it as an artefact):
 * without the receipt's salt, nobody, us included, can tie the digest to the file.
 *
 * Exit status: 0 when every file is recorded and has its receipt, 1 otherwise.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRecorder, digestFile } from './recorder.mjs';

const SBOM_FORMAT = (name) => (/cdx|cyclonedx/i.test(name) ? 'cyclonedx' : /spdx/i.test(name) ? 'spdx' : null);

export async function sealRelease({ files, product, version, sbom = null, out = 'riskrouter-receipts',
  releasedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), commit = process.env.GITHUB_SHA || null, recorder }) {
  if (!files.length) throw new Error('no files to seal');
  if (!product || !version) throw new Error('--product and --version are required');
  fs.mkdirSync(out, { recursive: true });
  const sbomDigest = sbom ? await digestFile(sbom) : null;
  const kept = [];
  for (const file of files) {
    const name = path.basename(file);
    const artefact_digest = await digestFile(file);
    const record_id = `rel-${product}-${version}-${name}`.replace(/[^A-Za-z0-9._:/-]/g, '-').slice(0, 128);
    const record = sbomDigest
      ? { pack: 'cra', pack_version: 1, kind: 'cra.release', record_id, product_ref: product.slice(0, 128), version: String(version).slice(0, 80),
        released_at: releasedAt, artefact_digest, sbom_digest: sbomDigest, ...(SBOM_FORMAT(sbom) ? { sbom_format: SBOM_FORMAT(sbom) } : {}),
        x_file_name: name, ...(commit ? { x_commit: commit } : {}) }
      : { kind: 'release.artefact', record_id, product, version: String(version), released_at: releasedAt, file_name: name, artefact_digest,
        ...(commit ? { commit } : {}) };
    kept.push({ file, name, ...recorder.record(record) });
  }
  const sent = await recorder.flush();
  const results = [];
  for (const k of kept) {
    const state = recorder.lookup(k.record_digest);
    if (state?.state !== 'recorded') {
      results.push({ file: k.file, recorded: false, reason: sent?.error || state?.code || state?.state || 'not recorded' });
      continue;
    }
    const receipt = path.join(out, `${k.name}.riskrouter.json`);
    fs.writeFileSync(receipt, `${JSON.stringify(await recorder.bundle(k.record_digest), null, 2)}\n`);
    results.push({ file: k.file, recorded: true, leaf_index: state.leaf_index, receipt });
  }
  return results;
}

async function main(argv) {
  const opts = { files: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (['--product', '--version', '--sbom', '--out', '--journal'].includes(a)) opts[a.slice(2)] = argv[++i];
    else opts.files.push(a);
  }
  opts.files = opts.files.filter((f) => fs.existsSync(f) && fs.statSync(f).isFile());
  if (!process.env.RISKROUTER_API_KEY) {
    console.error('seal-release: RISKROUTER_API_KEY is not set; a free sandbox key is at https://riskrouter.eu/integrate');
    process.exit(1);
  }
  const out = opts.out || 'riskrouter-receipts';
  const recorder = createRecorder({ journal: opts.journal || path.join(out, 'evidence-journal.jsonl'), flushIntervalMs: 3_600_000 });
  let results;
  try {
    results = await sealRelease({ ...opts, out, recorder });
  } finally {
    await recorder.close();
  }
  for (const r of results) {
    console.log(r.recorded ? `sealed   ${r.file}  leaf ${r.leaf_index}  receipt ${r.receipt}` : `NOT SEALED ${r.file}: ${r.reason}`);
  }
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `receipts=${out}\n`);
  process.exit(results.every((r) => r.recorded) ? 0 : 1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  main(process.argv.slice(2)).catch((e) => { console.error(`seal-release: ${e.message}`); process.exit(1); });
}
