/* Overlay across all four font-source paths, plus the invariant that matters:
 * the original content stream of every page must survive byte-identical. */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile, mkdir } from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
const { PDFDocument, PDFName, PDFArray, PDFStream } = PDFLib;
const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { planOverlay, addOverlay } = await import('../../static/js/pdf/overlay.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const OUT = path.join(DIR, 'out');
await mkdir(OUT, { recursive: true });
const open = async (f) => {
  const r = await loadDocument(new Uint8Array(await readFile(path.join(DIR, f))), f);
  if (!r.ok) throw new Error(r.message);
  return r.doc;
};
const streamHashes = (doc, pageIndex) => {
  const page = doc.getPage(pageIndex);
  const c = doc.context.lookup(page.node.get(PDFName.of('Contents')));
  const list = c instanceof PDFArray ? c.asArray().map(r => doc.context.lookup(r)) : [c];
  return list.filter(s => s instanceof PDFStream)
             .map(s => crypto.createHash('sha256').update(Buffer.from(s.contents)).digest('hex'));
};

let fail = 0;
const check = (ok, m) => { if (!ok) { fail++; console.log('    FAIL ' + m); } };
const manifest = [];

const CASES = [
  { file: '09-typographic-roles.pdf', label: 'TYPE A — original font reused',
    place: [{ pageIndex: 0, x: 70, y: 676, text: 'DX-4413-TT' }],
    want: { docType: 'A', source: 'original', category: 'monospace' } },
  { file: '08-subset-font-form.pdf', label: 'TYPE A — forced substitution',
    place: [{ pageIndex: 0, x: 72, y: 734, text: 'Verifica' }],
    want: { docType: 'A', source: 'SUBSTITUTE', reason: 'glyph-missing' } },
  { file: '03-scanned-ocr.pdf', label: 'TYPE B — size estimated from OCR layer',
    place: [{ pageIndex: 0, x: 100, y: 300, text: 'Added to a scan' }],
    want: { docType: 'B', source: 'ESTIMATED', reason: 'ocr-layer-median' } },
  { file: '10-scanned-no-ocr.pdf', label: 'TYPE B — no signal at all, declared default',
    place: [{ pageIndex: 0, x: 100, y: 300, text: 'Added to a bare scan' }],
    want: { docType: 'B', source: 'DEFAULT', reason: 'no-signal-in-document', size: 11 } },
  { file: '09-typographic-roles.pdf', label: 'TYPE A — user correction',
    place: [{ pageIndex: 0, x: 70, y: 676, text: 'Corrected', sizeOverride: 18,
              categoryOverride: 'serif' }],
    want: { source: 'USER', reason: 'user-corrected', category: 'serif', size: 18 } },
];

for (const c of CASES) {
  console.log(`\n=== ${c.label}  (${c.file}) ===`);
  const doc = await open(c.file);
  const before = streamHashes(doc, c.place[0].pageIndex);

  const { plans, blocked } = planOverlay(doc, c.place);
  check(blocked.length === 0, 'nothing should be blocked');
  const p = plans[0];
  console.log(`  doc=${p.docType} source=${p.source} category=${p.category} ` +
              `size=${p.size} face=${p.face ?? p.font?.name} reason=${p.reason}` +
              (p.basis ? ` basis=${p.basis}` : '') + (p.ocrRuns ? ` ocrRuns=${p.ocrRuns}` : ''));
  for (const [k, v] of Object.entries(c.want)) check(p[k] === v, `${k}: got ${p[k]}, want ${v}`);

  const { bytes, report, written } = await addOverlay(doc, c.file, c.place);
  const out = await PDFDocument.load(bytes, { updateMetadata: false });
  const after = streamHashes(out, c.place[0].pageIndex);

  // the invariant: every original stream survives, exactly one is added
  const survived = before.every(h => after.includes(h));
  console.log(`  content streams: ${before.length} before -> ${after.length} after; ` +
              `originals survive byte-identical: ${survived}`);
  check(survived, 'the original content stream must survive unchanged');
  check(after.length === before.length + 1, 'exactly one stream should be added');

  const prom = report.rebuilt.filter(e => e.prominent);
  console.log(`  prominent warnings: ${prom.length}` + (prom[0] ? ` — ${prom[0].item}` : ''));
  if (p.source === 'original') check(prom.length === 0, 'no warning when the original font is used');
  else if (p.source === 'USER') check(prom.length === 0, 'a user-set value is not a warning');
  else check(prom.length === 1, 'estimate/substitution must warn visibly');

  const name = `${c.file.replace(/\.pdf$/,'')}--overlay-${p.source.toLowerCase()}.pdf`;
  await writeFile(path.join(OUT, name), bytes);
  manifest.push({ input: c.file, op: `overlay-${p.source.toLowerCase()}`,
                  output: `out/${name}`,
                  pages: doc.getPages().map((_, i) => i), overlay: written });
}

await writeFile(path.join(OUT, 'overlay-manifest.json'), JSON.stringify(manifest, null, 2));
console.log(fail ? `\n${fail} CHECK(S) FAILED` : '\nall in-process checks passed');
