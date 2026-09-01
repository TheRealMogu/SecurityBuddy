/* Does the browser-side page classifier agree with the measurements taken
 * independently with pypdf? */
import { PDFLib } from './shim.mjs';
import { readFile, readdir } from 'fs/promises';
import path from 'path';
const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { classifyDocument } = await import('../../static/js/pdf/pagetype.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const files = (await readdir(DIR)).filter(f => f.endsWith('.pdf')).sort();

const EXPECTED = { '03-scanned-ocr.pdf': 'B' };   // everything else is TYPE A

let fail = 0;
for (const file of files) {
  const bytes = new Uint8Array(await readFile(path.join(DIR, file)));
  const r = await loadDocument(bytes, file);
  if (!r.ok) { console.log(`${file.padEnd(28)} refused (${r.reason})`); continue; }
  const c = classifyDocument(r.doc);
  const want = EXPECTED[file] || 'A';
  const ok = c.type === want;
  if (!ok) fail++;
  const s = c.pages[0].signals;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${file.padEnd(26)} type=${c.type} (want ${want})  ` +
    `p0: textOps=${s.textOps} visible=${s.visibleTextOps} Tr=[${s.renderModes}] ` +
    `cover=${s.imageCoverage} glyphless=[${s.glyphlessFonts}]`);
  if (c.pages[0].reasons.length) console.log(`       reasons: ${c.pages[0].reasons.join('; ')}`);
  const cats = c.pages[0].fonts.map(f => `${f.name}=${f.category}${f.subset?'/subset':''}${f.standard14?'/std14':''}`);
  if (cats.length) console.log(`       fonts: ${cats.join(', ')}`);
}
console.log(fail ? `\n${fail} FAILURE(S)` : '\nclassification agrees with the pypdf measurements');
