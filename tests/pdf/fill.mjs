/* The three cases required before form filling can be called done. */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile, mkdir } from 'fs/promises';
import path from 'path';
const { PDFDocument } = PDFLib;
const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { listTextFields, planFill, fillForm } = await import('../../static/js/pdf/fill.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const OUT = path.join(DIR, 'out');
await mkdir(OUT, { recursive: true });

const open = async (file) => {
  const r = await loadDocument(new Uint8Array(await readFile(path.join(DIR, file))), file);
  if (!r.ok) throw new Error(r.message);
  return r.doc;
};

const manifest = [];
let fail = 0;
const check = (ok, msg) => { if (!ok) { fail++; console.log('   FAIL ' + msg); } };

/* ── CASE 1: usable font as-is (standard Helvetica) — no warning expected ── */
console.log('\n=== CASE 1 — usable font, fixture 02 (Helvetica, standard 14) ===');
{
  const doc = await open('02-fillable-form.pdf');
  const fields = listTextFields(doc);
  console.log('  fields found:', fields.map(f => `${f.name}[${f.font?.name}/${f.font?.category}]`).join(', '));

  const values = { 'applicant.name': 'Luca Rossi', 'declaration.date': '01/09/2026' };
  const { plans, blocked } = planFill(doc, values);
  for (const p of plans) {
    console.log(`  ${p.name}: doc=${p.docType} font=${p.usedOriginal ? 'original' : 'SUBSTITUTE'} ` +
                `category=${p.category} reason=${p.reason}`);
    check(p.usedOriginal, `${p.name} should have used the original font`);
    check(p.docType === 'A', `${p.name} should be doc type A`);
  }
  check(blocked.length === 0, 'nothing should be blocked');

  const { bytes, report, written } = await fillForm(doc, '02-fillable-form.pdf', values);
  const prominent = report.rebuilt.filter(e => e.prominent);
  console.log('  prominent warnings:', prominent.length, '(expected 0)');
  check(prominent.length === 0, 'no warning should be raised when the original font is used');
  await writeFile(path.join(OUT, '02-fillable-form--filled.pdf'), bytes);
  manifest.push({ input: '02-fillable-form.pdf', op: 'fill-original',
                  output: 'out/02-fillable-form--filled.pdf',
                  pages: [0,1,2,3], written });
}

/* ── CASE 2: forced substitution (subset that cannot write the text) ─────── */
console.log('\n=== CASE 2 — forced substitution, fixture 08 (DejaVuSans subset) ===');
{
  const doc = await open('08-subset-font-form.pdf');
  const fields = listTextFields(doc);
  console.log('  fields found:', fields.map(f => `${f.name}[${f.font?.name}/${f.font?.category}` +
              `${f.font?.subset ? '/subset' : ''}]`).join(', '));

  const values = { 'subset.field': 'Verifica' };     // 'V' and 'k' are not in the subset
  const { plans } = planFill(doc, values);
  const p = plans[0];
  console.log(`  ${p.name}: doc=${p.docType} font=${p.usedOriginal ? 'original' : 'SUBSTITUTE'} ` +
              `category=${p.category} reason=${p.reason} missing=${JSON.stringify(p.missing)}`);
  console.log(`  substitute face: ${p.substituteFace}`);
  check(!p.usedOriginal, 'should have substituted');
  check(p.reason === 'glyph-missing', 'reason should be glyph-missing');
  check(p.missing.includes('V'), "missing should name 'V'");
  check(p.category === 'sans', 'DejaVuSans should classify as sans');
  check(p.substituteFace === 'Helvetica', 'sans substitute should be Helvetica');

  const { bytes, report, written } = await fillForm(doc, '08-subset-font-form.pdf', values);
  const prominent = report.rebuilt.filter(e => e.prominent);
  console.log('  prominent warnings:', prominent.length);
  check(prominent.length === 1, 'exactly one visible warning expected');
  if (prominent[0]) {
    console.log('  warning: ' + prominent[0].item);
    console.log('           ' + prominent[0].detail.slice(0, 150) + '…');
    check(/V/.test(prominent[0].detail), 'the warning must name the missing characters');
  }
  await writeFile(path.join(OUT, '08-subset-font-form--filled.pdf'), bytes);
  manifest.push({ input: '08-subset-font-form.pdf', op: 'fill-substitute',
                  output: 'out/08-subset-font-form--filled.pdf',
                  pages: [0,1,2], written });
}

/* ── CASE 3: untouched fields must be byte-identical ─────────────────────── */
console.log('\n=== CASE 3 — untouched fields unchanged (checked by pdf_compare.py) ===');
console.log('  outputs written; run:');
console.log('  python3 tools/pdf_compare.py --manifest tests/fixtures/pdf/out/fill-manifest.json');

await writeFile(path.join(OUT, 'fill-manifest.json'), JSON.stringify(manifest, null, 2));
console.log(fail ? `\n${fail} CHECK(S) FAILED` : '\nall in-process checks passed');
