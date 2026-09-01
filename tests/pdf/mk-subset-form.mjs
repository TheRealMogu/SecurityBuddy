/* A form field whose /DA points at the DejaVuSans SUBSET already embedded in
 * 01-word-export.pdf. That subset can write only 41 characters — no 'V', no
 * 'k' — so writing "Verifica" must fall back to a substitute face.
 *
 *   node tests/pdf/mk-subset-form.mjs
 */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile } from 'fs/promises';
import path from 'path';
const { PDFDocument, PDFDict, PDFArray, PDFName, PDFNumber, PDFString, PDFRef } = PDFLib;
const n = PDFName.of;
const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');

const src = await PDFDocument.load(new Uint8Array(await readFile(path.join(DIR, '01-word-export.pdf'))),
                                   { updateMetadata: false });
const ctx = src.context;
const page = src.getPage(0);

// Find the embedded subset already on the page and reuse its exact font object.
const res = page.node.lookup(n('Resources'));
const fonts = res.lookupMaybe(n('Font'), PDFDict);
let subsetRef = null, subsetName = null;
for (const [key] of fonts.entries()) {
  const ref = fonts.get(key);
  const f = ctx.lookup(ref);
  const base = String(f.get(n('BaseFont'))).replace(/^\//, '');
  if (/DejaVuSans$/.test(base)) { subsetRef = ref; subsetName = base; break; }
}
if (!subsetRef) throw new Error('no DejaVuSans subset found on page 1');
console.log('reusing embedded subset:', subsetName);

const mkWidget = (name, x, y, w, h, daFont) => {
  const d = PDFDict.withContext(ctx);
  d.set(n('Type'), n('Annot'));
  d.set(n('Subtype'), n('Widget'));
  d.set(n('FT'), n('Tx'));
  d.set(n('T'), PDFString.of(name));
  d.set(n('DA'), PDFString.of(`/${daFont} 11 Tf 0 g`));
  d.set(n('F'), PDFNumber.of(4));
  const rect = PDFArray.withContext(ctx);
  for (const v of [x, y, x + w, y + h]) rect.push(PDFNumber.of(v));
  d.set(n('Rect'), rect);
  d.set(n('P'), page.ref);
  return ctx.register(d);
};

const a = mkWidget('subset.field', 60, 500, 240, 20, 'Sub');
const b = mkWidget('subset.other', 60, 460, 240, 20, 'Sub');

let annots = page.node.lookupMaybe(n('Annots'), PDFArray);
if (!annots) { annots = PDFArray.withContext(ctx); page.node.set(n('Annots'), annots); }
annots.push(a); annots.push(b);

const dr = PDFDict.withContext(ctx);
const drFonts = PDFDict.withContext(ctx);
drFonts.set(n('Sub'), subsetRef);          // the /DA font IS the document's subset
dr.set(n('Font'), drFonts);

const acro = PDFDict.withContext(ctx);
const fields = PDFArray.withContext(ctx);
fields.push(a); fields.push(b);
acro.set(n('Fields'), fields);
acro.set(n('DR'), dr);
acro.set(n('DA'), PDFString.of('/Sub 11 Tf 0 g'));
src.catalog.set(n('AcroForm'), ctx.register(acro));

const out = path.join(DIR, '08-subset-font-form.pdf');
await writeFile(out, await src.save({ updateFieldAppearances: false, useObjectStreams: false }));
console.log('wrote', path.basename(out));
