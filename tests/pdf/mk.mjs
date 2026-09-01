// Build a source PDF carrying every structure preserve.js must handle.
import { PDFLib } from './shim.mjs';
const {
  PDFDocument, StandardFonts, PDFDict, PDFArray, PDFName, PDFNumber, PDFString, rgb,
} = PDFLib;

export async function makeRichPdf({ pages = 6, title = 'Rich source' } = {}) {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < pages; i++) {
    const p = doc.addPage([400, 600]);
    p.drawText(`Page ${i + 1}`, { x: 40, y: 540, size: 28, font, color: rgb(0.1, 0.1, 0.1) });
    p.drawText(`body text ${i}`, { x: 40, y: 500, size: 12, font });
  }
  doc.setTitle(title); doc.setAuthor('Test Author'); doc.setSubject('Subject line');
  doc.setKeywords(['alpha', 'beta']); doc.setCreator('Creator App');
  doc.setProducer('Original Producer');

  const ctx = doc.context;
  const pageRefs = doc.getPages().map(p => p.ref);
  const name = PDFName.of;

  // ── AcroForm with two text fields (widgets on pages 0 and 2)
  const form = doc.getForm();
  const f1 = form.createTextField('customer.name');
  f1.addToPage(doc.getPage(0), { x: 40, y: 300, width: 200, height: 24 });
  const f2 = form.createTextField('customer.email');
  f2.addToPage(doc.getPage(2), { x: 40, y: 300, width: 200, height: 24 });

  // ── Outline: two top-level items, one with two children on pages 1 and 4
  const clamp = i => Math.min(i, pages - 1);
  const mkItem = (titleText, rawIdx) => {
    const pageIdx = clamp(rawIdx);
    const d = PDFDict.withContext(ctx);
    d.set(name('Title'), PDFString.of(titleText));
    const dest = PDFArray.withContext(ctx);
    dest.push(pageRefs[pageIdx]); dest.push(name('XYZ'));
    dest.push(PDFLib.PDFNull); dest.push(PDFLib.PDFNull); dest.push(PDFLib.PDFNull);
    d.set(name('Dest'), dest);
    return { dict: d, ref: ctx.register(d) };
  };
  const root = PDFDict.withContext(ctx);
  const rootRef = ctx.register(root);
  root.set(name('Type'), name('Outlines'));
  const a = mkItem('Chapter one', 0);
  const b = mkItem('Chapter two', 3);
  const c1 = mkItem('Section 2.1', 1);
  const c2 = mkItem('Section 2.2', 4);
  a.dict.set(name('Parent'), rootRef); b.dict.set(name('Parent'), rootRef);
  a.dict.set(name('Next'), b.ref); b.dict.set(name('Prev'), a.ref);
  c1.dict.set(name('Parent'), b.ref); c2.dict.set(name('Parent'), b.ref);
  c1.dict.set(name('Next'), c2.ref); c2.dict.set(name('Prev'), c1.ref);
  b.dict.set(name('First'), c1.ref); b.dict.set(name('Last'), c2.ref);
  b.dict.set(name('Count'), PDFNumber.of(2));   // open
  root.set(name('First'), a.ref); root.set(name('Last'), b.ref);
  root.set(name('Count'), PDFNumber.of(4));
  doc.catalog.set(name('Outlines'), rootRef);

  // ── Named destinations
  const destsArr = PDFArray.withContext(ctx);
  for (const [key, raw] of [['intro', 0], ['middle', 2], ['end', 5]]) {
    const idx = clamp(raw);
    const d = PDFArray.withContext(ctx);
    d.push(pageRefs[idx]); d.push(name('Fit'));
    destsArr.push(PDFString.of(key)); destsArr.push(d);
  }
  const destsTree = PDFDict.withContext(ctx);
  destsTree.set(name('Names'), destsArr);
  const names = PDFDict.withContext(ctx);
  names.set(name('Dests'), ctx.register(destsTree));
  doc.catalog.set(name('Names'), ctx.register(names));

  // ── Page labels: pages 0-1 lowercase roman, then decimal from 1
  const nums = PDFArray.withContext(ctx);
  const r1 = PDFDict.withContext(ctx); r1.set(name('S'), name('r'));
  const r2 = PDFDict.withContext(ctx); r2.set(name('S'), name('D')); r2.set(name('St'), PDFNumber.of(1));
  nums.push(PDFNumber.of(0)); nums.push(r1);
  nums.push(PDFNumber.of(2)); nums.push(r2);
  const labels = PDFDict.withContext(ctx);
  labels.set(name('Nums'), nums);
  doc.catalog.set(name('PageLabels'), ctx.register(labels));

  // ── Viewer preferences + page mode
  doc.catalog.set(name('PageMode'), name('UseOutlines'));
  doc.catalog.set(name('Lang'), PDFString.of('en-GB'));

  return await doc.save({ updateFieldAppearances: false, useObjectStreams: false });
}
