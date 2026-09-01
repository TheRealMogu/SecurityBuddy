import { PDFLib } from './shim.mjs';
import { makeRichPdf } from './mk.mjs';
const { PDFDocument, PDFName, PDFDict, PDFArray } = PDFLib;
const n = PDFName.of;
const { loadDocument } = await import('/home/user/SecurityBuddy/static/js/pdf/preserve.js');
const { preserveAll } = await import('/home/user/SecurityBuddy/static/js/pdf/catalog.js');
const { SAVE_OPTIONS } = await import('/home/user/SecurityBuddy/static/js/pdf/pdflib.js');
try {
  const s1 = await makeRichPdf({ pages: 3, title: 'First doc' });
  const s2 = await makeRichPdf({ pages: 3, title: 'Second doc' });
  const dest = await PDFDocument.create();
  const sources = [];
  for (const [i, bytes] of [s1, s2].entries()) {
    const doc = (await loadDocument(bytes, `doc${i+1}`)).doc;
    const idx = [0,1,2];
    const copied = await dest.copyPages(doc, idx);
    const pagePairs = [];
    copied.forEach((p,k)=>{dest.addPage(p);pagePairs.push([doc.getPage(idx[k]).ref, p.ref]);});
    sources.push({ doc, label: `doc${i+1}`, pagePairs });
  }
  const report = preserveAll({ destDoc: dest, sources });
  for (const k of ['blocked','preserved','rebuilt','dropped'])
    for (const e of report[k]) console.log(`[${k}] ${e.item}: ${e.detail.slice(0,120)}`);
  const out = await PDFDocument.load(await dest.save(SAVE_OPTIONS), { updateMetadata: false });
  console.log('\npages:', out.getPageCount(), '| title:', JSON.stringify(out.getTitle()));
  let pageObjs = 0;
  for (const [, o] of out.context.enumerateIndirectObjects())
    if (o instanceof PDFDict && o.get(n('Type')) === n('Page')) pageObjs++;
  console.log('/Type /Page objects:', pageObjs, '(expected 6)');
  const outl = out.catalog.lookupMaybe(n('Outlines'), PDFDict);
  console.log('outline root Count:', outl?.lookupMaybe(n('Count'), PDFLib.PDFNumber)?.asNumber(), '(expected 4: 2 chapters x 2 docs)');
} catch (e) {
  console.log('THREW:', e.constructor?.name, '|', String(e.message).slice(0, 300));
  console.log('at:', (e.stack||'').split('\n').filter(l=>l.includes('/static/js/')).slice(0,4).join('\n'));
}
