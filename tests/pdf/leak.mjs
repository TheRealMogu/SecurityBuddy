import { PDFLib } from './shim.mjs';
import { makeRichPdf } from './mk.mjs';
const { PDFDocument, PDFName, PDFDict, PDFArray } = PDFLib;
const n = PDFName.of; const crypto = await import('crypto');
const { loadDocument } = await import('/home/user/SecurityBuddy/static/js/pdf/preserve.js');
const { preserveAll } = await import('/home/user/SecurityBuddy/static/js/pdf/catalog.js');
const { SAVE_OPTIONS } = await import('/home/user/SecurityBuddy/static/js/pdf/pdflib.js');

const hashPage = (doc, pageDict) => {
  const c = doc.context.lookup(pageDict.get(n('Contents')));
  const arr = c instanceof PDFArray ? c.asArray().map(r => doc.context.lookup(r)) : [c];
  const h = crypto.createHash('sha256');
  for (const s of arr) if (s?.contents) h.update(Buffer.from(s.contents));
  return h.digest('hex');
};

const src = await makeRichPdf({ pages: 6 });
const A0 = (await loadDocument(src, 'a')).doc;
const srcHashes = A0.getPages().map(p => hashPage(A0, p.node));

async function extract(indices) {
  const r = await loadDocument(src, 'doc1'); const doc = r.doc;
  const dest = await PDFDocument.create();
  const copied = await dest.copyPages(doc, indices);
  const pagePairs = [];
  copied.forEach((p, k) => { dest.addPage(p); pagePairs.push([doc.getPage(indices[k]).ref, p.ref]); });
  const report = preserveAll({ destDoc: dest, sources: [{ doc, label: 'doc1', pagePairs }] });
  return { bytes: await dest.save(SAVE_OPTIONS), report };
}

let fail = 0;
for (const sel of [[0,1],[0],[2,3],[5,4,3,2,1,0],[0,1,2,3,4,5]]) {
  const { bytes } = await extract(sel);
  const out = await PDFDocument.load(bytes, { updateMetadata: false });
  // every /Type /Page object in the file, whether or not it is in the page tree
  const found = [];
  for (const [ref, o] of out.context.enumerateIndirectObjects()) {
    if (o instanceof PDFDict && o.get(n('Type')) === n('Page')) found.push(srcHashes.indexOf(hashPage(out, o)));
  }
  // exit criterion: the kept pages' content streams must be byte-identical
  const kept = out.getPages().map(p => hashPage(out, p.node));
  const expect = sel.map(i => srcHashes[i]);
  const identical = kept.length === expect.length && kept.every((h, i) => h === expect[i]);
  const leaked = found.filter(i => !sel.includes(i));
  const ok = leaked.length === 0 && found.length === sel.length && identical;
  if (!ok) fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  extract [${sel}] -> page objects in file: [${found}]` +
              `  content streams identical: ${identical}` +
              (leaked.length ? `  *** LEAKED SOURCE PAGES: [${leaked}] ***` : ''));
}
console.log(fail ? `\n${fail} FAILURE(S)` : '\nall clear');
