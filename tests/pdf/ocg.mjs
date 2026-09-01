/* Does a document with optional content (layers) survive extraction, or does an
 * OCG reachable only through a catalog structure leak like defect (b)? */
import { PDFLib } from './shim.mjs';
const { PDFDocument, StandardFonts, PDFDict, PDFArray, PDFName, PDFString, PDFRef } = PDFLib;
const n = PDFName.of; const crypto = await import('crypto');
const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { preserveAll } = await import('../../static/js/pdf/catalog.js');
const { SAVE_OPTIONS } = await import('../../static/js/pdf/pdflib.js');

async function makeLayered() {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const ctx = doc.context; const ocgRefs = [];
  for (let i = 0; i < 4; i++) {
    const p = doc.addPage([400, 400]);
    p.drawText(`layer page ${i}`, { x: 40, y: 340, size: 20, font });
    const ocg = PDFDict.withContext(ctx);
    ocg.set(n('Type'), n('OCG')); ocg.set(n('Name'), PDFString.of(`Layer ${i}`));
    const ocgRef = ctx.register(ocg); ocgRefs.push(ocgRef);
    const props = PDFDict.withContext(ctx);
    props.set(n(`oc${i}`), ocgRef);
    p.node.Resources().set(n('Properties'), props);
  }
  const ocgs = PDFArray.withContext(ctx); ocgRefs.forEach(r => ocgs.push(r));
  const on = PDFArray.withContext(ctx); ocgRefs.forEach(r => on.push(r));
  const order = PDFArray.withContext(ctx); ocgRefs.forEach(r => order.push(r));
  const cfg = PDFDict.withContext(ctx); cfg.set(n('ON'), on); cfg.set(n('Order'), order);
  const props = PDFDict.withContext(ctx); props.set(n('OCGs'), ocgs); props.set(n('D'), cfg);
  doc.catalog.set(n('OCProperties'), ctx.register(props));
  return await doc.save(SAVE_OPTIONS);
}

const srcBytes = await makeLayered();
const A0 = (await loadDocument(srcBytes, 'a')).doc;
const hashPage = (doc, d) => { const c = doc.context.lookup(d.get(n('Contents')));
  const arr = c instanceof PDFArray ? c.asArray().map(r => doc.context.lookup(r)) : [c];
  const h = crypto.createHash('sha256');
  for (const s of arr) if (s?.contents) h.update(Buffer.from(s.contents));
  return h.digest('hex'); };
const srcH = A0.getPages().map(p => hashPage(A0, p.node));

async function extract(indices) {
  const doc = (await loadDocument(srcBytes, 'doc1')).doc;
  const dest = await PDFDocument.create();
  const copied = await dest.copyPages(doc, indices);
  const pagePairs = [];
  copied.forEach((p, k) => { dest.addPage(p); pagePairs.push([doc.getPage(indices[k]).ref, p.ref]); });
  const report = preserveAll({ destDoc: dest, sources: [{ doc, label: 'doc1', pagePairs }] });
  return { out: await PDFDocument.load(await dest.save(SAVE_OPTIONS), { updateMetadata: false }), report };
}

let fail = 0;
for (const sel of [[0, 1], [1], [3, 0], [0, 1, 2, 3]]) {
  const { out } = await extract(sel);
  const found = [];
  for (const [, o] of out.context.enumerateIndirectObjects())
    if (o instanceof PDFDict && o.get(n('Type')) === n('Page')) found.push(srcH.indexOf(hashPage(out, o)));
  const leaked = found.filter(i => !sel.includes(i));

  const props = out.catalog.lookupMaybe(n('OCProperties'), PDFDict);
  const listed = []; const listedTags = new Set();
  const ocgs = props?.lookupMaybe(n('OCGs'), PDFArray);
  if (ocgs) for (const r of ocgs.asArray()) {
    if (r instanceof PDFRef) listedTags.add(r.tag);
    listed.push(out.context.lookup(r)?.get(n('Name'))?.decodeText?.() ?? '?');
  }
  const usedTags = new Set();
  for (const p of out.getPages()) {
    const pr = p.node.Resources()?.lookupMaybe(n('Properties'), PDFDict);
    if (pr) for (const [, v] of pr.entries()) if (v instanceof PDFRef) usedTags.add(v.tag);
  }
  const unlisted = [...usedTags].filter(t => !listedTags.has(t));
  const ghosts = [...listedTags].filter(t => !usedTags.has(t));

  const ok = leaked.length === 0 && unlisted.length === 0 && ghosts.length === 0;
  if (!ok) fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  extract [${sel}] pages=[${found}] layers=[${listed}]` +
    (leaked.length ? `  *** LEAKED PAGES [${leaked}] ***` : '') +
    (unlisted.length ? `  *** page uses an OCG missing from /OCProperties ***` : '') +
    (ghosts.length ? `  *** ${ghosts.length} ghost layer(s) listed but used by no page ***` : ''));
}
console.log(fail ? `\n${fail} FAILURE(S)` : '\nall clear');
