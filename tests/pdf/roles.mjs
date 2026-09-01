/* The boundary case: a click inside the code block must resolve to Courier,
 * not to the heading whose last word is geometrically closer. */
import { PDFLib } from './shim.mjs';
import { readFile } from 'fs/promises';
import path from 'path';
const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { extractRuns, fontForRun, fontAtPoint } = await import('../../static/js/pdf/textruns.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const doc = (await loadDocument(new Uint8Array(
    await readFile(path.join(DIR, '09-typographic-roles.pdf'))), 'roles')).doc;
const page = doc.getPage(0);
const runs = extractRuns(doc, page);

console.log('runs extracted:');
for (const r of runs) console.log(`   x=${r.x.toFixed(1).padStart(6)} y=${r.y.toFixed(1).padStart(6)} ` +
                                  `font=${r.fontName} size=${r.size}`);

const probes = [
    { at: [70, 690],  want: 'Courier',        why: 'first code line — same baseline as the codes' },
    { at: [200, 690], want: 'Courier',        why: 'right along the first code line, under the heading' },
    { at: [70, 676],  want: 'Courier',        why: 'second code line' },
    { at: [70, 700],  want: 'Times-Bold',     why: 'on the heading baseline' },
    { at: [250, 700], want: 'Times-Bold',     why: 'end of the heading' },
    { at: [70, 600],  want: 'Helvetica',      why: 'body paragraph, isolated' },
];

console.log('\nlookups:');
let fail = 0;
for (const probe of probes) {
    const [x, y] = probe.at;
    const hit = fontAtPoint(runs, x, y);
    const font = hit.run ? fontForRun(doc, page, hit.run.fontName) : null;
    const got = font?.name ?? '(none)';
    const ok = got === probe.want;
    if (!ok) fail++;
    console.log(`  ${ok ? 'PASS' : 'FAIL'} (${String(x).padStart(3)},${y})  -> ${got.padEnd(12)} ` +
                `size=${hit.run?.size ?? '-'}  basis=${hit.basis.padEnd(14)} want=${probe.want}`);
    console.log(`        ${probe.why}`);
}

// What would a naive nearest-by-distance search have answered?
console.log('\nnaive nearest-by-distance, for comparison:');
for (const probe of probes.slice(0, 2)) {
    const [x, y] = probe.at;
    const visible = runs.filter(r => !r.invisible && r.fontName);
    const near = visible.reduce((b, c) =>
        Math.hypot(c.x - x, c.y - y) < Math.hypot(b.x - x, b.y - y) ? c : b);
    const font = fontForRun(doc, page, near.fontName);
    const wrong = font?.name !== probe.want;
    console.log(`  (${x},${y}) -> ${font?.name}  ${wrong ? '<-- WRONG ROLE' : '(same answer)'}`);
}
console.log(fail ? `\n${fail} FAILURE(S)` : '\nbaseline-first lookup picks the right role everywhere');
