/* Run every block-1 operation over the real fixtures and write the outputs to
 * disk so tools/pdf_compare.py can check them against their inputs.
 *
 *   node tests/pdf/run_fixtures.mjs
 *
 * Inputs come from tests/fixtures/pdf/ (gitignored — see DEVELOPMENT.md for how
 * to produce them). Outputs go to tests/fixtures/pdf/out/ along with a
 * manifest.json telling pdf_compare.py which output page came from which input
 * page, which it needs to compare content-stream hashes across a selection.
 */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile, mkdir, readdir } from 'fs/promises';
import path from 'path';

const { PDFDocument } = PDFLib;
const { loadDocument, inspectDocument } = await import('../../static/js/pdf/preserve.js');
const ops = await import('../../static/js/pdf/operations.js');

const FIXTURES = path.resolve(import.meta.dirname, '../fixtures/pdf');
const OUT = path.join(FIXTURES, 'out');
await mkdir(OUT, { recursive: true });

const files = (await readdir(FIXTURES)).filter((f) => f.toLowerCase().endsWith('.pdf')).sort();
if (!files.length) {
    console.log(`No fixtures in ${FIXTURES}. See DEVELOPMENT.md, "Fixture PDF per i test".`);
    process.exit(0);
}

const manifest = [];
const summarise = (report) => {
    const parts = [];
    for (const key of ['blocked', 'confirm', 'rebuilt', 'dropped']) {
        if (report[key].length) parts.push(`${key}:${report[key].length}`);
    }
    return parts.join(' ') || 'clean';
};

for (const file of files) {
    const bytes = await readFile(path.join(FIXTURES, file));
    const loaded = await loadDocument(new Uint8Array(bytes), file);

    if (!loaded.ok) {
        console.log(`\n${file}\n  REFUSED (${loaded.reason}): ${loaded.message.slice(0, 100)}…`);
        manifest.push({ input: file, refused: loaded.reason });
        continue;
    }

    const doc = loaded.doc;
    const pageCount = doc.getPageCount();
    const inspection = inspectDocument(doc);
    console.log(`\n${file}  (${pageCount} pages)`);

    const flags = [];
    if (inspection.hasAcroForm) flags.push('form');
    if (inspection.hasOutlines) flags.push('outline');
    if (inspection.hasStructTree) flags.push('tagged');
    if (inspection.hasOCProperties) flags.push('layers');
    if (inspection.javaScript.length) flags.push('JAVASCRIPT');
    if (inspection.isSigned) flags.push('SIGNED');
    if (flags.length) console.log(`  contains: ${flags.join(', ')}`);

    const preflightReport = ops.preflight([{ doc, label: file }]);
    for (const entry of preflightReport.blocked) console.log(`  BLOCKED  ${entry.item}`);
    for (const entry of preflightReport.confirm) console.log(`  CONFIRM  ${entry.item}`);

    const stem = file.replace(/\.pdf$/i, '');
    const jobs = [];

    // Extract: first half, in order.
    const half = Math.max(1, Math.ceil(pageCount / 2));
    jobs.push({
        name: 'extract',
        indices: Array.from({ length: half }, (_, i) => i),
        run: () => ops.extract(doc, file, Array.from({ length: half }, (_, i) => i)),
    });

    // Reorder: reverse.
    const reversed = Array.from({ length: pageCount }, (_, i) => pageCount - 1 - i);
    jobs.push({ name: 'reorder', indices: reversed, run: () => ops.reorder(doc, file, reversed) });

    // Rotate: every page 90 degrees clockwise. Page order is unchanged.
    const all = Array.from({ length: pageCount }, (_, i) => i);
    const angles = Object.fromEntries(all.map((i) => [i, 90]));
    jobs.push({ name: 'rotate', indices: all, run: () => ops.rotate(doc, file, angles) });

    // Merge: the document with itself, which doubles every page.
    jobs.push({
        name: 'merge-self',
        indices: [...all, ...all],
        run: async () => {
            const second = (await loadDocument(new Uint8Array(bytes), `${file}#2`)).doc;
            return ops.merge([{ doc, label: file }, { doc: second, label: `${file}#2` }]);
        },
    });

    for (const job of jobs) {
        try {
            const { bytes: outBytes, report } = await job.run();
            const outName = `${stem}--${job.name}.pdf`;
            await writeFile(path.join(OUT, outName), outBytes);
            console.log(`  ${job.name.padEnd(11)} -> ${outName}  [${summarise(report)}]`);
            for (const entry of report.rebuilt.filter((e) => e.prominent)) {
                console.log(`      ! ${entry.item}`);
            }
            manifest.push({ input: file, op: job.name, output: `out/${outName}`, pages: job.indices });
        } catch (err) {
            console.log(`  ${job.name.padEnd(11)} -> FAILED: ${err.message}`);
            manifest.push({ input: file, op: job.name, error: err.message });
        }
    }

    // Split into two parts, reported separately.
    if (pageCount > 1) {
        try {
            const parts = await ops.split(doc, file, [half]);
            let offset = 0;
            for (const [index, part] of parts.entries()) {
                const outName = `${stem}--split-${index + 1}.pdf`;
                await writeFile(path.join(OUT, outName), part.bytes);
                console.log(`  ${`split ${index + 1}`.padEnd(11)} -> ${outName}  [${summarise(part.report)}]`);
                manifest.push({ input: file, op: `split-${index + 1}`, output: `out/${outName}`, pages: part.indices });
                offset += part.indices.length;
            }
        } catch (err) {
            console.log(`  split       -> FAILED: ${err.message}`);
        }
    }
}

await writeFile(path.join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2));
console.log(`\nWrote ${manifest.filter((m) => m.output).length} output(s) to ${OUT}`);
console.log('Now run: python3 tools/pdf_compare.py --manifest tests/fixtures/pdf/out/manifest.json');
