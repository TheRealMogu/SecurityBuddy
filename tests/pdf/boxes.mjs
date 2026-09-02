/* Emits, as JSON, the rectangles the UI draws over every recognised run.
 *
 * The UI draws exactly these boxes: readableRuns() decides which runs exist,
 * runBox() decides their geometry. Nothing here is UI-only arithmetic, so
 * checking this output against Poppler checks what the browser paints.
 *
 * Usage: node boxes.mjs <fixture.pdf> [pageIndex]
 */
import { PDFLib } from './shim.mjs';
import { readFile } from 'fs/promises';
const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { readableRuns, runBox } = await import('../../static/js/pdf/replace.js');
const { PDFArray, PDFDict, PDFName } = PDFLib;

/* Annotation rectangles, so the ink checker can tell a form field's border from
 * a character a box failed to cover. A widget draws its own frame and fill on
 * the same scan lines as the label beside it. */
function annotationRects(page) {
    // lookupMaybe, not lookup: lookup asserts the type and throws on a page
    // that simply has no /Annots, which is most pages.
    const annots = page.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
    if (!annots) return [];
    const out = [];
    for (let i = 0; i < annots.size(); i += 1) {
        const annot = page.node.context.lookup(annots.get(i));
        if (!(annot instanceof PDFDict)) continue;
        const rect = annot.lookupMaybe(PDFName.of('Rect'), PDFArray);
        if (!rect || rect.size() < 4) continue;
        const n = [0, 1, 2, 3].map((k) => rect.lookup(k)?.asNumber?.() ?? 0);
        out.push({
            subtype: String(annot.get(PDFName.of('Subtype')) ?? '').replace(/^\//, ''),
            x: Math.min(n[0], n[2]), bottom: Math.min(n[1], n[3]),
            width: Math.abs(n[2] - n[0]), height: Math.abs(n[3] - n[1]),
        });
    }
    return out;
}

const file = process.argv[2];
const pageIndex = Number(process.argv[3] ?? 0);
const { doc } = await loadDocument(new Uint8Array(await readFile(file)), 'boxes');
const page = doc.getPage(pageIndex);
const { width, height } = page.getSize();
const runs = readableRuns(doc, page);

console.log(JSON.stringify({
    file, pageIndex, pageWidth: width, pageHeight: height,
    annotations: annotationRects(page),
    boxes: runs.map((run) => {
        const box = runBox(run);
        return {
            id: run.id, text: run.text, font: run.font?.name ?? run.fontName,
            size: run.size, invisible: !!run.invisible,
            x: box.x, top: box.top, bottom: box.bottom,
            width: box.width, height: box.height,
        };
    }),
}, null, 1));
