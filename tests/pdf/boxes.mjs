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

const file = process.argv[2];
const pageIndex = Number(process.argv[3] ?? 0);
const { doc } = await loadDocument(new Uint8Array(await readFile(file)), 'boxes');
const page = doc.getPage(pageIndex);
const { width, height } = page.getSize();
const runs = readableRuns(doc, page);

console.log(JSON.stringify({
    file, pageIndex, pageWidth: width, pageHeight: height,
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
