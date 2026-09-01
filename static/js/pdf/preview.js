/* Security Buddy — page thumbnails.
 *
 * pdf.js renders previews and nothing else. It never participates in producing
 * an output file: everything written comes from pdf-lib copying the original
 * page objects. Keeping that boundary sharp is what stops a preview pipeline
 * from quietly becoming a rasteriser.
 */

const WORKER_SRC = document.currentScript?.dataset?.worker
    ?? window.__SB_PDFJS_WORKER__;

let pdfjsPromise = null;

function loadPdfjs() {
    if (pdfjsPromise) return pdfjsPromise;
    pdfjsPromise = import(window.__SB_PDFJS_SRC__).then((pdfjs) => {
        /* Same-origin worker.
         *
         * pdf.js only reaches for a blob: worker when workerSrc is cross-origin
         * (PDFWorker#initialize tests _isSameOrigin first). Pointing it at our
         * own /static path keeps that branch unreachable, so the page stays
         * inside the site's existing default-src 'self' policy. */
        pdfjs.GlobalWorkerOptions.workerSrc = WORKER_SRC || window.__SB_PDFJS_WORKER__;
        return pdfjs;
    });
    return pdfjsPromise;
}

/* Open a document for previewing.
 *
 * The bytes are copied first: pdf.js transfers the buffer to its worker, which
 * detaches the original and would leave the caller holding an empty array.
 */
export async function openForPreview(bytes) {
    const pdfjs = await loadPdfjs();
    const task = pdfjs.getDocument({
        data: bytes.slice(),
        // No document in this tool needs pdf.js to evaluate anything, and a
        // preview renderer is the last place that should be able to.
        isEvalSupported: false,
        // Previews only: never fetch a fallback font from the network, and never
        // run the document's own JavaScript.
        disableAutoFetch: true,
        enableXfa: false,
    });
    return task.promise;
}

/* Render one page into a canvas sized to `maxWidth`. */
export async function renderThumbnail(pdf, pageNumber, canvas, maxWidth = 150) {
    const page = await pdf.getPage(pageNumber);
    const unscaled = page.getViewport({ scale: 1 });
    const scale = maxWidth / unscaled.width;
    const viewport = page.getViewport({ scale });

    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.floor(viewport.width * ratio);
    canvas.height = Math.floor(viewport.height * ratio);
    canvas.style.width = `${Math.floor(viewport.width)}px`;
    canvas.style.height = `${Math.floor(viewport.height)}px`;

    const context = canvas.getContext('2d');
    context.scale(ratio, ratio);
    await page.render({ canvasContext: context, viewport }).promise;
    return { width: viewport.width, height: viewport.height };
}

/* Render a page at the largest size that fits a box, for the full-screen
 * viewer. Same renderer as the thumbnails — the difference is only scale, so a
 * page never looks different up close than it did small. */
export async function renderToFit(pdf, pageNumber, canvas, boxWidth, boxHeight, rotationDelta = 0) {
    const page = await pdf.getPage(pageNumber);
    const base = page.getViewport({ scale: 1 });
    // The viewer must show the page as the operation will leave it, so a
    // pending rotation is applied to the preview too.
    const rotation = (((page.rotate || 0) + rotationDelta) % 360 + 360) % 360;
    const rotated = page.getViewport({ scale: 1, rotation });
    const scale = Math.min(boxWidth / rotated.width, boxHeight / rotated.height);
    const viewport = page.getViewport({ scale, rotation });

    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.floor(viewport.width * ratio);
    canvas.height = Math.floor(viewport.height * ratio);
    canvas.style.width = `${Math.floor(viewport.width)}px`;
    canvas.style.height = `${Math.floor(viewport.height)}px`;

    const context = canvas.getContext('2d');
    context.scale(ratio, ratio);
    await page.render({ canvasContext: context, viewport }).promise;
    return { width: base.width, height: base.height, rotation };
}
