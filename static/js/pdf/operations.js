/* Security Buddy — structural PDF operations.
 * ============================================================================
 *
 * Merge, split/extract, reorder and rotate. All four are lossless in the sense
 * that matters: no page content is touched. Pages are copied from the source
 * document with copyPages, never redrawn, and the only thing rotation changes
 * is the page's /Rotate attribute — a number, not a pixel.
 *
 * Every operation goes through the same three steps, in this order:
 *
 *   1. inspect  — refuse what must be refused, flag what the user should know
 *                 BEFORE anything is produced (encrypted, XFA, signed,
 *                 executable JavaScript);
 *   2. copy     — copyPages, recording which source page became which output
 *                 page;
 *   3. preserve — preserveAll() carries the catalog across and reports what
 *                 survived, what was rebuilt and what could not come along.
 *
 * Step 3 is not optional and there is no path around it. A "quick" operation
 * that skipped it would produce a file that opens correctly and has quietly
 * lost its bookmarks, its form and its attachments — and, as the page-leak
 * defect showed, may carry pages the user never selected.
 */

import { PDFDocument, PDFName, degrees, SAVE_OPTIONS } from './pdflib.js';
import { loadDocument, inspectDocument, assessOperation, createReport } from './preserve.js';
import { preserveAll } from './catalog.js';

/* ── Shared plumbing ─────────────────────────────────────────────────────── */

/* Open every input, refusing the whole operation if any one of them cannot be
 * opened. Partial success is not offered on purpose: a merge that silently
 * dropped an unreadable input would produce a document missing pages the user
 * believes are in it. */
export async function openAll(inputs) {
    const documents = [];
    for (const input of inputs) {
        const result = await loadDocument(input.bytes, input.label);
        if (!result.ok) return { ok: false, failure: result };
        documents.push({ doc: result.doc, label: input.label });
    }
    return { ok: true, documents };
}

/* Everything the user should be told before an operation runs.
 *
 * `blocked` stops the operation outright. `confirm` must be shown and
 * acknowledged first — the file is processed only if the user says so. */
export function preflight(documents) {
    const report = createReport();
    const multiple = documents.length > 1;
    for (const { doc, label } of documents) {
        assessOperation(inspectDocument(doc), report, multiple ? label : '');
    }
    return report;
}

/* Copy a selection of pages into a fresh document and preserve the catalog.
 *
 * `selections` is [{ doc, label, indices }]; `transform` runs on each copied
 * page before preservation and is where rotation applies its change. */
async function assemble(selections, transform) {
    const destDoc = await PDFDocument.create();
    const sources = [];

    for (const selection of selections) {
        const { doc, label, indices } = selection;
        const copied = await destDoc.copyPages(doc, indices);
        const pagePairs = [];

        copied.forEach((page, position) => {
            destDoc.addPage(page);
            pagePairs.push([doc.getPage(indices[position]).ref, page.ref]);
            if (transform) transform(page, indices[position], selection);
        });

        sources.push({ doc, label, pagePairs });
    }

    const report = preserveAll({ destDoc, sources });
    const bytes = await destDoc.save(SAVE_OPTIONS);
    return { bytes, report };
}

function validateIndices(indices, pageCount, what) {
    if (!Array.isArray(indices) || indices.length === 0) {
        throw new Error(`${what}: no pages selected.`);
    }
    for (const index of indices) {
        if (!Number.isInteger(index) || index < 0 || index >= pageCount) {
            throw new Error(
                `${what}: page ${index + 1} does not exist in a ` +
                `${pageCount}-page document.`);
        }
    }
}

/* ── Merge ───────────────────────────────────────────────────────────────── */

/* Concatenate documents in the order given.
 *
 * Structures that a PDF can only have one of — /Info, XMP, viewer preferences —
 * come from the first document and the rest are reported as dropped. Form
 * fields that share a name across inputs are reported too: in PDF those become
 * one field with one shared value, which is a behaviour change no amount of
 * copying can avoid. */
export async function merge(documents) {
    const selections = documents.map(({ doc, label }) => ({
        doc,
        label,
        indices: doc.getPages().map((_, index) => index),
    }));
    return assemble(selections);
}

/* ── Extract ─────────────────────────────────────────────────────────────── */

/* Keep the given pages, in the given order, and drop the rest. */
export async function extract(doc, label, indices) {
    validateIndices(indices, doc.getPageCount(), 'Extract');
    return assemble([{ doc, label, indices }]);
}

/* ── Split ───────────────────────────────────────────────────────────────── */

/* Cut a document into several documents at the given boundaries.
 *
 * `boundaries` are zero-based indices at which a new part starts, so [3] on a
 * 5-page document gives pages 1-3 and pages 4-5. Each part is a full,
 * independent document with the catalog preserved and its own report. */
export async function split(doc, label, boundaries) {
    const pageCount = doc.getPageCount();
    const cuts = [...new Set(boundaries)]
        .filter((b) => Number.isInteger(b) && b > 0 && b < pageCount)
        .sort((a, b) => a - b);

    const ranges = [];
    let start = 0;
    for (const cut of [...cuts, pageCount]) {
        ranges.push(Array.from({ length: cut - start }, (_, i) => start + i));
        start = cut;
    }

    const parts = [];
    for (const [index, indices] of ranges.entries()) {
        const partLabel = `${label} (part ${index + 1} of ${ranges.length})`;
        const result = await assemble([{ doc, label: partLabel, indices }]);
        parts.push({ ...result, indices, label: partLabel });
    }
    return parts;
}

/* ── Reorder ─────────────────────────────────────────────────────────────── */

/* Rearrange pages. `order` must be a permutation of every page index: reorder
 * moves pages, it never drops them, and a caller that meant to drop some should
 * say so by calling extract instead. */
export async function reorder(doc, label, order) {
    const pageCount = doc.getPageCount();
    validateIndices(order, pageCount, 'Reorder');
    if (order.length !== pageCount || new Set(order).size !== pageCount) {
        throw new Error(
            `Reorder: expected each of the ${pageCount} pages exactly once. ` +
            `To keep only some pages, use Extract instead.`);
    }
    return assemble([{ doc, label, indices: order }]);
}

/* ── Rotate ──────────────────────────────────────────────────────────────── */

/* Rotate pages by a multiple of 90 degrees.
 *
 * This changes /Rotate, an integer attribute of the page, and nothing else. The
 * content stream is not touched, so text stays text and the page is not
 * re-rendered. `angles` maps a page index to its rotation delta; pages absent
 * from it keep the rotation they had.
 */
export async function rotate(doc, label, angles) {
    const pageCount = doc.getPageCount();
    const indices = doc.getPages().map((_, index) => index);

    for (const [key, delta] of Object.entries(angles)) {
        const index = Number(key);
        if (!Number.isInteger(index) || index < 0 || index >= pageCount) {
            throw new Error(`Rotate: page ${index + 1} does not exist.`);
        }
        if (!Number.isInteger(delta) || delta % 90 !== 0) {
            throw new Error(
                `Rotate: ${delta} degrees is not a multiple of 90. Any other ` +
                `angle would require re-drawing the page, which this tool ` +
                `does not do.`);
        }
    }

    return assemble([{ doc, label, indices }], (page, sourceIndex) => {
        const delta = angles[sourceIndex];
        if (!delta) return;
        const current = page.getRotation().angle;
        // PDF stores /Rotate as a non-negative multiple of 90 below 360.
        page.setRotation(degrees(((current + delta) % 360 + 360) % 360));
    });
}

/* ── Naming ──────────────────────────────────────────────────────────────── */

export function outputName(sourceName, suffix) {
    const base = sourceName.replace(/\.pdf$/i, '');
    return `${base}-${suffix}.pdf`;
}
