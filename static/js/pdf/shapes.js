/* Security Buddy — drawing shapes on a page.
 * ============================================================================
 *
 * A rectangle, an ellipse or a line, with a fill and a stroke.
 *
 * This is the cheapest operation in the feature set to do honestly, and the
 * reason is worth writing down: a shape does not have to touch anything that is
 * already on the page. It goes into a content stream APPENDED after the page's
 * own, exactly like overlay text, so every byte the document arrived with is
 * still there afterwards — the fidelity report can say "page bytes untouched"
 * and mean it. Nothing here rasterises, rebuilds or re-encodes.
 *
 * What that also means, and what the panel says out loud: a shape drawn over
 * text HIDES it. The words underneath are still in the file and a copy-and-paste
 * still finds them. A filled black rectangle is not a redaction, and on a
 * security site that confusion is the one worth pre-empting — it is the single
 * most common way people believe they have removed something when they have
 * not.
 */

import {
    PDFDocument, PDFDict, PDFArray, PDFName, PDFNumber, PDFRawStream, SAVE_OPTIONS,
} from './pdflib.js';
import { preserveAll } from './catalog.js';
import { pageContentText } from './textruns.js';
import { readableRuns } from './replace.js';

const N = { Contents: PDFName.of('Contents'), Length: PDFName.of('Length') };

export const KINDS = ['rectangle', 'ellipse', 'line'];

/* A colour as the PDF wants it: three numbers, zero to one. */
export function rgb(hex) {
    const value = String(hex ?? '').replace('#', '');
    const full = value.length === 3 ? [...value].map((c) => c + c).join('') : value;
    const n = parseInt(full, 16);
    if (!Number.isFinite(n) || full.length !== 6) return null;
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => c / 255);
}

const fmt = (n) => (Math.round(n * 1000) / 1000).toString();

/* ── Planning ────────────────────────────────────────────────────────────── */

/* What a shape would cover. Nothing here stops the operation — a shape over
 * text is a legitimate thing to want — but the user is told before saving,
 * because "I drew a black box over it" is how people think they redacted
 * something. */
export function planShapes(doc, shapes) {
    const plans = [];
    const runCache = new Map();

    for (const shape of shapes) {
        const fill = shape.fill ? rgb(shape.fill) : null;
        const stroke = shape.stroke ? rgb(shape.stroke) : null;
        if (!fill && !stroke) {
            plans.push({ shape, invalid: 'A shape needs a fill, an outline, or both.' });
            continue;
        }

        if (!runCache.has(shape.pageIndex)) {
            let runs = [];
            try { runs = readableRuns(doc, doc.getPage(shape.pageIndex)); } catch { /* */ }
            runCache.set(shape.pageIndex, runs);
        }
        const covered = fill
            ? runCache.get(shape.pageIndex).filter((run) => overlaps(shape, run))
            : [];

        plans.push({ shape, fill, stroke, covered: covered.map((r) => r.text) });
    }
    return { plans };
}

function overlaps(shape, run) {
    const x0 = Math.min(shape.x, shape.x + shape.width);
    const x1 = Math.max(shape.x, shape.x + shape.width);
    const y0 = Math.min(shape.y, shape.y + shape.height);
    const y1 = Math.max(shape.y, shape.y + shape.height);
    const top = run.y + run.size * 0.85;
    const bottom = run.y - run.size * 0.25;
    return run.x < x1 && run.x + Math.max(run.size, 4) > x0 && bottom < y1 && top > y0;
}

/* ── Writing ─────────────────────────────────────────────────────────────── */

export async function addShapes(doc, label, shapes) {
    const { plans } = planShapes(doc, shapes);
    const bad = plans.find((p) => p.invalid);
    if (bad) throw new Error(bad.invalid);

    const destDoc = await PDFDocument.create();
    const indices = doc.getPages().map((_, index) => index);
    const copied = await destDoc.copyPages(doc, indices);
    const pagePairs = [];
    copied.forEach((page, position) => {
        destDoc.addPage(page);
        pagePairs.push([doc.getPage(indices[position]).ref, page.ref]);
    });

    const report = preserveAll({ destDoc, sources: [{ doc, label, pagePairs }] });

    const byPage = new Map();
    for (const plan of plans) {
        if (!byPage.has(plan.shape.pageIndex)) byPage.set(plan.shape.pageIndex, []);
        byPage.get(plan.shape.pageIndex).push(plan);
    }

    const written = [];
    for (const [pageIndex, pagePlans] of byPage) {
        const page = destDoc.getPage(pageIndex);
        const before = pageContentText(destDoc, page).text.length;
        appendContentStream(destDoc, page, pagePlans.map(operators).join('\n'));
        written.push({
            page: pageIndex, count: pagePlans.length,
            covering: pagePlans.reduce((n, p) => n + p.covered.length, 0),
            bytesBefore: before,
        });
    }

    for (const entry of written) {
        report.preserved.push({
            item: `Page ${entry.page + 1}: ${entry.count} shape(s) added`,
            detail: 'The shapes were written into a content stream appended after the page\'s '
                  + 'own, which is left exactly as it was.',
        });
        if (entry.covering) {
            report.dropped.push({
                item: `Page ${entry.page + 1}: ${entry.covering} piece(s) of text are now `
                    + 'underneath a filled shape',
                detail: 'Covering text does not remove it. The words are still in the file and '
                      + 'a copy-and-paste or any parser still finds them. If the point is to '
                      + 'take the text out, edit or crop it instead — a filled rectangle is '
                      + 'not a redaction.',
                prominent: true,
            });
        }
    }

    const bytes = await destDoc.save(SAVE_OPTIONS);
    return { bytes, report, written };
}

/* The operators for one shape, wrapped in q/Q so the graphics state it sets —
 * colour, line width — cannot leak onto anything drawn after it. */
function operators(plan) {
    const { shape, fill, stroke } = plan;
    const width = shape.strokeWidth ?? 1;
    const out = ['q'];
    if (fill) out.push(`${fill.map(fmt).join(' ')} rg`);
    if (stroke) out.push(`${stroke.map(fmt).join(' ')} RG`, `${fmt(width)} w`);

    if (shape.kind === 'line') {
        out.push(`${fmt(shape.x)} ${fmt(shape.y)} m`,
                 `${fmt(shape.x + shape.width)} ${fmt(shape.y + shape.height)} l`, 'S');
    } else if (shape.kind === 'ellipse') {
        out.push(...ellipse(shape), paint(fill, stroke));
    } else {
        out.push(`${fmt(shape.x)} ${fmt(shape.y)} ${fmt(shape.width)} ${fmt(shape.height)} re`,
                 paint(fill, stroke));
    }
    out.push('Q');
    return out.join('\n');
}

const paint = (fill, stroke) => (fill && stroke ? 'B' : fill ? 'f' : 'S');

/* PDF has no ellipse operator, so it is four Bezier arcs. 0.5523 is the usual
 * constant: the control-point distance that makes a cubic curve match a
 * quarter circle to within about a part in ten thousand. */
const KAPPA = 0.5522847498;

function ellipse(shape) {
    const x0 = Math.min(shape.x, shape.x + shape.width);
    const y0 = Math.min(shape.y, shape.y + shape.height);
    const w = Math.abs(shape.width);
    const h = Math.abs(shape.height);
    const rx = w / 2;
    const ry = h / 2;
    const cx = x0 + rx;
    const cy = y0 + ry;
    const ox = rx * KAPPA;
    const oy = ry * KAPPA;
    const p = (x, y) => `${fmt(x)} ${fmt(y)}`;
    return [
        `${p(cx - rx, cy)} m`,
        `${p(cx - rx, cy + oy)} ${p(cx - ox, cy + ry)} ${p(cx, cy + ry)} c`,
        `${p(cx + ox, cy + ry)} ${p(cx + rx, cy + oy)} ${p(cx + rx, cy)} c`,
        `${p(cx + rx, cy - oy)} ${p(cx + ox, cy - ry)} ${p(cx, cy - ry)} c`,
        `${p(cx - ox, cy - ry)} ${p(cx - rx, cy - oy)} ${p(cx - rx, cy)} c`,
        'h',
    ];
}

function appendContentStream(destDoc, page, source) {
    const bytes = new Uint8Array(source.length);
    for (let i = 0; i < source.length; i += 1) bytes[i] = source.charCodeAt(i) & 0xff;

    const dict = PDFDict.withContext(destDoc.context);
    dict.set(N.Length, PDFNumber.of(bytes.length));
    const ref = destDoc.context.register(PDFRawStream.of(dict, bytes));

    const existing = page.node.get(N.Contents);
    const resolved = destDoc.context.lookup(existing);
    if (resolved instanceof PDFArray) {
        resolved.push(ref);
        return;
    }
    const array = PDFArray.withContext(destDoc.context);
    if (existing) array.push(existing);
    array.push(ref);
    page.node.set(N.Contents, array);
}
