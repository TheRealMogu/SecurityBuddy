/* Security Buddy — page numbers, watermarks, headers and footers.
 * ============================================================================
 *
 * Everything here STAMPS: it writes into a content stream appended after the
 * page's own, so the document keeps every byte it arrived with, exactly like
 * shapes and overlay text. The report says "page bytes untouched" and means it.
 *
 * The text is ours — a page number, a "DRAFT" across the page, a running head —
 * not the document's, so it is set in a standard font (Helvetica) embedded once
 * and referenced by hand. Registering the resource by hand rather than through
 * pdf-lib's newFontDictionary() matters for the same reason it did in replace.js:
 * newFontDictionary() calls normalizeContentStreams(), which wraps the page's
 * existing content in q/Q — rewriting bytes nobody asked to change. An appended
 * stream needs none of that.
 */

import {
    PDFDocument, PDFDict, PDFArray, PDFName, PDFNumber, PDFRawStream, PDFString,
    StandardFonts, SAVE_OPTIONS, degrees,
} from './pdflib.js';
import { preserveAll } from './catalog.js';

const N = {
    Contents: PDFName.of('Contents'), Length: PDFName.of('Length'),
    Resources: PDFName.of('Resources'), Font: PDFName.of('Font'),
};

/* Where on the page a stamp sits. Margins are in points from the trim edge. */
export const POSITIONS = [
    'top-left', 'top-center', 'top-right',
    'bottom-left', 'bottom-center', 'bottom-right',
];

const MARGIN = 36;   // half an inch, the usual page-number margin
const fmt = (n) => (Math.round(n * 100) / 100).toString();

/* Substitute the page tokens. {n} the page's own number (honouring start-at and
 * the range offset), {total} the count that will carry the number. */
function expand(text, n, total) {
    return String(text ?? '')
        .replace(/\{n\}/g, String(n))
        .replace(/\{total\}/g, String(total))
        .replace(/\{page\}/g, String(n))
        .replace(/\{pages\}/g, String(total));
}

function encode(font, text) {
    // WinAnsi via the embedder, so accented running heads survive.
    try { return font.encodeText(text); } catch { return font.encodeText('?'.repeat(text.length)); }
}

/* ── Planning ────────────────────────────────────────────────────────────── */

/* A stamp job is one of: number | watermark | running. `pages` is the 0-based
 * indices to stamp; omitted means all. */
export function planStamp(doc, job) {
    const count = doc.getPageCount();
    const pages = (job.pages && job.pages.length ? job.pages : [...Array(count).keys()])
        .filter((i) => i >= 0 && i < count);
    const startAt = Number.isFinite(job.startAt) ? job.startAt : 1;

    const items = pages.map((pageIndex, order) => {
        const number = startAt + order;
        return { pageIndex, number, total: pages.length + startAt - 1 };
    });
    return { job, items, pageCount: pages.length };
}

/* ── Writing ─────────────────────────────────────────────────────────────── */

export async function addStamp(doc, label, job) {
    const { items } = planStamp(doc, job);

    const destDoc = await PDFDocument.create();
    const indices = doc.getPages().map((_, index) => index);
    const copied = await destDoc.copyPages(doc, indices);
    const pagePairs = [];
    copied.forEach((page, position) => {
        destDoc.addPage(page);
        pagePairs.push([doc.getPage(indices[position]).ref, page.ref]);
    });

    const report = preserveAll({ destDoc, sources: [{ doc, label, pagePairs }] });

    // One embedded Helvetica for the whole job.
    const bold = job.bold ? StandardFonts.HelveticaBold : StandardFonts.Helvetica;
    const font = await destDoc.embedStandardFont(bold);

    let stamped = 0;
    for (const item of items) {
        const page = destDoc.getPage(item.pageIndex);
        const stream = job.kind === 'watermark'
            ? watermarkStream(page, job, font)
            : textStamp(page, job, item, font);
        if (!stream) continue;
        appendContentStream(destDoc, page, font, stream);
        stamped += 1;
    }

    report.preserved.push({
        item: `${labelFor(job.kind)} added to ${stamped} page(s)`,
        detail: 'Written into a content stream appended after each page\'s own, which is left '
              + 'exactly as it was.',
    });

    const bytes = await destDoc.save(SAVE_OPTIONS);
    return { bytes, report, stamped };
}

function labelFor(kind) {
    return { number: 'Page numbers', watermark: 'Watermark',
             running: 'Header/footer' }[kind] ?? 'Stamp';
}

/* A single line of text placed at a corner or centre. Page numbers and running
 * heads are the same operation with different text. */
function textStamp(page, job, item, font) {
    const text = expand(job.text ?? '{n}', item.number, item.total);
    if (!text) return null;
    const size = job.size ?? 10;
    const { width, height } = page.getSize();
    const textWidth = font.widthOfTextAtSize(text, size);

    const position = job.position ?? (job.kind === 'number' ? 'bottom-center' : 'top-center');
    const [vert, horiz] = position.split('-');
    let x = MARGIN;
    if (horiz === 'center') x = (width - textWidth) / 2;
    else if (horiz === 'right') x = width - MARGIN - textWidth;
    let y = vert === 'top' ? height - MARGIN : MARGIN - size * 0.3;

    const [r, g, b] = job.colour ?? [0, 0, 0];
    return [
        'q', 'BT',
        '0 Tr', '100 Tz', '0 Ts', '0 Tc', '0 Tw',
        `/SBSTAMP ${fmt(size)} Tf`,
        `${fmt(r)} ${fmt(g)} ${fmt(b)} rg`,
        `1 0 0 1 ${fmt(x)} ${fmt(y)} Tm`,
        `${encode(font, text)} Tj`,
        'ET', 'Q',
    ].join('\n');
}

/* A word across the page, on a diagonal, faint. The classic DRAFT / CONFIDENTIAL
 * stamp. Rotated about the page centre and set at a low opacity through an
 * ExtGState so it sits behind the reader's attention, not on top of it. */
function watermarkStream(page, job, font) {
    const text = expand(job.text ?? 'DRAFT', 0, 0);
    if (!text) return null;
    const { width, height } = page.getSize();
    const size = job.size ?? 72;
    const textWidth = font.widthOfTextAtSize(text, size);

    const cx = width / 2;
    const cy = height / 2;
    const angle = (job.angle ?? 45) * Math.PI / 180;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    // Start the baseline so the text is centred on the page after rotation.
    const dx = -textWidth / 2;
    const dy = -size * 0.35;
    const [r, g, b] = job.colour ?? [0.6, 0.6, 0.6];

    return [
        'q',
        '/SBWM gs',                       // the low-opacity graphics state
        'BT',
        '0 Tr', '100 Tz', '0 Ts', '0 Tc', '0 Tw',
        `/SBSTAMP ${fmt(size)} Tf`,
        `${fmt(r)} ${fmt(g)} ${fmt(b)} rg`,
        `${fmt(cos)} ${fmt(sin)} ${fmt(-sin)} ${fmt(cos)} ${fmt(cx)} ${fmt(cy)} Tm`,
        `1 0 0 1 ${fmt(dx)} ${fmt(dy)} Tm`,   // (overwritten below with combined matrix)
        `${encode(font, text)} Tj`,
        'ET', 'Q',
    ];
}

/* Append the stream and make sure the page's resources name our font — and, for
 * a watermark, the transparency state it uses. */
function appendContentStream(destDoc, page, font, streamOrLines) {
    let resources = page.node.lookupMaybe(N.Resources, PDFDict);
    if (!resources) { resources = destDoc.context.obj({}); page.node.set(N.Resources, resources); }

    let fonts = resources.lookupMaybe(N.Font, PDFDict);
    if (!fonts) { fonts = destDoc.context.obj({}); resources.set(N.Font, fonts); }
    fonts.set(PDFName.of('SBSTAMP'), font.ref);

    let source;
    if (Array.isArray(streamOrLines)) {
        // watermark: build the combined rotate+translate matrix correctly and
        // register the ExtGState.
        source = buildWatermark(destDoc, page, resources, streamOrLines);
    } else {
        source = streamOrLines;
    }

    const bytes = new Uint8Array(source.length);
    for (let i = 0; i < source.length; i += 1) bytes[i] = source.charCodeAt(i) & 0xff;
    const dict = PDFDict.withContext(destDoc.context);
    dict.set(N.Length, PDFNumber.of(bytes.length));
    const ref = destDoc.context.register(PDFRawStream.of(dict, bytes));

    const existing = page.node.get(N.Contents);
    const resolved = destDoc.context.lookup(existing);
    if (resolved instanceof PDFArray) { resolved.push(ref); return; }
    const array = PDFArray.withContext(destDoc.context);
    if (existing) array.push(existing);
    array.push(ref);
    page.node.set(N.Contents, array);
}

/* Register a low-opacity ExtGState and fold the two text matrices into one, so
 * the diagonal placement is a single Tm rather than two (a second Tm would
 * replace the first, not compose with it). */
function buildWatermark(destDoc, page, resources, lines) {
    let ext = resources.lookupMaybe(PDFName.of('ExtGState'), PDFDict);
    if (!ext) { ext = destDoc.context.obj({}); resources.set(PDFName.of('ExtGState'), ext); }
    const gs = destDoc.context.obj({ CA: 0.18, ca: 0.18 });   // stroke + fill alpha
    ext.set(PDFName.of('SBWM'), gs);

    // Compose: first translate by (dx,dy) in text space, then rotate+move to
    // centre. Multiplying [1 0 0 1 dx dy] into [cos sin -sin cos cx cy].
    const tmRotate = lines.find((l) => l.endsWith('Tm') && !l.startsWith('1 0 0 1'));
    const tmShift = lines.find((l) => l.startsWith('1 0 0 1') && l.endsWith('Tm'));
    const [cos, sin, nsin, cosb, cx, cy] = tmRotate.split(' ').slice(0, 6).map(Number);
    const [, , , , dx, dy] = tmShift.split(' ').slice(0, 6).map(Number);
    const mx = cos * dx + nsin * dy + cx;
    const my = sin * dx + cosb * dy + cy;
    const combined = `${fmt(cos)} ${fmt(sin)} ${fmt(nsin)} ${fmt(cosb)} ${fmt(mx)} ${fmt(my)} Tm`;

    return lines
        .filter((l) => l !== tmShift)
        .map((l) => (l === tmRotate ? combined : l))
        .join('\n');
}

export { degrees };
