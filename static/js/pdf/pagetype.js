/* Security Buddy — is this page real text, or a picture of text?
 * ============================================================================
 *
 * TYPE A — the page draws text with a font that exists in the document. The
 *          font can be inspected: name, category, whether the glyph is there.
 * TYPE B — the page is a scan. There is no font to read, only an appearance to
 *          estimate, and the user has to be told that plainly.
 *
 * THE CRITERION IS NOT "DOES THE PAGE HAVE TEXT".
 *
 * An OCR'd scan has a great deal of text. Measured on a Tesseract output: 368
 * text-showing operations per page, an embedded font, and a /ToUnicode CMap
 * claiming 55,506 writable characters. What it does not have is any of that
 * text VISIBLE — every operation runs in text render mode 3 — or a font with
 * outlines: the program is 572 bytes and draws nothing.
 *
 * A check based on "is there text?" or "is the glyph in the subset?" promotes
 * such a page to TYPE A, writes with the glyphless font, and produces text the
 * user cannot see. So the page is classified first, from how it is drawn, and
 * only then is any font question asked.
 */

import {
    PDFDict, PDFName, PDFArray, PDFNumber, PDFStream, PDFRawStream, PDFRef,
    decodePDFRawStream,
} from './pdflib.js';
import { describeFont } from './fonts.js';

const N = {
    Contents: PDFName.of('Contents'), Resources: PDFName.of('Resources'),
    XObject: PDFName.of('XObject'), Font: PDFName.of('Font'),
    Subtype: PDFName.of('Subtype'), Image: PDFName.of('Image'),
    MediaBox: PDFName.of('MediaBox'),
};

/* A single image covering this much of the page is a scan, not an illustration. */
const FULL_PAGE_COVERAGE = 0.85;

function pageContentText(doc, page) {
    const contents = page.node.lookup(N.Contents);
    const streams = contents instanceof PDFArray
        ? contents.asArray().map((ref) => doc.context.lookup(ref))
        : [contents];
    let text = '';
    for (const stream of streams) {
        if (!(stream instanceof PDFStream)) continue;
        try {
            const bytes = stream instanceof PDFRawStream
                ? decodePDFRawStream(stream).decode()
                : stream.getContents();
            text += new TextDecoder('latin1').decode(bytes);
        } catch {
            // An unreadable content stream cannot be classified from its
            // drawing operations; the caller falls back on the other signals.
        }
    }
    return text;
}

/* Walk the drawing operators, tracking the graphics state well enough to know
 * how big each image lands on the page and whether any text is visible. */
function scanOperators(text) {
    const result = { textOps: 0, visibleTextOps: 0, renderModes: new Set(), imageNames: [] };

    // A minimal CTM tracker: q/Q stack and cm concatenation. Enough for image
    // coverage, which is all we need from it.
    let ctm = [1, 0, 0, 1, 0, 0];
    const stack = [];
    let renderMode = 0;
    const multiply = (a, b) => [
        a[0] * b[0] + a[1] * b[2], a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2], a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4], a[4] * b[1] + a[5] * b[3] + b[5],
    ];

    // Operators with their operands. Strings are skipped so that text content
    // containing "Tj" or "q" cannot be mistaken for an operator.
    const pattern = /\((?:\\.|[^\\()])*\)|<[0-9A-Fa-f\s]*>|(-?\d*\.?\d+)|(\/[^\s/<>\[\]()]+)|([A-Za-z'"*]+)/g;
    let operands = [];
    let match;

    while ((match = pattern.exec(text)) !== null) {
        const [token, number, name, operator] = match;
        if (number !== undefined) { operands.push(parseFloat(number)); continue; }
        if (name !== undefined) { operands.push(name); continue; }
        if (operator === undefined) { operands.push(token); continue; }

        switch (operator) {
            case 'q': stack.push([...ctm]); break;
            case 'Q': if (stack.length) ctm = stack.pop(); break;
            case 'cm':
                if (operands.length >= 6) ctm = multiply(operands.slice(-6), ctm);
                break;
            case 'Tr':
                renderMode = Number(operands[operands.length - 1]) || 0;
                result.renderModes.add(renderMode);
                break;
            case 'Tj': case 'TJ': case "'": case '"':
                result.textOps += 1;
                // 3 is invisible, 7 is clip-only: neither puts marks on the page.
                if (renderMode !== 3 && renderMode !== 7) result.visibleTextOps += 1;
                break;
            case 'Do': {
                const target = operands[operands.length - 1];
                if (typeof target === 'string' && target.startsWith('/')) {
                    const width = Math.abs(ctm[0]) + Math.abs(ctm[2]);
                    const height = Math.abs(ctm[1]) + Math.abs(ctm[3]);
                    result.imageNames.push({ name: target.slice(1), width, height });
                }
                break;
            }
            default: break;
        }
        operands = [];
    }
    return result;
}

/* Classify one page. Returns
 * { type: 'A' | 'B', reasons: string[], signals: {...}, fonts: [...] } */
export function classifyPage(doc, page) {
    const box = page.node.lookup(N.MediaBox);
    const pageWidth = box instanceof PDFArray ? Math.abs(box.lookup(2)?.asNumber?.() - box.lookup(0)?.asNumber?.()) : 612;
    const pageHeight = box instanceof PDFArray ? Math.abs(box.lookup(3)?.asNumber?.() - box.lookup(1)?.asNumber?.()) : 792;
    const pageArea = (pageWidth || 612) * (pageHeight || 792);

    const scan = scanOperators(pageContentText(doc, page));

    const resources = page.node.lookup(N.Resources);
    const xobjects = resources instanceof PDFDict ? resources.lookupMaybe(N.XObject, PDFDict) : null;
    let maxCoverage = 0;
    for (const image of scan.imageNames) {
        const target = xobjects ? xobjects.lookup(PDFName.of(image.name)) : null;
        if (!(target instanceof PDFStream)) continue;
        if (target.dict.get(N.Subtype) !== N.Image) continue;
        maxCoverage = Math.max(maxCoverage, (image.width * image.height) / pageArea);
    }

    const fonts = [];
    const fontDict = resources instanceof PDFDict ? resources.lookupMaybe(N.Font, PDFDict) : null;
    if (fontDict) {
        for (const [key] of fontDict.entries()) {
            const described = describeFont(doc, fontDict.get(key));
            if (described) fonts.push({ resourceName: key.asString().replace(/^\//, ''), ...described });
        }
    }

    const signals = {
        textOps: scan.textOps,
        visibleTextOps: scan.visibleTextOps,
        renderModes: [...scan.renderModes],
        imageCoverage: Number(maxCoverage.toFixed(3)),
        glyphlessFonts: fonts.filter((f) => f.glyphless).map((f) => f.name),
    };

    const reasons = [];
    const allTextInvisible = scan.textOps > 0 && scan.visibleTextOps === 0;
    const coveredByImage = maxCoverage >= FULL_PAGE_COVERAGE;

    if (allTextInvisible) {
        reasons.push(`all ${scan.textOps} text operations are drawn in an invisible render mode`);
    }
    if (coveredByImage) {
        reasons.push(`a single image covers ${Math.round(maxCoverage * 100)}% of the page`);
    }
    if (signals.glyphlessFonts.length) {
        reasons.push(`the page's font (${signals.glyphlessFonts.join(', ')}) has no glyph outlines`);
    }
    if (scan.textOps === 0 && coveredByImage) {
        reasons.push('the page draws no text at all');
    }

    // Invisible text over a full-page image is the OCR signature. A page with
    // no text at all under a full-page image is a scan that was never OCR'd.
    const isScan = (allTextInvisible && coveredByImage)
        || (scan.textOps === 0 && coveredByImage)
        || (signals.glyphlessFonts.length > 0 && coveredByImage);

    return { type: isScan ? 'B' : 'A', reasons, signals, fonts };
}

/* Classify the whole document: TYPE B when every page that could be classified
 * is a scan; mixed documents report per page. */
export function classifyDocument(doc) {
    const pages = doc.getPages().map((page) => classifyPage(doc, page));
    const scans = pages.filter((p) => p.type === 'B').length;
    return {
        pages,
        type: scans === pages.length && pages.length > 0 ? 'B' : (scans > 0 ? 'mixed' : 'A'),
        scannedPages: scans,
        pageCount: pages.length,
    };
}
