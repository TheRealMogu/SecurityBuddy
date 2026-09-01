/* Security Buddy — positioned text runs, and finding the font of a zone.
 * ============================================================================
 *
 * To make new text resemble what is already at a point on the page, we have to
 * know what IS at that point. This walks the page's drawing operators keeping
 * the text matrix, and emits one record per text-showing operation: where it
 * sits, which font resource drew it, and at what effective size.
 *
 * FINDING THE FONT OF A ZONE IS NOT "NEAREST BY DISTANCE".
 *
 * Real pages stack typographic roles close together — a heading sitting a few
 * points above a block of data, a caption under a table. The geometrically
 * nearest run to a click inside the data block is often the last word of the
 * heading above it, whose font is the wrong answer.
 *
 * So the search prefers runs on the SAME BASELINE (same Ty within a small
 * tolerance) over runs that are merely close. Sharing a baseline is a much
 * stronger statement of "same typographic zone" than proximity: text on one
 * line was almost always set in one style. Only when no run shares the click's
 * baseline does it fall back to nearest-by-distance, and past the search radius
 * it gives up rather than guess.
 */

import {
    PDFDict, PDFName, PDFArray, PDFStream, PDFRawStream, decodePDFRawStream,
} from './pdflib.js';
import { describeFont } from './fonts.js';

const N = {
    Contents: PDFName.of('Contents'), Resources: PDFName.of('Resources'),
    Font: PDFName.of('Font'),
};

/* Beyond this, a run is not "the same zone" in any useful sense — an inch. */
export const SEARCH_RADIUS_PT = 72;

/* Two baselines within this are the same line. Enough to absorb the sub-point
 * jitter of a justified line, tight enough not to swallow the next line. */
export const BASELINE_TOLERANCE_PT = 2.5;

/* How far past a line's text a click still counts as being on that line. Two
 * inches: generous enough for a click in the blank part of a short line,
 * bounded enough that it does not reach across a page. */
export const LINE_REACH_PT = 144;

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
            text += `${new TextDecoder('latin1').decode(bytes)}\n`;
        } catch {
            // Unreadable stream: the page simply contributes no runs.
        }
    }
    return text;
}

/* Every text-showing operation on the page, with position, font and size. */
export function extractRuns(doc, page) {
    const text = pageContentText(doc, page);
    const runs = [];

    // Resource names are per-producer and often unique per drawing call, so
    // they cannot stand in for font identity. Resolve each one once.
    const keyCache = new Map();
    const resolveKey = (resourceName) => {
        if (!keyCache.has(resourceName)) {
            const font = fontForRun(doc, page, resourceName);
            keyCache.set(resourceName, font?.name ?? resourceName);
        }
        return keyCache.get(resourceName);
    };

    let ctm = [1, 0, 0, 1, 0, 0];
    const stack = [];
    let textMatrix = null;
    let lineMatrix = null;
    let leading = 0;
    let fontName = null;
    let fontSize = 0;
    let renderMode = 0;

    const multiply = (a, b) => [
        a[0] * b[0] + a[1] * b[2], a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2], a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4], a[4] * b[1] + a[5] * b[3] + b[5],
    ];
    const translate = (m, tx, ty) => [
        m[0], m[1], m[2], m[3],
        m[0] * tx + m[2] * ty + m[4], m[1] * tx + m[3] * ty + m[5],
    ];

    // Strings are matched first so that text containing "Tj" or "q" is never
    // mistaken for an operator.
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
            case 'cm': if (operands.length >= 6) ctm = multiply(operands.slice(-6), ctm); break;
            case 'BT': textMatrix = [1, 0, 0, 1, 0, 0]; lineMatrix = [...textMatrix]; break;
            case 'ET': textMatrix = null; lineMatrix = null; break;
            case 'Tf':
                if (operands.length >= 2) {
                    fontName = String(operands[operands.length - 2]).replace(/^\//, '');
                    fontSize = Number(operands[operands.length - 1]) || 0;
                }
                break;
            case 'TL': leading = Number(operands[operands.length - 1]) || 0; break;
            case 'Tr': renderMode = Number(operands[operands.length - 1]) || 0; break;
            case 'Tm':
                if (operands.length >= 6) {
                    textMatrix = operands.slice(-6);
                    lineMatrix = [...textMatrix];
                }
                break;
            case 'Td': case 'TD':
                if (lineMatrix && operands.length >= 2) {
                    if (operator === 'TD') leading = -operands[operands.length - 1];
                    lineMatrix = translate(lineMatrix,
                        operands[operands.length - 2], operands[operands.length - 1]);
                    textMatrix = [...lineMatrix];
                }
                break;
            case 'T*':
                if (lineMatrix) {
                    lineMatrix = translate(lineMatrix, 0, -leading);
                    textMatrix = [...lineMatrix];
                }
                break;
            case 'Tj': case 'TJ': case "'": case '"': {
                if (!textMatrix) break;
                // How many characters this run draws, to estimate its extent.
                // A run is a horizontal segment, not a point: measuring only
                // from where it starts puts a click near the END of a line
                // outside the search radius and loses the line entirely.
                let charCount = 0;
                for (const operand of operands) {
                    if (typeof operand !== 'string') continue;
                    if (operand.startsWith('(')) charCount += operand.length - 2;
                    else if (operand.startsWith('<')) charCount += (operand.length - 2) / 4;
                }
                if (operator === "'" || operator === '"') {
                    lineMatrix = translate(lineMatrix ?? textMatrix, 0, -leading);
                    textMatrix = [...lineMatrix];
                }
                const device = multiply(textMatrix, ctm);
                // Effective size: the /Tf value scaled by the text matrix and
                // the CTM, which covers producers that write "Tf 1" and put the
                // real size in the matrix.
                const scale = Math.hypot(device[2], device[3]) || 1;
                const size = Number((fontSize * scale).toFixed(2));
                runs.push({
                    x: device[4],
                    y: device[5],
                    // Average Latin advance is near half an em; this is a
                    // proximity estimate, not typesetting.
                    width: Math.max(0, charCount) * size * 0.5,
                    fontName,
                    fontKey: fontName ? resolveKey(fontName) : null,
                    size,
                    invisible: renderMode === 3 || renderMode === 7,
                });
                break;
            }
            default: break;
        }
        operands = [];
    }
    return runs;
}

/* Resolve a run's font resource name against the page's resources. */
export function fontForRun(doc, page, resourceName) {
    if (!resourceName) return null;
    const resources = page.node.lookup(N.Resources);
    const fonts = resources instanceof PDFDict ? resources.lookupMaybe(N.Font, PDFDict) : null;
    const ref = fonts?.get(PDFName.of(resourceName));
    if (!ref) return null;
    const described = describeFont(doc, ref);
    return described ? { ...described, resourceName, ref } : null;
}

/* Which font is in use at (x, y)?
 *
 * Baseline first, then distance, then nothing. Returns
 * { run, basis: 'same-baseline' | 'nearest' | 'page-dominant' | 'none', distance }.
 */
export function fontAtPoint(runs, x, y, {
    radius = SEARCH_RADIUS_PT, tolerance = BASELINE_TOLERANCE_PT,
    lineReach = LINE_REACH_PT,
} = {}) {
    const visible = runs.filter((run) => !run.invisible && run.fontName);
    if (!visible.length) return { run: null, basis: 'none', distance: Infinity };

    // Distance to the run's horizontal extent, not to the point it starts at.
    const gapTo = (run) => {
        if (x < run.x) return run.x - x;
        if (x > run.x + run.width) return x - (run.x + run.width);
        return 0;
    };

    /* 1. Same baseline.
     *
     * Deliberately NOT filtered by the euclidean radius first. A click past the
     * end of a short line is still on that line, and the line is the strongest
     * statement of "same typographic zone" available — stronger than a heading
     * that happens to sit a few points above. Only the horizontal reach is
     * bounded, which is also what keeps a two-column layout honest: the nearest
     * same-baseline run is the one in the column that was clicked. */
    const sameBaseline = visible
        .filter((run) => Math.abs(run.y - y) <= tolerance)
        .filter((run) => gapTo(run) <= lineReach);
    if (sameBaseline.length) {
        const run = sameBaseline.reduce((best, candidate) =>
            (gapTo(candidate) < gapTo(best) ? candidate : best));
        return { run, basis: 'same-baseline', distance: gapTo(run) };
    }

    // 2. Nothing on this line: the nearest run inside the search radius.
    const distanceTo = (run) => Math.hypot(gapTo(run), run.y - y);
    const withinRadius = visible.filter((run) => distanceTo(run) <= radius);
    if (withinRadius.length) {
        const run = withinRadius.reduce((best, candidate) =>
            (distanceTo(candidate) < distanceTo(best) ? candidate : best));
        return { run, basis: 'nearest', distance: distanceTo(run) };
    }

    /* 3. Past the radius there is no local font. The page's dominant face is a
     *    weaker but honest answer, reported as such. Counted by resolved font
     *    identity, never by resource name: producers routinely emit a fresh
     *    resource name per drawing call, which would make every run look like a
     *    different font and hand dominance to whichever appeared first. */
    const byFont = new Map();
    for (const run of visible) {
        const key = run.fontKey ?? run.fontName;
        byFont.set(key, (byFont.get(key) ?? 0) + 1);
    }
    let dominant = null;
    let best = 0;
    for (const [key, count] of byFont) {
        if (count > best) { best = count; dominant = key; }
    }
    const run = visible.find((c) => (c.fontKey ?? c.fontName) === dominant) ?? null;
    return { run, basis: 'page-dominant', distance: Infinity };
}

/* The size to use on a scanned page, taken from its invisible OCR layer.
 *
 * The explicit /Tf size is used, not the spacing between baselines. Measured on
 * a Tesseract layer: the /Tf values give 11.0pt against a true 11.0pt in the
 * document the scan was made from, while baseline gaps give 12.9pt because
 * paragraph spacing inflates them. The OCR engine already did the
 * height-to-size conversion, and did it better.
 */
export function estimateSizeFromOcr(runs) {
    const sizes = runs.filter((run) => run.invisible && run.size > 0).map((run) => run.size);
    if (sizes.length < 3) return null;
    sizes.sort((a, b) => a - b);
    const median = sizes[Math.floor(sizes.length / 2)];
    // Outside this, the layer is telling us something we should not believe.
    if (median < 4 || median > 40) return null;
    return { size: Number(median.toFixed(1)), runs: sizes.length };
}

/* Declared, not measured: the fallback when a page offers no signal at all. */
export const DEFAULT_SIZE_PT = 11;
export const DEFAULT_CATEGORY = 'sans';
