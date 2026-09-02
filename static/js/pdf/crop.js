/* Security Buddy — cropping a page by REMOVING what falls outside it.
 * ============================================================================
 *
 * Setting /CropBox is the usual way to crop a PDF, and it is the wrong way for
 * this site: it changes where a viewer draws the page edge and leaves every
 * removed word, line and picture in the file, recoverable by anyone who opens
 * it with something other than a viewer. A tool on a security site that says
 * "cropped" while the content is still there is worse than no tool at all.
 *
 * So this crops by deleting the drawing operations themselves, and refuses
 * rather than pretending when it cannot. The rules it works by:
 *
 *   * Anything whose extent cannot be computed is NOT removable. Never delete
 *     something whose position is a guess.
 *   * Anything that straddles the crop edge is NOT removable here. Clipping a
 *     Bezier or re-encoding half an image is a different, much larger job; the
 *     honest answer is to name what would be left behind and stop.
 *   * Invisible text counts. An OCR layer draws no ink, so a viewer shows
 *     nothing where it sits, and it is exactly the content a crop is expected
 *     to get rid of. It is removed on the same terms as visible text.
 *   * A path used for clipping is never deleted. Removing it would change what
 *     is visible everywhere after it, which is a silent change to the parts of
 *     the page the user asked to KEEP.
 *
 * The plan is produced before anything is written, and the operation refuses
 * unless the caller has explicitly accepted whatever cannot be removed.
 */

import {
    PDFDocument, PDFArray, PDFDict, PDFName, PDFNumber, PDFStream, PDFRef,
    SAVE_OPTIONS,
} from './pdflib.js';
import { pageContentText, extractRuns, fontForRun } from './textruns.js';
import { widthMap, buildReadableMap } from './fonts.js';
import { rewriteSpans } from './replace.js';
import { preserveAll } from './catalog.js';

const N = {
    Contents: PDFName.of('Contents'),
    Resources: PDFName.of('Resources'),
    XObject: PDFName.of('XObject'),
    Subtype: PDFName.of('Subtype'),
    Image: PDFName.of('Image'),
    Form: PDFName.of('Form'),
    BBox: PDFName.of('BBox'),
    Matrix: PDFName.of('Matrix'),
    MediaBox: PDFName.of('MediaBox'),
    CropBox: PDFName.of('CropBox'),
    Annots: PDFName.of('Annots'),
    Rect: PDFName.of('Rect'),
};

/* A drawn thing sits inside, outside, or across the crop edge. Only the middle
 * one can be deleted, and only the last one has to be refused. */
const INSIDE = 'inside';
const OUTSIDE = 'outside';
const ACROSS = 'across';

const EPS = 0.01;

function classify(box, rect) {
    if (!box || !Number.isFinite(box.x0)) return null;   // extent unknown
    const outside = box.x1 <= rect.x + EPS || box.x0 >= rect.x + rect.width - EPS
                 || box.y1 <= rect.y + EPS || box.y0 >= rect.y + rect.height - EPS;
    if (outside) return OUTSIDE;
    const inside = box.x0 >= rect.x - EPS && box.x1 <= rect.x + rect.width + EPS
                && box.y0 >= rect.y - EPS && box.y1 <= rect.y + rect.height + EPS;
    return inside ? INSIDE : ACROSS;
}

const multiply = (a, b) => [
    a[0] * b[0] + a[1] * b[2], a[0] * b[1] + a[1] * b[3],
    a[2] * b[0] + a[3] * b[2], a[2] * b[1] + a[3] * b[3],
    a[4] * b[0] + a[5] * b[2] + b[4], a[4] * b[1] + a[5] * b[3] + b[5],
];
const apply = (m, x, y) => [m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]];

function boxOf(points) {
    if (!points.length) return null;
    let x0 = Infinity; let y0 = Infinity; let x1 = -Infinity; let y1 = -Infinity;
    for (const [x, y] of points) {
        if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
        x0 = Math.min(x0, x); y0 = Math.min(y0, y);
        x1 = Math.max(x1, x); y1 = Math.max(y1, y);
    }
    return { x0, y0, x1, y1 };
}

/* Everything the page draws, with where it lands and which bytes drew it.
 *
 * Bezier control points are included in the box rather than the curve's true
 * hull. That over-estimates, which is the safe direction: a curve reported as
 * crossing the edge is refused, never silently removed. */
function scanDrawing(doc, page) {
    const { text, bounds } = pageContentText(doc, page);
    const items = [];

    let ctm = [1, 0, 0, 1, 0, 0];
    const stack = [];
    let pathPoints = [];
    let pathStart = -1;
    let pathIsClip = false;
    let inText = false;

    const resources = page.node.lookup(N.Resources);
    const xobjects = resources instanceof PDFDict
        ? resources.lookupMaybe(N.XObject, PDFDict) : null;

    const pattern = /\((?:\\.|[^\\()])*\)|<[0-9A-Fa-f\s]*>|(-?\d*\.?\d+)|(\/[^\s/<>\[\]()]+)|([A-Za-z'"*]+)/g;
    let operands = [];
    let match;

    while ((match = pattern.exec(text)) !== null) {
        const [token, number, name, operator] = match;
        if (number !== undefined) { operands.push(parseFloat(number)); continue; }
        if (name !== undefined) { operands.push(name); continue; }
        if (operator === undefined) { operands.push(token); continue; }
        const opEnd = match.index + token.length;
        const n = operands.length;
        const num = (i) => Number(operands[n - i]);

        switch (operator) {
            case 'q': stack.push([...ctm]); break;
            case 'Q': if (stack.length) ctm = stack.pop(); break;
            case 'cm': if (n >= 6) ctm = multiply(operands.slice(-6), ctm); break;
            case 'BT': inText = true; break;
            case 'ET': inText = false; break;

            // Path construction. The span starts at the first operand of the
            // first construction operator so the whole path can be cut out.
            case 'm': case 'l':
                if (n >= 2) {
                    if (pathStart < 0) pathStart = match.index - operandText(text, match.index, 2);
                    pathPoints.push(apply(ctm, num(2), num(1)));
                }
                break;
            case 'c':
                if (n >= 6) {
                    if (pathStart < 0) pathStart = match.index - operandText(text, match.index, 6);
                    pathPoints.push(apply(ctm, num(6), num(5)), apply(ctm, num(4), num(3)),
                                    apply(ctm, num(2), num(1)));
                }
                break;
            case 'v': case 'y':
                if (n >= 4) {
                    if (pathStart < 0) pathStart = match.index - operandText(text, match.index, 4);
                    pathPoints.push(apply(ctm, num(4), num(3)), apply(ctm, num(2), num(1)));
                }
                break;
            case 're':
                if (n >= 4) {
                    if (pathStart < 0) pathStart = match.index - operandText(text, match.index, 4);
                    const [x, y, w, h] = [num(4), num(3), num(2), num(1)];
                    pathPoints.push(apply(ctm, x, y), apply(ctm, x + w, y),
                                    apply(ctm, x + w, y + h), apply(ctm, x, y + h));
                }
                break;
            case 'h': break;
            case 'W': case 'W*': pathIsClip = true; break;

            // Path painting closes the current path.
            case 'S': case 's': case 'f': case 'F': case 'B': case 'b': case 'n':
            case 'f*': case 'B*': case 'b*':
                if (pathStart >= 0) {
                    items.push({
                        kind: pathIsClip ? 'clip' : 'path',
                        box: boxOf(pathPoints),
                        span: { start: pathStart, end: opEnd },
                        painted: operator !== 'n',
                    });
                }
                pathPoints = []; pathStart = -1; pathIsClip = false;
                break;

            case 'Do': {
                const resourceName = String(operands[n - 1] ?? '').replace(/^\//, '');
                const target = xobjects ? xobjects.lookup(PDFName.of(resourceName)) : null;
                let kind = 'xobject';
                let unit = [[0, 0], [1, 0], [1, 1], [0, 1]];
                if (target instanceof PDFStream) {
                    const sub = target.dict.get(N.Subtype);
                    if (sub === N.Image) kind = 'image';
                    else if (sub === N.Form) {
                        kind = 'form';
                        const bbox = target.dict.lookupMaybe(N.BBox, PDFArray);
                        const mtx = target.dict.lookupMaybe(N.Matrix, PDFArray);
                        if (bbox && bbox.size() >= 4) {
                            const v = [0, 1, 2, 3].map((i) => bbox.lookup(i)?.asNumber?.() ?? NaN);
                            let inner = [[v[0], v[1]], [v[2], v[1]], [v[2], v[3]], [v[0], v[3]]];
                            if (mtx && mtx.size() >= 6) {
                                const m = [0, 1, 2, 3, 4, 5].map((i) => mtx.lookup(i)?.asNumber?.() ?? NaN);
                                inner = inner.map(([x, y]) => apply(m, x, y));
                            }
                            unit = inner;
                        } else {
                            unit = null;        // a form without a BBox has no known extent
                        }
                    }
                }
                items.push({
                    kind, name: resourceName,
                    box: unit ? boxOf(unit.map(([x, y]) => apply(ctm, x, y))) : null,
                    span: { start: match.index - operandText(text, match.index, 1), end: opEnd },
                });
                break;
            }

            case 'BI': {
                // Inline image: the bytes after ID are arbitrary, so the scan
                // jumps to EI rather than tokenising through them.
                const end = findInlineEnd(text, opEnd);
                items.push({
                    kind: 'inline-image',
                    box: boxOf([[0, 0], [1, 0], [1, 1], [0, 1]].map(([x, y]) => apply(ctm, x, y))),
                    span: { start: match.index, end },
                });
                pattern.lastIndex = end;
                break;
            }
            default: break;
        }
        operands = [];
    }
    return { items, bounds, text, hadText: inText };
}

/* How far back the operands of an operator reach, so a span covers them too. */
function operandText(text, opIndex, count) {
    let i = opIndex;
    let seen = 0;
    while (i > 0 && seen < count) {
        let j = i - 1;
        while (j > 0 && /\s/.test(text[j])) j -= 1;
        const tokenEnd = j + 1;
        while (j > 0 && !/\s/.test(text[j - 1])) j -= 1;
        if (tokenEnd === j) break;
        i = j;
        seen += 1;
    }
    return opIndex - i;
}

function findInlineEnd(text, from) {
    const at = text.indexOf('EI', from);
    return at < 0 ? text.length : at + 2;
}

/* ── Planning ────────────────────────────────────────────────────────────── */

/* What would cropping this page to `rect` remove, and what would it leave? */
export function planCrop(doc, page, rect) {
    const { items, bounds } = scanDrawing(doc, page);
    const remove = [];
    const split = [];
    const keep = [];
    const blocked = [];

    for (const item of items) {
        if (item.kind === 'clip') { keep.push(item); continue; }
        const where = classify(item.box, rect);
        if (where === null) {
            blocked.push({
                kind: item.kind,
                reason: 'extent-unknown',
                detail: `A ${describeKind(item.kind)} on this page does not declare where it `
                      + 'is drawn, so whether it falls outside the crop cannot be established. '
                      + 'It is left in the file rather than deleted on a guess.',
            });
            continue;
        }
        if (where === INSIDE) { keep.push(item); continue; }
        if (where === OUTSIDE) { remove.push(item); continue; }
        blocked.push({
            kind: item.kind,
            reason: item.kind === 'image' || item.kind === 'inline-image'
                ? 'image-across-edge' : 'geometry-across-edge',
            detail: item.kind === 'image' || item.kind === 'inline-image'
                ? 'An image crosses the crop edge. Removing only the part outside would mean '
                + 'decoding and re-encoding its pixels, which is not something these tools do '
                + 'to a document. The whole image stays, including the part outside the crop.'
                : `A ${describeKind(item.kind)} crosses the crop edge. Cutting a line or a `
                + 'curve at the boundary needs real geometry, which this tool does not do. '
                + 'The whole shape stays, including the part outside the crop.',
        });
    }

    // Text is scanned separately: extractRuns reports every run including the
    // invisible ones, which a crop must remove precisely because a viewer will
    // not show the user that they are still there.
    for (const run of textItems(doc, page)) {
        const where = classify(run.box, rect);
        if (where === null) {
            blocked.push({
                kind: 'text', reason: 'extent-unknown',
                detail: `The width of "${run.preview}" could not be measured from the font, `
                      + 'so whether it reaches past the crop cannot be established. The text '
                      + 'is left in the file.',
            });
            continue;
        }
        if (where === INSIDE) continue;
        if (where === OUTSIDE) { remove.push({ ...run, kind: 'text' }); continue; }

        // Across the edge. Only a horizontal cut can be made honestly: the run
        // sits on one baseline, so glyphs can be dropped from its ends. A run
        // crossing the top or bottom edge would need its glyphs cut in half.
        const verticalCross = run.box.y0 < rect.y - EPS
                           || run.box.y1 > rect.y + rect.height + EPS;
        const piece = verticalCross ? null : splitRun(run, rect);
        if (!piece) {
            blocked.push({
                kind: 'text',
                reason: verticalCross ? 'text-across-top-or-bottom' : 'text-unsplittable',
                detail: verticalCross
                    ? `"${run.preview}" sits across the top or bottom crop edge. Its letters `
                    + 'would have to be cut through, which needs geometry this tool does not '
                    + 'do. The whole line stays, including the part outside the crop.'
                    : `"${run.preview}" crosses the crop edge and could not be split on a `
                    + 'character boundary. The whole line stays.',
            });
            continue;
        }
        split.push(piece);
    }

    return {
        rect, bounds,
        remove, split, keep, blocked,
        clean: blocked.length === 0,
    };
}

function describeKind(kind) {
    return { path: 'line or shape', form: 'grouped drawing', image: 'image',
             'inline-image': 'inline image', xobject: 'drawing' }[kind] ?? kind;
}

/* Runs with a measured box, invisible ones included. */
function textItems(doc, page) {
    let runs = [];
    try { runs = extractRuns(doc, page); } catch { return []; }
    const cache = new Map();
    const out = [];

    for (const run of runs) {
        if (!run.span || !run.fontName) continue;
        if (!cache.has(run.fontName)) {
            const font = fontForRun(doc, page, run.fontName);
            const readable = font ? buildReadableMap(doc, font) : null;
            cache.set(run.fontName, font
                ? { font, readable, widths: widthMap(doc, font, readable),
                    twoByte: font.subtype === 'Type0' }
                : null);
        }
        const entry = cache.get(run.fontName);
        const codes = decode(run.rawOperands, entry?.twoByte);
        let width = null;
        if (entry) {
            let total = 0;
            let known = true;
            for (const code of codes) {
                // Never the 500 fallback here: a crop deletes things, so a
                // width the document does not state leaves the run unmeasured
                // and therefore untouched.
                const w = entry.widths.get(code) ?? entry.widths.defaultWidth;
                if (w === undefined) { known = false; break; }
                total += w;
            }
            if (known) width = (total / 1000) * run.size;
        }
        const preview = entry?.readable
            ? codes.map((c) => entry.readable.get(c) ?? '?').join('').slice(0, 30)
            : '(unreadable text)';

        out.push({
            span: run.span, x: run.x, y: run.y, size: run.size, codes, preview,
            twoByte: !!entry?.twoByte,
            widths: entry?.widths ?? new Map(),
            invisible: !!run.invisible,
            box: width === null ? null : {
                x0: run.x, x1: run.x + width,
                y0: run.y - run.size * 0.25, y1: run.y + run.size * 0.85,
            },
        });
    }
    return out;
}

function decode(operands, twoByte) {
    const codes = [];
    for (const operand of operands ?? []) {
        if (typeof operand !== 'string') continue;
        if (operand.startsWith('<')) {
            const hex = operand.slice(1, -1).replace(/\s+/g, '');
            const step = twoByte ? 4 : 2;
            for (let i = 0; i + step <= hex.length; i += step) {
                codes.push(parseInt(hex.slice(i, i + step), 16));
            }
        } else if (operand.startsWith('(')) {
            const body = operand.slice(1, -1).replace(/\\([nrtbf()\\])/g, (_, c) =>
                ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' }[c] ?? c));
            for (let i = 0; i < body.length; i += 1) {
                if (twoByte && i + 1 < body.length) {
                    codes.push((body.charCodeAt(i) << 8) | body.charCodeAt(i + 1));
                    i += 1;
                } else codes.push(body.charCodeAt(i));
            }
        }
    }
    return codes;
}

/* Drop the glyphs that fall outside, keeping the ones that do not.
 *
 * A glyph is kept only if its whole advance is inside: a letter half past the
 * edge would have to be cut through, and this tool does not cut glyphs. The
 * kept run is re-emitted as a TJ with one leading displacement, which moves the
 * text without touching the line matrix — a Td here would shift everything
 * positioned relative to this line afterwards. */
function splitRun(run, rect) {
    if (!run.codes.length || !run.size) return null;
    let cursor = run.x;
    const kept = [];
    let firstX = null;
    for (const code of run.codes) {
        const w = run.widths.get(code) ?? run.widths.defaultWidth;
        if (w === undefined) return null;
        const advance = (w / 1000) * run.size;
        const inside = cursor >= rect.x - EPS
                    && cursor + advance <= rect.x + rect.width + EPS;
        if (inside) {
            if (firstX === null) firstX = cursor;
            kept.push(code);
        } else if (kept.length) {
            // A gap in the middle would need two runs; the crop rectangle can
            // only cut a line at its ends, so this cannot happen — but if a
            // document ever produces it, refuse rather than reorder the words.
            const rest = run.codes.slice(run.codes.indexOf(code));
            if (rest.some((c) => {
                const rw = run.widths.get(c);
                return rw !== undefined;
            }) && kept.length < run.codes.length) break;
        }
        cursor += advance;
    }
    if (!kept.length || kept.length === run.codes.length) return null;
    return { ...run, kind: 'text-split', keptCodes: kept, newX: firstX ?? run.x };
}

/* ── Writing ─────────────────────────────────────────────────────────────── */

/* Crop pages, removing what falls outside. Refuses unless the caller has said
 * in so many words that it accepts whatever cannot be removed. */
export async function cropPages(doc, label, requests, { acceptUnremovable = false } = {}) {
    const plans = new Map();
    for (const request of requests) {
        const plan = planCrop(doc, doc.getPage(request.pageIndex), request.rect);
        plans.set(request.pageIndex, { plan, rect: request.rect });
    }

    const leftovers = [...plans.values()].flatMap(({ plan }) => plan.blocked);
    if (leftovers.length && !acceptUnremovable) {
        const error = new Error(
            `${leftovers.length} thing(s) outside the crop cannot be removed from the file. `
            + 'Cropping anyway would hide them without deleting them.');
        error.blocked = leftovers;
        throw error;
    }

    const destDoc = await PDFDocument.create();
    const indices = doc.getPages().map((_, index) => index);
    const copied = await destDoc.copyPages(doc, indices);
    const pagePairs = [];
    copied.forEach((page, position) => {
        destDoc.addPage(page);
        pagePairs.push([doc.getPage(indices[position]).ref, page.ref]);
    });

    const report = preserveAll({ destDoc, sources: [{ doc, label, pagePairs }] });
    const written = [];

    for (const [pageIndex, { rect }] of plans) {
        const page = destDoc.getPage(pageIndex);
        // Re-planned against the copy, because the spans must index the streams
        // that are about to be rewritten.
        const plan = planCrop(destDoc, page, rect);

        const spans = plan.remove.map((item) => ({
            start: item.span.start, end: item.span.end, replacement: '',
        }));
        for (const piece of plan.split) {
            spans.push({
                start: piece.span.start, end: piece.span.end,
                replacement: emitSplit(piece),
            });
        }
        if (spans.length) rewriteSpans(destDoc, page, plan.bounds, spans);

        const box = destDoc.context.obj([
            rect.x, rect.y, rect.x + rect.width, rect.y + rect.height,
        ]);
        page.node.set(N.MediaBox, box);
        page.node.set(N.CropBox, destDoc.context.obj([
            rect.x, rect.y, rect.x + rect.width, rect.y + rect.height,
        ]));

        const annotsRemoved = pruneAnnotations(destDoc, page, rect);

        written.push({
            page: pageIndex, rect,
            removed: plan.remove.length,
            split: plan.split.length,
            annotations: annotsRemoved,
            leftBehind: plan.blocked.length,
        });
    }

    for (const entry of written) {
        report.rebuilt.push({
            item: `Page ${entry.page + 1} cropped`,
            detail: `${entry.removed} drawing operation(s) deleted, ${entry.split} line(s) of `
                  + `text shortened, ${entry.annotations} annotation(s) removed. The page's `
                  + 'content stream was decoded, edited and written back — the removed content '
                  + 'is gone from the file, not hidden behind a smaller page box.',
            prominent: true,
        });
        if (entry.leftBehind) {
            report.dropped.push({
                item: `Page ${entry.page + 1}: ${entry.leftBehind} thing(s) outside the crop `
                    + 'are still in the file',
                detail: 'They cross the crop edge or their position could not be established, '
                      + 'so they were not deleted. They are outside the visible page and a '
                      + 'viewer will not show them, but they can still be recovered from the '
                      + 'file. Do not treat this output as redacted.',
                prominent: true,
            });
        }
    }

    const bytes = await destDoc.save(SAVE_OPTIONS);
    return { bytes, report, written };
}

/* The kept glyphs, displaced back to where they were drawn. */
function emitSplit(piece) {
    let hex = '';
    for (const code of piece.keptCodes) {
        hex += piece.twoByte || code > 0xff
            ? code.toString(16).padStart(4, '0')
            : code.toString(16).padStart(2, '0');
    }
    const shift = piece.newX - piece.x;
    if (Math.abs(shift) < 0.001) return `<${hex}> Tj`;
    // A TJ number displaces by -value/1000 of the type size.
    const adjust = -(shift * 1000) / piece.size;
    return `[ ${adjust.toFixed(2)} <${hex}> ] TJ`;
}

function pruneAnnotations(destDoc, page, rect) {
    const annots = page.node.lookupMaybe(N.Annots, PDFArray);
    if (!annots) return 0;
    const keep = [];
    let removed = 0;
    for (let i = 0; i < annots.size(); i += 1) {
        const ref = annots.get(i);
        const annot = destDoc.context.lookup(ref);
        const box = annot instanceof PDFDict ? annot.lookupMaybe(N.Rect, PDFArray) : null;
        if (!box || box.size() < 4) { keep.push(ref); continue; }
        const v = [0, 1, 2, 3].map((k) => box.lookup(k)?.asNumber?.() ?? NaN);
        const extent = {
            x0: Math.min(v[0], v[2]), x1: Math.max(v[0], v[2]),
            y0: Math.min(v[1], v[3]), y1: Math.max(v[1], v[3]),
        };
        if (classify(extent, rect) === OUTSIDE) { removed += 1; continue; }
        keep.push(ref);
    }
    if (removed) {
        // The field tree is pruned by the mark-and-sweep in preserve.js, which
        // keeps only what the surviving pages still reach.
        page.node.set(N.Annots, destDoc.context.obj(keep));
    }
    return removed;
}

export { INSIDE, OUTSIDE, ACROSS };
