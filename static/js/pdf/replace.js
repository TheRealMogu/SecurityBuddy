/* Security Buddy — replacing text that is already on the page.
 * ============================================================================
 *
 * THIS IS THE ONE OPERATION THAT REWRITES A CONTENT STREAM.
 *
 * Everything else in these tools leaves the page's bytes alone: structural
 * operations copy them, the overlay appends a second stream beside them. A
 * replacement cannot. The drawing operation that puts the old words on the page
 * is the thing being changed, so that stream is decoded, edited and written
 * back. pdf_compare.py reports it as a changed stream, and it is meant to.
 *
 * WHY NOT COVER THE OLD TEXT INSTEAD
 *
 * The easy version paints a rectangle over the old words and draws new ones on
 * top. It looks right and it is a lie: the original text is still in the content
 * stream, recoverable by copy-and-paste or by any parser. On a security tool,
 * shipping a redaction that does not redact is not an option. The old string is
 * removed from the file.
 *
 * WHAT THIS DOES NOT DO
 *
 * It does not re-flow. The replacement is drawn from the same origin with the
 * same font, so a longer string runs on past where the original ended and a
 * shorter one leaves a gap. Nothing after it moves. Where the width changes
 * enough to matter, the plan says so before anything is written — and on a
 * justified or kerned line the spacing of the replaced run is normalised, which
 * is visible up close.
 *
 * Reflow was excluded from this project from the start, and this is the reason:
 * doing it properly means re-breaking paragraphs, which needs the real metrics
 * and layout rules of the original producer. An approximation would move text
 * the user did not ask to move.
 */

import {
    PDFDocument, PDFDict, PDFArray, PDFName, PDFNumber, PDFStream, PDFRawStream, PDFRef,
    SAVE_OPTIONS,
} from './pdflib.js';
import { preserveAll } from './catalog.js';
import {
    describeFont, planText, substituteFor, buildReadableMap, widthMap, CATEGORIES,
} from './fonts.js';
import { classifyPage } from './pagetype.js';
import { extractRuns, fontForRun, locateOffset, pageContentText } from './textruns.js';

const N = {
    Contents: PDFName.of('Contents'), Length: PDFName.of('Length'),
    Resources: PDFName.of('Resources'), Font: PDFName.of('Font'),
};

/* Below this, a width change is not worth mentioning; above it, the line will
 * visibly run long or fall short, and the user has to be told. */
const WIDTH_TOLERANCE = 0.15;

/* ── Reading what is there ───────────────────────────────────────────────── */

/* Decode the bytes a show-operation draws into the characters a person sees.
 *
 * A subset font's codes are arbitrary slot numbers — without the /ToUnicode map
 * the existing text reads as control characters, which is what it looked like
 * before this went in. */
function decodeOperands(rawOperands, readable, twoByte) {
    const codes = [];
    for (const operand of rawOperands) {
        if (typeof operand !== 'string') continue;

        if (operand.startsWith('<')) {
            const hex = operand.slice(1, -1).replace(/\s+/g, '');
            const step = twoByte ? 4 : 2;
            for (let i = 0; i + step <= hex.length; i += step) {
                codes.push(parseInt(hex.slice(i, i + step), 16));
            }
            continue;
        }

        if (operand.startsWith('(')) {
            const body = operand.slice(1, -1);
            const bytes = [];
            for (let i = 0; i < body.length; i += 1) {
                if (body[i] !== '\\') { bytes.push(body.charCodeAt(i)); continue; }
                const next = body[i + 1];
                const simple = { n: 10, r: 13, t: 9, b: 8, f: 12, '(': 40, ')': 41, '\\': 92 }[next];
                if (simple !== undefined) { bytes.push(simple); i += 1; continue; }
                const octal = /^[0-7]{1,3}/.exec(body.slice(i + 1));
                if (octal) { bytes.push(parseInt(octal[0], 8)); i += octal[0].length; continue; }
                i += 1;   // an escaped newline: skipped
            }
            if (twoByte) {
                for (let i = 0; i + 1 < bytes.length; i += 2) codes.push((bytes[i] << 8) | bytes[i + 1]);
            } else {
                codes.push(...bytes);
            }
        }
    }

    let text = '';
    for (const code of codes) text += readable.get(code) ?? '�';
    return { text, codes };
}

/* Every run on the page that could be replaced, with the text it shows. */
export function readableRuns(doc, page) {
    const runs = extractRuns(doc, page);
    const fontCache = new Map();
    const out = [];

    runs.forEach((run, index) => {
        if (!run.span || !run.fontName || run.invisible) return;
        if (!fontCache.has(run.fontName)) {
            const font = fontForRun(doc, page, run.fontName);
            fontCache.set(run.fontName, font ? {
                font,
                readable: buildReadableMap(doc, font),
                widths: widthMap(doc, font),
                twoByte: font.subtype === 'Type0',
            } : null);
        }
        const entry = fontCache.get(run.fontName);
        if (!entry) return;

        const { text, codes } = decodeOperands(run.rawOperands, entry.readable, entry.twoByte);
        if (!text.trim()) return;

        out.push({
            id: index,
            x: run.x, y: run.y, size: run.size, span: run.span,
            fontName: run.fontName, font: entry.font,
            widths: entry.widths, twoByte: entry.twoByte,
            text, codes,
            kerned: run.span.operator === 'TJ'
                && run.rawOperands.some((o) => typeof o === 'number'),
        });
    });

    out.bounds = runs.bounds;
    return out;
}

/* Which run did the user click on?
 *
 * Same baseline-first idea as choosing a font for new text, but stricter: this
 * selects a specific piece of text to overwrite, so the click has to land on
 * the run's own extent, not merely near it. Picking the wrong run here does not
 * produce a slightly-off typeface — it rewrites the wrong words. */
export function runAtPoint(runs, x, y, tolerance = 6) {
    const onLine = runs.filter((run) => Math.abs(run.y - y) <= Math.max(tolerance, run.size * 0.8));
    if (!onLine.length) return null;

    const width = (run) => Math.max(measure(run.codes, run.widths, run.size), run.size);
    const inside = onLine.filter((run) => x >= run.x - 2 && x <= run.x + width(run) + 2);
    if (inside.length) {
        return inside.reduce((best, run) => (run.size < best.size ? run : best));
    }
    // On the line but past the text: the nearest run on that line.
    return onLine.reduce((best, run) => {
        const gap = (r) => (x < r.x ? r.x - x : x - (r.x + width(r)));
        return gap(run) < gap(best) ? run : best;
    });
}

/* The rectangle to draw around a run, in PDF user space.
 *
 * Width is MEASURED, from the font's own /Widths — not the
 * charCount * size * 0.5 estimate that extractRuns uses. That estimate is
 * correct for what it does (proximity: is the click near this run) but drawing
 * with it would put visibly crooked boxes around anything wider or narrower
 * than an average Latin lowercase, which is most headings and all monospace.
 *
 * Height has no source in the document and is not given one: nothing here reads
 * /Ascent or /Descent, by decision. It is derived from the type size purely to
 * draw a box — a presentational approximation that never reaches the engine and
 * never influences what is written. The proportions are the usual Latin ones,
 * generous enough to clear ascenders and descenders at any size.
 */
export const BOX_ASCENT = 0.85;
export const BOX_DESCENT = 0.25;

export function runBox(run) {
    const width = measure(run.codes, run.widths, run.size);
    return {
        x: run.x,
        width,
        top: run.y + run.size * BOX_ASCENT,
        bottom: run.y - run.size * BOX_DESCENT,
        height: run.size * (BOX_ASCENT + BOX_DESCENT),
    };
}

/* Measured drawn width, in points, from the font's own advance widths. */
export function measureRun(run) {
    return measure(run.codes, run.widths, run.size);
}

/* Approximate drawn width, in points, from the font's own advance widths. */
function measure(codes, widths, size) {
    let total = 0;
    for (const code of codes) total += widths.get(code) ?? 500;
    return (total / 1000) * size;
}

/* ── Planning ────────────────────────────────────────────────────────────── */

/* What would replacing this run's text cost? Decided before anything is
 * written, and shown to the user. */
export function planReplacement(doc, page, run, newText) {
    const pageType = classifyPage(doc, page).type;
    const decision = planText(doc, run.font, newText);

    if (decision.substituted && decision.category === 'cjk') {
        return {
            blocked: true, reason: 'cjk-no-substitute', category: 'cjk',
            explain: `"${run.font.name}" is a CJK font and cannot write `
                   + `${decision.missing.map((c) => JSON.stringify(c)).join(', ')}. `
                   + 'There is no standard PDF font for CJK and none is embedded here, so '
                   + 'there is nothing to substitute with that would not silently change '
                   + 'the script.',
        };
    }

    /* A substitute cannot be used for a REPLACEMENT the way it can for new text.
     *
     * New text in a different face is a visible, honest compromise. Half a line
     * of body text in a different face is a defect: the replaced words would not
     * match the words either side of them on the same line. So this stops
     * instead, and says which characters the document's own font is missing. */
    if (decision.substituted) {
        return {
            blocked: true, reason: decision.reason, category: decision.category,
            missing: decision.missing,
            explain: `${decision.explain} Replacing text is different from adding it: `
                   + 'a substitute face here would leave the new words looking unlike the '
                   + 'words either side of them on the same line. Change the wording to '
                   + `characters this font has, or add the text as a new overlay instead, `
                   + 'where a substitute is an honest compromise.',
        };
    }

    const oldWidth = measure(run.codes, run.widths, run.size);
    const newCodes = [...newText].map((char) => decision.codes.get(char) ?? 0x3f);
    const newWidth = measure(newCodes, run.widths, run.size);
    const delta = oldWidth === 0 ? 0 : (newWidth - oldWidth) / oldWidth;

    const notes = [];
    if (Math.abs(delta) > WIDTH_TOLERANCE) {
        notes.push(newWidth > oldWidth
            ? `The replacement is about ${Math.round(delta * 100)}% wider than what it `
              + `replaces (${oldWidth.toFixed(1)}pt to ${newWidth.toFixed(1)}pt). Nothing `
              + 'after it moves, so it will run on past where the original ended and may '
              + 'overlap what follows.'
            : `The replacement is about ${Math.round(-delta * 100)}% narrower than what it `
              + `replaces (${oldWidth.toFixed(1)}pt to ${newWidth.toFixed(1)}pt). Nothing `
              + 'after it moves, so it will leave a gap.');
    }
    if (run.kerned) {
        notes.push('The original was drawn with per-pair spacing adjustments, which cannot '
                 + 'be carried onto different words. The replacement is set with the font\'s '
                 + 'normal spacing, which is visible up close on a justified line.');
    }

    return {
        blocked: false, docType: pageType, category: decision.category,
        face: run.font.name, size: run.size,
        oldText: run.text, newText,
        oldWidth: Number(oldWidth.toFixed(2)), newWidth: Number(newWidth.toFixed(2)),
        widthDelta: Number((delta * 100).toFixed(1)),
        kerned: run.kerned, notes, codes: decision.codes,
    };
}

/* ── Writing ─────────────────────────────────────────────────────────────── */

/* `edits` is [{ pageIndex, runId, newText }]. */
export async function replaceText(doc, label, edits) {
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

    const byPage = new Map();
    for (const edit of edits) {
        if (!edit.newText) continue;
        if (!byPage.has(edit.pageIndex)) byPage.set(edit.pageIndex, []);
        byPage.get(edit.pageIndex).push(edit);
    }

    for (const [pageIndex, pageEdits] of byPage) {
        const page = destDoc.getPage(pageIndex);
        const runs = readableRuns(destDoc, page);
        const byId = new Map(runs.map((run) => [run.id, run]));

        const patches = [];
        for (const edit of pageEdits) {
            const run = byId.get(edit.runId);
            if (!run) continue;
            const plan = planReplacement(destDoc, page, run, edit.newText);
            if (plan.blocked) {
                const error = new Error(plan.explain);
                error.blocked = [{ ...plan, edit }];
                throw error;
            }
            patches.push({ run, plan });
            written.push({
                page: pageIndex, x: run.x, y: run.y,
                oldText: run.text, newText: edit.newText,
                docType: plan.docType, fontSource: 'original',
                category: plan.category, face: plan.face, size: plan.size,
                reason: 'replaced-in-place', widthDelta: plan.widthDelta,
                kerned: plan.kerned, notes: plan.notes,
            });
        }

        if (patches.length) applyPatches(destDoc, page, patches, runs.bounds);
    }

    for (const entry of written) {
        for (const note of entry.notes) {
            report.rebuilt.push({
                item: `Replaced text on page ${entry.page + 1} — "${entry.oldText.slice(0, 40)}"`,
                detail: note,
                prominent: true,
            });
        }
    }
    if (written.length) {
        report.rebuilt.push({
            item: 'Page content stream rewritten',
            detail: `${written.length} run(s) of existing text were replaced, which means the `
                  + 'content stream of the affected page(s) was decoded, edited and written '
                  + 'back. Every other operation in these tools leaves page bytes untouched; '
                  + 'this one cannot, because the drawing operation itself is what changed. '
                  + 'The original words are removed from the file, not covered over.',
        });
    }

    const bytes = await destDoc.save(SAVE_OPTIONS);
    return { bytes, report, written };
}

/* Rewrite the affected content streams with the new strings in place. */
function applyPatches(destDoc, page, patches, bounds) {
    const { text } = pageContentText(destDoc, page);

    // Group by stream, and apply from the end backwards so that each edit's
    // offsets are still valid when it is made.
    const perStream = new Map();
    for (const patch of patches) {
        const located = locateOffset(bounds, patch.run.span.start);
        if (!located) continue;
        if (!perStream.has(located.index)) {
            perStream.set(located.index, { bound: located, edits: [] });
        }
        perStream.get(located.index).edits.push({
            start: patch.run.span.start - located.start,
            end: patch.run.span.end - located.start,
            replacement: `${encodeCodes(patch.plan, patch.run)} Tj`,
        });
    }

    const contents = page.node.lookup(N.Contents);
    for (const [, { bound, edits }] of perStream) {
        let source = text.slice(bound.start, bound.end);
        edits.sort((a, b) => b.start - a.start);
        for (const edit of edits) {
            source = source.slice(0, edit.start) + edit.replacement + source.slice(edit.end);
        }

        const bytes = new Uint8Array(source.length);
        for (let i = 0; i < source.length; i += 1) bytes[i] = source.charCodeAt(i) & 0xff;
        const dict = PDFDict.withContext(destDoc.context);
        dict.set(N.Length, PDFNumber.of(bytes.length));
        const ref = destDoc.context.register(PDFRawStream.of(dict, bytes));

        if (contents instanceof PDFArray) {
            for (let i = 0; i < contents.size(); i += 1) {
                if (contents.get(i)?.tag === bound.ref?.tag) contents.set(i, ref);
            }
        } else {
            page.node.set(N.Contents, ref);
        }
    }
}

/* The replacement always uses the document's own font, so its own codes. */
function encodeCodes(plan, run) {
    let hex = '';
    for (const char of plan.newText) {
        const code = plan.codes.get(char) ?? 0x3f;
        hex += run.twoByte || code > 0xff
            ? code.toString(16).padStart(4, '0')
            : code.toString(16).padStart(2, '0');
    }
    return `<${hex}>`;
}

export { CATEGORIES };
