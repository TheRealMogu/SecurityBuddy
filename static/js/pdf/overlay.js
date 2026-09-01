/* Security Buddy — free text placed anywhere on a page.
 * ============================================================================
 *
 * THE ORIGINAL CONTENT STREAM IS NEVER TOUCHED.
 *
 * A page's /Contents may be an ARRAY of streams, which the viewer concatenates
 * in order. New text goes into a second stream appended to that array, so the
 * bytes the page already had stay byte-identical and the addition is a separate,
 * inspectable object. pdf_compare.py checks exactly that: the original stream's
 * SHA-256 must survive, and the overlay must appear only as an added stream.
 *
 * WHAT FONT
 *
 * TYPE A — the page has real text, so there is a real font at the click point.
 *   textruns.js finds it, preferring a run on the same baseline over one that is
 *   merely nearer, and fonts.js decides whether it can write the characters
 *   asked for. Same three outcomes as form filling: original, a visible
 *   substitution, or a refusal for a missing CJK glyph.
 *
 * TYPE B — the page is a scan. There is no font, only an appearance:
 *   * with an OCR layer, the size is ESTIMATED from the layer's own /Tf values;
 *   * with no signal at all, a DECLARED default is used and said to be one.
 *   In both cases the face is a substitute, because there is nothing to reuse.
 *   Nothing is inferred from the pixels — an estimate with no signal behind it
 *   would be a guess wearing the costume of a measurement.
 *
 * Every one of those outcomes is reported on the placement it applies to, and
 * every estimated value can be corrected by the user before anything is written.
 */

import {
    PDFDocument, PDFDict, PDFArray, PDFName, PDFNumber, PDFRawStream, PDFRef,
    SAVE_OPTIONS,
} from './pdflib.js';
import { preserveAll } from './catalog.js';
import { planText, substituteFor, CATEGORIES } from './fonts.js';
import { classifyPage } from './pagetype.js';
import {
    extractRuns, fontForRun, fontAtPoint, estimateSizeFromOcr,
    DEFAULT_SIZE_PT, DEFAULT_CATEGORY,
} from './textruns.js';

const N = {
    Contents: PDFName.of('Contents'), Resources: PDFName.of('Resources'),
    Font: PDFName.of('Font'), Length: PDFName.of('Length'),
};

/* ── Planning ────────────────────────────────────────────────────────────── */

/* Work out, for every placement, which font and size will be used and where
 * that decision came from. Nothing is written here — this is what the UI shows
 * and what the user may correct. */
export function planOverlay(doc, placements) {
    const pageCache = new Map();
    const runCache = new Map();
    const plans = [];
    const blocked = [];

    for (const placement of placements) {
        const { pageIndex, x, y, text } = placement;
        if (!text || pageIndex < 0 || pageIndex >= doc.getPageCount()) continue;
        const page = doc.getPage(pageIndex);

        if (!pageCache.has(pageIndex)) {
            pageCache.set(pageIndex, classifyPage(doc, page));
            runCache.set(pageIndex, extractRuns(doc, page));
        }
        const classified = pageCache.get(pageIndex);
        const runs = runCache.get(pageIndex);

        const plan = classified.type === 'B'
            ? planForScan(runs, placement, classified)
            : planForText(doc, page, runs, placement);

        if (plan.blocked) { blocked.push({ ...plan, placement }); continue; }
        applyOverrides(plan, placement);
        plans.push({ ...plan, placement, pageIndex, x, y, text });
    }

    return { plans, blocked };
}

/* TYPE A: reuse the font already at that point when it can write the text. */
function planForText(doc, page, runs, placement) {
    const hit = fontAtPoint(runs, placement.x, placement.y);
    const font = hit.run ? fontForRun(doc, page, hit.run.fontName) : null;
    const size = hit.run?.size || DEFAULT_SIZE_PT;

    if (!font) {
        return {
            docType: 'A', source: 'DEFAULT', category: DEFAULT_CATEGORY,
            size: DEFAULT_SIZE_PT, basis: hit.basis, reason: 'no-text-nearby',
            face: substituteFor(DEFAULT_CATEGORY),
            explain: 'There is no text near this point to take a font from, so a '
                   + `declared default was used (${DEFAULT_SIZE_PT}pt sans-serif). `
                   + 'Check it and correct it if it does not fit.',
        };
    }

    const decision = planText(doc, font, placement.text);

    if (decision.substituted && decision.category === 'cjk') {
        return {
            blocked: true, docType: 'A', category: 'cjk', reason: 'cjk-no-substitute',
            explain: `The font at this point (${font.name}) is CJK and cannot write `
                   + `${decision.missing.length ? decision.missing.map((c) => JSON.stringify(c)).join(', ') : 'this text'}. `
                   + 'There is no standard PDF font for CJK and Security Buddy does not '
                   + 'embed one, so there is nothing to substitute with that would not '
                   + 'silently change the script.',
        };
    }

    if (!decision.substituted) {
        return {
            docType: 'A', source: 'original', category: decision.category, size,
            basis: hit.basis, reason: 'original', face: font.name,
            font, codes: decision.codes, missing: [],
        };
    }

    return {
        docType: 'A', source: 'SUBSTITUTE', category: decision.category, size,
        basis: hit.basis, reason: decision.reason, missing: decision.missing,
        face: substituteFor(decision.category, { bold: font.bold, italic: font.italic }),
        explain: decision.explain,
    };
}

/* TYPE B: no font to read. Estimate the size from the OCR layer if there is
 * one, otherwise fall back to a value that is declared rather than measured. */
function planForScan(runs, placement, classified) {
    const estimate = estimateSizeFromOcr(runs);

    if (estimate) {
        return {
            docType: 'B', source: 'ESTIMATED', category: DEFAULT_CATEGORY,
            size: estimate.size, reason: 'ocr-layer-median', ocrRuns: estimate.runs,
            face: substituteFor(DEFAULT_CATEGORY), missing: [],
            explain: 'This page is a scan — there is no font in it to reuse. The size '
                   + `was estimated from the invisible OCR text layer (${estimate.runs} `
                   + `text runs, median ${estimate.size}pt). This is an estimate of SIZE, `
                   + 'not a font recovered from the document: the typeface is a '
                   + 'substitute chosen for you. Check both and correct them if they '
                   + 'do not match the page.',
        };
    }

    return {
        docType: 'B', source: 'DEFAULT', category: DEFAULT_CATEGORY,
        size: DEFAULT_SIZE_PT, reason: 'no-signal-in-document',
        face: substituteFor(DEFAULT_CATEGORY), missing: [],
        explain: 'This page is a scan with no OCR text layer, so the document offers '
               + `no signal at all about its type size. A default of ${DEFAULT_SIZE_PT}pt `
               + 'sans-serif was used — check it and correct it manually. Nothing was '
               + 'inferred from the image itself.',
        reasons: classified.reasons,
    };
}

/* A value the user corrected is recorded as theirs, not as an estimate that
 * happened to be right. */
function applyOverrides(plan, placement) {
    let corrected = false;
    if (placement.sizeOverride && placement.sizeOverride !== plan.size) {
        plan.size = placement.sizeOverride;
        corrected = true;
    }
    if (placement.categoryOverride && placement.categoryOverride !== plan.category) {
        plan.category = placement.categoryOverride;
        plan.face = substituteFor(plan.category, {});
        plan.font = null;          // the original font no longer applies
        plan.codes = null;
        corrected = true;
    }
    if (corrected) {
        plan.correctedFrom = plan.source;
        plan.source = 'USER';
        plan.reason = 'user-corrected';
        plan.explain = 'Size and typeface were set by you, replacing the value the '
                     + 'document suggested.';
    }
}

/* ── Writing ─────────────────────────────────────────────────────────────── */

export async function addOverlay(doc, label, placements) {
    const { blocked } = planOverlay(doc, placements);
    if (blocked.length) {
        const error = new Error(blocked[0].explain);
        error.blocked = blocked;
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

    // Re-plan against the output document: its pages are the ones being written.
    const { plans } = planOverlay(destDoc, placements);
    const written = [];
    const byPage = new Map();
    for (const plan of plans) {
        if (!byPage.has(plan.pageIndex)) byPage.set(plan.pageIndex, []);
        byPage.get(plan.pageIndex).push(plan);
    }

    const substituteCache = new Map();
    for (const [pageIndex, pagePlans] of byPage) {
        const page = destDoc.getPage(pageIndex);
        const resources = ensureResources(destDoc, page);
        const fonts = ensureFontDict(destDoc, resources);
        const operations = [];

        for (const plan of pagePlans) {
            let fontRef = plan.font?.ref ?? null;
            let resourceName = plan.font?.resourceName ?? null;

            if (!fontRef) {
                const face = plan.face;
                if (!substituteCache.has(face)) {
                    substituteCache.set(face, await destDoc.embedFont(face));
                }
                fontRef = substituteCache.get(face).ref;
                resourceName = freshResourceName(fonts, 'SB');
                fonts.set(PDFName.of(resourceName), fontRef);
            } else if (!fonts.get(PDFName.of(resourceName))) {
                fonts.set(PDFName.of(resourceName), fontRef);
            }

            /* The text state is reset explicitly rather than trusted.
             *
             * q/Q saves and restores the graphics state, which INCLUDES the
             * text state — so a page that leaves the render mode set carries it
             * into everything drawn afterwards, our overlay included. Measured
             * on a Tesseract OCR layer: the stream does "BT 3 Tr ... ET" outside
             * any q/Q, leaving render mode 3 in force. Text added on top of it
             * was written into the file and drew nothing at all: exactly the
             * invisible-text failure this feature warns users about.
             *
             * The same stream also leaves the horizontal scale set via Tz, so
             * the whole text state is reset, not just the render mode. */
            operations.push([
                'q', 'BT',
                '0 Tr',      // fill glyphs: never inherit an invisible mode
                '100 Tz',    // normal horizontal scale
                '0 Ts',      // no text rise
                '0 Tc', '0 Tw',
                `/${resourceName} ${round(plan.size)} Tf`,
                '0 g',
                `1 0 0 1 ${round(plan.x)} ${round(plan.y)} Tm`,
                `${encodeText(plan)} Tj`,
                'ET', 'Q',
            ].join('\n'));

            written.push({
                page: pageIndex, x: round(plan.x), y: round(plan.y), text: plan.text,
                docType: plan.docType, fontSource: plan.source, category: plan.category,
                face: plan.face ?? plan.font?.name ?? '(none)', size: plan.size,
                reason: plan.reason, basis: plan.basis ?? null,
                missing: plan.missing ?? [], ocrRuns: plan.ocrRuns ?? null,
                correctedFrom: plan.correctedFrom ?? null, explain: plan.explain ?? null,
            });
        }

        appendContentStream(destDoc, page, `\n${operations.join('\n')}\n`);
    }

    // Every estimate, default and substitution is surfaced, on the placement it
    // belongs to. A summary the user has to go looking for is not a warning.
    for (const entry of written) {
        if (entry.fontSource === 'original') continue;
        const label = {
            SUBSTITUTE: 'Substitute font used',
            ESTIMATED: 'Size estimated, typeface substituted',
            DEFAULT: 'Default size and typeface used',
            USER: 'Size and typeface set by you',
        }[entry.fontSource] ?? entry.fontSource;
        report.rebuilt.push({
            item: `${label} — page ${entry.page + 1} at ${entry.x},${entry.y}`,
            detail: entry.explain ?? '',
            prominent: entry.fontSource !== 'USER',
        });
    }

    const bytes = await destDoc.save(SAVE_OPTIONS);
    return { bytes, report, written };
}

/* Append a stream to the page's /Contents, converting a single stream to an
 * array. The existing stream object is not modified, so its bytes — and its
 * hash — survive untouched. */
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

function ensureResources(destDoc, page) {
    let resources = page.node.lookup(N.Resources);
    if (!(resources instanceof PDFDict)) {
        resources = PDFDict.withContext(destDoc.context);
        page.node.set(N.Resources, resources);
    }
    return resources;
}

function ensureFontDict(destDoc, resources) {
    let fonts = resources.lookupMaybe(N.Font, PDFDict);
    if (!fonts) {
        fonts = PDFDict.withContext(destDoc.context);
        resources.set(N.Font, fonts);
    }
    return fonts;
}

/* A name that cannot collide with one the page already uses. */
function freshResourceName(fonts, prefix) {
    let index = 0;
    while (fonts.get(PDFName.of(`${prefix}${index}`))) index += 1;
    return `${prefix}${index}`;
}

function encodeText(plan) {
    const useOriginalCodes = plan.source === 'original' && plan.codes instanceof Map;
    let hex = '';
    for (const char of plan.text) {
        let code = useOriginalCodes ? plan.codes.get(char) : char.charCodeAt(0);
        if (code === undefined || code > 0xffff) code = 0x3f;   // '?'
        hex += code > 0xff
            ? code.toString(16).padStart(4, '0')
            : code.toString(16).padStart(2, '0');
    }
    return `<${hex}>`;
}

const round = (value) => Math.round(value * 100) / 100;

export { CATEGORIES };
