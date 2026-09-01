/* Security Buddy — filling existing form fields.
 * ============================================================================
 *
 * The value goes in twice: as /V, which is what a program reading the form
 * sees, and as an appearance stream, which is what a person looking at the page
 * sees. Both have to be written here.
 *
 * WHY THE APPEARANCE IS BUILT BY HAND
 *
 * The easy routes are both wrong for this tool:
 *
 *   * Letting pdf-lib regenerate appearances means letting pdf-lib choose the
 *     font. It picks its own, and a filled form comes back restyled. That is
 *     the behaviour switched off in pdflib.js, and it is not switched back on
 *     here.
 *   * Setting /NeedAppearances and leaving it to the viewer hands the same
 *     choice to whichever viewer opens the file, with a different answer in
 *     each — and browsers frequently ignore the flag entirely, showing an empty
 *     field over a value that is really there.
 *
 * Writing the stream ourselves is the only way the font decision made in
 * fonts.js survives into the file. The font comes from the field's own /DA,
 * resolved against the form's /DR — that is what "the font already declared for
 * this zone" means for a form field.
 *
 * Fields that are not being filled are never touched: the whole document goes
 * through the block-1 copy path, so their /V and /AP come across byte for byte.
 */

import {
    PDFDocument, PDFDict, PDFArray, PDFName, PDFNumber, PDFString, PDFHexString,
    PDFRef, PDFRawStream, StandardFonts, SAVE_OPTIONS,
} from './pdflib.js';
import { preserveAll } from './catalog.js';
import { describeFont, planText, substituteFor, CATEGORIES } from './fonts.js';
import { classifyPage } from './pagetype.js';

const N = {
    AcroForm: PDFName.of('AcroForm'), Fields: PDFName.of('Fields'), Kids: PDFName.of('Kids'),
    T: PDFName.of('T'), FT: PDFName.of('FT'), V: PDFName.of('V'), DA: PDFName.of('DA'),
    DR: PDFName.of('DR'), Font: PDFName.of('Font'), AP: PDFName.of('AP'), N: PDFName.of('N'),
    Rect: PDFName.of('Rect'), BBox: PDFName.of('BBox'), Resources: PDFName.of('Resources'),
    Subtype: PDFName.of('Subtype'), Form: PDFName.of('Form'), Type: PDFName.of('Type'),
    XObject: PDFName.of('XObject'), Matrix: PDFName.of('Matrix'), P: PDFName.of('P'),
    Ff: PDFName.of('Ff'), MK: PDFName.of('MK'), Q: PDFName.of('Q'),
    NeedAppearances: PDFName.of('NeedAppearances'),
};

/* ── Reading the form ────────────────────────────────────────────────────── */

/* Every text field in the document, with the font its /DA points at. */
export function listTextFields(doc) {
    const acro = doc.catalog.lookupMaybe(N.AcroForm, PDFDict);
    if (!acro) return [];

    const defaultDA = acro.get(N.DA);
    const resources = acro.lookupMaybe(N.DR, PDFDict);
    const fields = [];
    const seen = new Set();

    const walk = (ref, prefix, inheritedDA) => {
        if (!(ref instanceof PDFRef) || seen.has(ref.tag)) return;
        seen.add(ref.tag);
        const dict = doc.context.lookup(ref);
        if (!(dict instanceof PDFDict)) return;

        const partial = dict.get(N.T);
        const label = partial ? (partial.decodeText?.() ?? String(partial)) : '';
        const name = prefix && label ? `${prefix}.${label}` : (label || prefix);
        const da = dict.get(N.DA) ?? inheritedDA;

        const kids = dict.lookupMaybe(N.Kids, PDFArray);
        // A kid with its own /T is a child field; a kid without one is this
        // field's widget and must not add a level to the qualified name.
        const childFields = kids ? kids.asArray().filter((kid) => {
            const child = doc.context.lookup(kid);
            return child instanceof PDFDict && child.get(N.T) !== undefined;
        }) : [];

        if (childFields.length) {
            for (const kid of childFields) walk(kid, name, da);
            return;
        }

        if (dict.get(N.FT) !== PDFName.of('Tx')) return;   // only text fields here

        const widgetRef = kids && kids.size() ? kids.get(0) : ref;
        const widget = doc.context.lookup(widgetRef);
        const appearance = parseDA(String(da?.decodeText?.() ?? da ?? ''));
        const fontRef = resolveFontRef(doc, appearance.fontName, resources, widget);
        const font = fontRef ? describeFont(doc, fontRef) : null;
        const value = dict.get(N.V);

        fields.push({
            name,
            fieldRef: ref,
            widgetRef,
            appearance,
            font,
            fontResourceName: appearance.fontName,
            currentValue: value ? (value.decodeText?.() ?? String(value)) : '',
            pageIndex: findPageOfWidget(doc, widgetRef),
        });
    };

    for (const field of acro.lookupMaybe(N.Fields, PDFArray)?.asArray() ?? []) {
        walk(field, '', defaultDA);
    }
    return fields;
}

/* "/Helv 12 Tf .1 .1 .1 rg" -> the resource name, the size, and the colour
 * operators, which are carried through untouched so the value keeps the ink
 * the form asked for. */
function parseDA(da) {
    const font = /\/([^\s/]+)\s+([\d.]+)\s+Tf/.exec(da);
    const colour = /((?:[\d.]+\s+){1,4}(?:rg|g|k))\b/.exec(da);
    return {
        raw: da,
        fontName: font ? font[1] : null,
        size: font ? parseFloat(font[2]) : 0,   // 0 means auto-size
        colour: colour ? colour[1].trim() : '0 g',
    };
}

function resolveFontRef(doc, resourceName, formResources, widget) {
    if (!resourceName) return null;
    const key = PDFName.of(resourceName);

    const fromDR = formResources?.lookupMaybe(N.Font, PDFDict)?.get(key);
    if (fromDR) return fromDR;

    // Some producers only put the font in the widget's own appearance resources.
    const appearance = widget instanceof PDFDict ? widget.lookup(N.AP) : null;
    const normal = appearance instanceof PDFDict ? appearance.lookup(N.N) : null;
    const resources = normal?.dict?.lookup(N.Resources);
    return resources instanceof PDFDict ? resources.lookupMaybe(N.Font, PDFDict)?.get(key) ?? null : null;
}

function findPageOfWidget(doc, widgetRef) {
    if (!(widgetRef instanceof PDFRef)) return -1;
    const pages = doc.getPages();
    for (let i = 0; i < pages.length; i += 1) {
        const annots = pages[i].node.lookupMaybe(PDFName.of('Annots'), PDFArray);
        if (!annots) continue;
        for (const ref of annots.asArray()) {
            if (ref instanceof PDFRef && ref.tag === widgetRef.tag) return i;
        }
    }
    return -1;
}

/* ── Planning ────────────────────────────────────────────────────────────── */

/* Decide, for every value the user typed, which font will write it — before
 * anything is produced. The UI shows this; nothing is discovered afterwards. */
export function planFill(doc, values) {
    const fields = listTextFields(doc);
    const byName = new Map(fields.map((f) => [f.name, f]));
    const pageTypes = new Map();
    const plans = [];
    const blocked = [];

    for (const [name, text] of Object.entries(values)) {
        const field = byName.get(name);
        if (!field || !text) continue;

        if (!pageTypes.has(field.pageIndex) && field.pageIndex >= 0) {
            pageTypes.set(field.pageIndex, classifyPage(doc, doc.getPage(field.pageIndex)));
        }
        const page = pageTypes.get(field.pageIndex);
        const docType = page?.type ?? 'A';

        const decision = planText(doc, field.font, text);
        const category = decision.category;

        // CJK has no substitute by decision: there is no standard PDF CJK face,
        // and embedding one would add megabytes for a rare case. A missing CJK
        // glyph stops the operation instead of writing the wrong script.
        if (decision.substituted && category === 'cjk') {
            blocked.push({
                field: name,
                reason: 'cjk-no-substitute',
                detail: `"${name}" uses a CJK font (${field.font?.name ?? 'unknown'}) that cannot `
                      + `write ${decision.missing.length ? decision.missing.map((c) => JSON.stringify(c)).join(', ') : 'this text'}. `
                      + `There is no standard PDF font for CJK, and Security Buddy does not embed `
                      + `one, so there is nothing to substitute with that would not silently change `
                      + `the script. Fill this field in an application that has the font.`,
            });
            continue;
        }

        plans.push({
            field,
            name,
            text,
            docType,
            docTypeReasons: page?.reasons ?? [],
            category,
            usedOriginal: !decision.substituted,
            reason: decision.reason,
            missing: decision.missing,
            explain: decision.explain,
            codes: decision.codes,
            substituteFace: decision.substituted
                ? substituteFor(category, { bold: field.font?.bold, italic: field.font?.italic })
                : null,
        });
    }

    return { plans, blocked, fields };
}

/* ── Writing ─────────────────────────────────────────────────────────────── */

/* Fill the form. Everything goes through the block-1 copy path first, so pages
 * and every untouched field arrive byte-identical; only the filled widgets are
 * then rewritten in the output. */
export async function fillForm(doc, label, values) {
    const { plans, blocked } = planFill(doc, values);
    if (blocked.length) {
        const error = new Error(blocked[0].detail);
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

    // Re-read the fields from the OUTPUT document: the widgets there are the
    // objects the pages actually reference.
    const destFields = new Map(listTextFields(destDoc).map((f) => [f.name, f]));
    const written = [];
    const substituteCache = new Map();

    for (const plan of plans) {
        const target = destFields.get(plan.name);
        if (!target) continue;

        let fontRef = target.font?.ref ?? null;
        let faceName = target.font?.name ?? '(none)';

        if (plan.substituteFace) {
            if (!substituteCache.has(plan.substituteFace)) {
                const embedded = await destDoc.embedFont(plan.substituteFace);
                substituteCache.set(plan.substituteFace, embedded);
            }
            const embedded = substituteCache.get(plan.substituteFace);
            fontRef = embedded.ref;
            faceName = plan.substituteFace;
        }

        writeFieldValue(destDoc, target, plan, fontRef, faceName);
        written.push({
            field: plan.name,
            page: target.pageIndex,
            docType: plan.docType,
            fontSource: plan.usedOriginal ? 'original' : 'SUBSTITUTE',
            category: plan.category,
            face: faceName,
            reason: plan.usedOriginal ? 'original' : plan.reason,
            missing: plan.missing,
            explain: plan.explain,
        });
    }

    // Every substitution is reported, on the exact field it happened to. A
    // silent fallback is the failure this whole feature exists to avoid.
    for (const entry of written.filter((w) => w.fontSource === 'SUBSTITUTE')) {
        report.rebuilt.push({
            item: `Substitute font used in "${entry.field}"`,
            detail: `${entry.explain} A ${CATEGORIES[entry.category]?.label ?? entry.category} `
                  + `substitute (${entry.face}) was used instead, so the value is legible, but it `
                  + `will not match the rest of the document exactly.`,
            prominent: true,
        });
    }

    const bytes = await destDoc.save(SAVE_OPTIONS);
    return { bytes, report, written };
}

/* Build the widget's appearance stream and set the field's value. */
function writeFieldValue(destDoc, target, plan, fontRef, faceName) {
    const field = destDoc.context.lookup(target.fieldRef);
    const widget = destDoc.context.lookup(target.widgetRef);
    if (!(field instanceof PDFDict) || !(widget instanceof PDFDict)) return;

    field.set(N.V, PDFHexString.fromText(plan.text));

    const rect = widget.lookupMaybe(N.Rect, PDFArray);
    const numbers = rect ? rect.asArray().map((n) => (n instanceof PDFNumber ? n.asNumber() : 0)) : [0, 0, 0, 0];
    const width = Math.abs(numbers[2] - numbers[0]);
    const height = Math.abs(numbers[3] - numbers[1]);

    // /DA size 0 means auto-size; a value that fills two-thirds of the box is
    // what viewers converge on and keeps descenders inside the frame.
    const size = plan.field.appearance.size > 0
        ? plan.field.appearance.size
        : Math.max(6, Math.min(12, height * 0.66));

    const resourceName = plan.field.fontResourceName || 'F0';
    const encoded = encodeForFont(plan, faceName);
    const padding = 2;
    // Baseline: centre the ascender box, then drop to where the baseline sits.
    const baseline = Math.max(padding, (height - size) / 2 + size * 0.22);

    const operations = [
        '/Tx BMC', 'q', 'BT',
        `/${resourceName} ${round(size)} Tf`,
        plan.field.appearance.colour || '0 g',
        `${round(padding)} ${round(baseline)} Td`,
        `${encoded} Tj`,
        'ET', 'Q', 'EMC',
    ].join('\n');

    const resources = PDFDict.withContext(destDoc.context);
    const fonts = PDFDict.withContext(destDoc.context);
    if (fontRef) fonts.set(PDFName.of(resourceName), fontRef);
    resources.set(N.Font, fonts);

    const bbox = PDFArray.withContext(destDoc.context);
    for (const value of [0, 0, width, height]) bbox.push(PDFNumber.of(value));

    const streamDict = PDFDict.withContext(destDoc.context);
    streamDict.set(N.Type, N.XObject);
    streamDict.set(N.Subtype, N.Form);
    streamDict.set(N.BBox, bbox);
    streamDict.set(N.Resources, resources);
    streamDict.set(PDFName.of('Length'), PDFNumber.of(operations.length));

    const bytes = new Uint8Array(operations.length);
    for (let i = 0; i < operations.length; i += 1) bytes[i] = operations.charCodeAt(i) & 0xff;
    const streamRef = destDoc.context.register(PDFRawStream.of(streamDict, bytes));

    const appearance = PDFDict.withContext(destDoc.context);
    appearance.set(N.N, streamRef);
    widget.set(N.AP, appearance);

    // Deliberately NOT setting /NeedAppearances: it would invite the viewer to
    // throw this stream away and re-render the field with a font of its own.
}

/* Encode the text as a PDF string in the codes the chosen font understands.
 *
 * A substitute is one of the standard 14 with WinAnsi encoding, so the
 * character code is the byte. An original subset font uses its own code
 * assignment, which is exactly what the /ToUnicode inversion produced. */
function encodeForFont(plan, faceName) {
    const useOriginalCodes = plan.usedOriginal && plan.codes instanceof Map;
    let hex = '';
    for (const char of plan.text) {
        let code;
        if (useOriginalCodes) code = plan.codes.get(char);
        else code = char.charCodeAt(0) <= 0xff ? char.charCodeAt(0) : 0x3f;   // '?'
        if (code === undefined) code = 0x3f;
        hex += code > 0xff
            ? code.toString(16).padStart(4, '0')
            : code.toString(16).padStart(2, '0');
    }
    return `<${hex}>`;
}

const round = (value) => Math.round(value * 100) / 100;
