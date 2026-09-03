/* Security Buddy — where the missing glyphs come from.
 * ============================================================================
 *
 * An embedded subset contains only the glyphs the document already used.
 * Measured on the corpus: DejaVuSans arrives with 42 writable characters and
 * three capitals out of twenty-six. So "edit the text" meant "retype it using
 * the forty characters already on this page", and 139 of 156 clickable runs
 * refused any new word. Blocking was right — a silent substitute is the worst
 * possible bug here — but blocking with no way forward is not a tool.
 *
 * The way forward is the one a desktop editor takes: get the real glyphs from a
 * real font file and embed them. The subset in the document cannot supply them
 * (it does not contain the outlines), so the file has to come from elsewhere:
 *
 *   1. a font the user's machine already has, read through the browser's Local
 *      Font Access API — this is what Acrobat does implicitly, and it gives the
 *      SAME face the document names;
 *   2. a font file the user picks;
 *   3. the DejaVu family shipped with this tool.
 *
 * The rule that does not move: a source is used only when its name MATCHES the
 * font the document names. A lookalike embedded under another name is the
 * silent substitution this project refuses, just better hidden. When nothing
 * matches, the operation still stops and says which font it needs.
 */

import { PDFLib } from './pdflib.js';

/* Everything here is loaded on demand. fontkit is 740KB and the faces are
 * hundreds of KB each: a user who never edits text should never pay for them. */
const FONTKIT_URL = '/static/vendor/fontkit/fontkit.umd.min.js';
const FONTS_BASE = '/static/vendor/fonts/';

/* Shipped faces, by the PostScript name a document would use. */
const SHIPPED = new Map([
    ['DejaVuSans', 'DejaVuSans.ttf'],
    ['DejaVuSans-Bold', 'DejaVuSans-Bold.ttf'],
    ['DejaVuSans-Oblique', 'DejaVuSans-Oblique.ttf'],
    ['DejaVuSans-BoldOblique', 'DejaVuSans-BoldOblique.ttf'],
    ['DejaVuSerif', 'DejaVuSerif.ttf'],
    ['DejaVuSerif-Bold', 'DejaVuSerif-Bold.ttf'],
    ['DejaVuSerif-Italic', 'DejaVuSerif-Italic.ttf'],
    ['DejaVuSansMono', 'DejaVuSansMono.ttf'],
    ['DejaVuSansMono-Bold', 'DejaVuSansMono-Bold.ttf'],
]);

const userFonts = new Map();    // normalised name -> { bytes, label, origin }
const localIndex = new Map();   // normalised name -> FontData, once granted
const fileCache = new Map();
let fontkit = null;
let localGranted = false;

/* "BAAAAA+DejaVuSans" and "DejaVu Sans" are the same face wearing different
 * hats: strip the subset tag, the spaces and the case before comparing. */
export function normaliseName(name) {
    return String(name ?? '')
        .replace(/^[A-Z]{6}\+/, '')
        .replace(/[\s_]/g, '')
        .toLowerCase();
}

async function loadFontkit() {
    if (fontkit) return fontkit;
    if (!window.fontkit) {
        await new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = FONTKIT_URL;
            script.onload = resolve;
            script.onerror = () => reject(new Error(
                'The font engine could not be loaded, so glyphs missing from the document '
                + 'cannot be embedded.'));
            document.head.append(script);
        });
    }
    fontkit = window.fontkit;
    return fontkit;
}

async function fetchShipped(file) {
    if (fileCache.has(file)) return fileCache.get(file);
    const response = await fetch(FONTS_BASE + file);
    if (!response.ok) throw new Error(`The font file ${file} could not be read.`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    fileCache.set(file, bytes);
    return bytes;
}

/* ── The user's own fonts ────────────────────────────────────────────────── */

/* Chrome and Edge can hand a page the fonts the machine has installed, with the
 * user's permission. That is the case that makes this work on a real document:
 * a file that names Calibri gets Calibri, not something that looks like it.
 * Firefox and Safari do not implement it, which is why the file picker exists. */
export function canReadLocalFonts() {
    return typeof window.queryLocalFonts === 'function';
}

export async function grantLocalFonts() {
    if (!canReadLocalFonts()) return { granted: false, reason: 'unsupported' };
    try {
        const fonts = await window.queryLocalFonts();
        localIndex.clear();
        for (const font of fonts) localIndex.set(normaliseName(font.postscriptName), font);
        localGranted = true;
        return { granted: true, count: localIndex.size };
    } catch (err) {
        return { granted: false, reason: err?.name === 'SecurityError' ? 'denied' : 'failed' };
    }
}

export function localFontsReady() { return localGranted; }

/* A font file the user picked. Its real name is read from the file rather than
 * from the filename, so "arial.ttf" cannot be passed off as something else. */
export async function addUserFont(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const kit = await loadFontkit();
    let name = file.name.replace(/\.[^.]+$/, '');
    try {
        const parsed = kit.create(bytes);
        name = parsed.postscriptName || parsed.familyName || name;
    } catch {
        throw new Error(`"${file.name}" could not be read as a font file.`);
    }
    userFonts.set(normaliseName(name), { bytes, label: name, origin: 'file' });
    return name;
}

export function userFontNames() {
    return [...userFonts.values()].map((f) => f.label);
}

/* ── Finding a source ────────────────────────────────────────────────────── */

/* The bytes of a font file whose name matches, or null. Order is deliberate:
 * the machine's own copy first, because it is most likely to BE the font the
 * document was made with. */
export async function findSource(fontName) {
    const key = normaliseName(fontName);
    if (!key) return null;

    if (localIndex.has(key)) {
        try {
            const blob = await localIndex.get(key).blob();
            return {
                bytes: new Uint8Array(await blob.arrayBuffer()),
                origin: 'installed', label: fontName,
            };
        } catch { /* permission withdrawn between the grant and now */ }
    }
    if (userFonts.has(key)) {
        const entry = userFonts.get(key);
        return { bytes: entry.bytes, origin: 'file', label: entry.label };
    }
    for (const [name, file] of SHIPPED) {
        if (normaliseName(name) !== key) continue;
        return { bytes: await fetchShipped(file), origin: 'shipped', label: name };
    }
    return null;
}

/* Is a source available at all, without fetching it? Used to decide what the
 * panel offers before the user commits to anything. */
export function hasSource(fontName) {
    const key = normaliseName(fontName);
    if (!key) return null;
    if (localIndex.has(key)) return 'installed';
    if (userFonts.has(key)) return 'file';
    for (const name of SHIPPED.keys()) if (normaliseName(name) === key) return 'shipped';
    return null;
}

/* ── Embedding ───────────────────────────────────────────────────────────── */

const embedded = new WeakMap();   // doc -> Map(normalised name -> PDFFont)

/* Embed a source font into a document, once per document and face.
 *
 * subset:true keeps only the glyphs actually written, so a 740KB face costs a
 * few KB in the output — the same discipline the document's own producer used.
 */
export async function embedSource(doc, fontName, source) {
    if (!embedded.has(doc)) embedded.set(doc, new Map());
    const cache = embedded.get(doc);
    const key = normaliseName(fontName);
    if (cache.has(key)) return cache.get(key);

    const kit = await loadFontkit();
    doc.registerFontkit(kit);
    const font = await doc.embedFont(source.bytes, { subset: true });
    cache.set(key, font);
    return font;
}

export { PDFLib };
