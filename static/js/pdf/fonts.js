/* Security Buddy — font identity, category and glyph availability.
 * ============================================================================
 *
 * Everything here answers two questions about a font already in the document:
 * what KIND of face is it, and can it actually write the characters the user
 * typed. Both answers are drawn from the PDF's own metadata — no font-program
 * parser, no extra dependency.
 *
 * The rules below are not the textbook ones. They were measured against real
 * documents and the textbook signals lost:
 *
 *   * /FontDescriptor /Flags is unreliable. Every embedded font produced by
 *     LibreOffice in the test corpus reports Flags=4 (Symbolic) and nothing
 *     else — including "LiberationSerif", which is a serif face, and
 *     "WenQuanYiZenHei", which is CJK. Classifying by Flags calls both of them
 *     sans. The name is checked first and Flags only corroborates.
 *
 *   * /Widths does not tell you which CHARACTERS a subset can write. Subset
 *     fonts remap codes to a dense 0..N range with a built-in encoding, so
 *     "FirstChar=0 LastChar=42" describes 43 arbitrary slots, not a character
 *     range. The reliable oracle is the /ToUnicode CMap read backwards.
 *
 *   * /ToUnicode alone is not enough either. A Tesseract OCR layer ships a
 *     "GlyphLessFont" whose /ToUnicode claims 55,506 characters and whose font
 *     program is 572 bytes and draws nothing. Glyphless fonts are detected
 *     separately, before any glyph question is asked — see pagetype.js.
 */

import {
    PDFDict, PDFName, PDFArray, PDFNumber, PDFStream, PDFRef, PDFRawStream,
    StandardFonts, decodePDFRawStream,
} from './pdflib.js';

/* ── Categories and their substitutes ────────────────────────────────────── */

/* Substitutes are the PDF standard 14: present in every viewer, so nothing has
 * to be embedded and the output gains no weight.
 *
 * CJK deliberately has no substitute. There is no standard PDF CJK face, and
 * embedding one would add megabytes to every page load for a case that should
 * be rare. When a CJK glyph is missing the operation stops with an explanation
 * rather than quietly writing the wrong script. */
export const CATEGORIES = {
    serif: {
        label: 'serif', regular: StandardFonts.TimesRoman, bold: StandardFonts.TimesRomanBold,
        italic: StandardFonts.TimesRomanItalic, boldItalic: StandardFonts.TimesRomanBoldItalic,
    },
    sans: {
        label: 'sans-serif', regular: StandardFonts.Helvetica, bold: StandardFonts.HelveticaBold,
        italic: StandardFonts.HelveticaOblique, boldItalic: StandardFonts.HelveticaBoldOblique,
    },
    monospace: {
        label: 'monospace', regular: StandardFonts.Courier, bold: StandardFonts.CourierBold,
        italic: StandardFonts.CourierOblique, boldItalic: StandardFonts.CourierBoldOblique,
    },
    symbol: {
        label: 'symbol', regular: StandardFonts.Symbol, bold: StandardFonts.Symbol,
        italic: StandardFonts.Symbol, boldItalic: StandardFonts.Symbol,
    },
    // No substitute by decision: there is no standard PDF CJK face, and
    // embedding one would add megabytes for a rare case.
    cjk: { label: 'CJK', regular: null, bold: null, italic: null, boldItalic: null },
};

/* The categories a user may pick from when correcting an estimate. CJK is
 * absent because there is nothing to switch to. */
export const CHOOSABLE_CATEGORIES = ['sans', 'serif', 'monospace'];

/* Latin faces whose names contain a word that also signals CJK. Checked first,
 * or "Century Gothic" and "Franklin Gothic" would be classified as Japanese. */
const CJK_FALSE_FRIENDS =
    /(century|franklin|news|trade|copperplate|highway|alternate|agency|bank)\s*gothic/i;

/* Name patterns, checked in this order. The order matters more than it looks:
 * "Noto Serif CJK" is CJK, not serif; "DejaVu Sans Mono" is monospace, not
 * sans; "Roboto Slab" is a serif, not the sans that shares its name.
 *
 * This list is deliberately long. Substitution can only ever draw on the 14
 * standard PDF faces — nothing else exists without embedding a font file — so
 * the one thing that genuinely widens coverage on ordinary documents is
 * recognising more of the names those documents actually use, and putting each
 * in the right family. */
const NAME_HINTS = [
    [/(ming|songti|simsun|simhei|nsimsun|fangsong|kaiti|dfkai|mingliu|pmingliu|batang|gungsuh|dotum|gulim|malgun|nanum|meiryo|yugothic|msgothic|msmincho|mincho|hgothic|ipagothic|ipamincho|hiragino|osaka|pingfang|heitisc|heititc|songtisc|wenquanyi|sourcehan|notosanscjk|notoserifcjk|notosanssc|notosanstc|notosansjp|notosanskr|cjk|hanazono|zenhei|ukai|uming|arplu|msyahei|microsoftyahei|microsoftjhenghei|jhenghei|yahei|kozuka|ryumin|gothicbbb|shinseikai)/i, 'cjk'],
    [/(mono|courier|consolas|menlo|monaco|inconsolata|typewriter|hack|firacode|firamono|jetbrains|plexmono|sourcecodepro|robotomono|ubuntumono|andale|lucidaconsole|ptmono|spacemono|cousine|anonymouspro|iosevka|cascadia|terminal|ocra|ocrb|prestige|letergothic|nimbusmono|freemono|dejavusansmono|liberationmono|overpassmono|redhatmono|victormono|hasklig|monoid|sudo|terminus)/i, 'monospace'],
    [/(serif|times|georgia|garamond|baskerville|caslon|palatino|bookantiqua|bookman|cambria|constantia|minion|century(?!gothic)|didot|bodoni|rockwell|slab|merriweather|ptserif|sourceserif|notoserif|liberationserif|dejavuserif|nimbusroman|freeserif|charter|utopia|charis|crimson|spectral|lora|playfair|cormorant|ebgaramond|librebaskerville|tinos|droidserif|zillaslab|vollkorn|alegreya|cardo|gentium|junicode|sitka|sylfaen|newcenturyschlbk|schoolbook|clarendon|egyptienne|scala|sabon|janson|plantin|ehrhardt|bembo|dante|arno|warnock|freight|tiempos|lyon|publico|guardian|miller|chronicle|mercury)/i, 'serif'],
    [/(symbol|dingbat|wingding|webding|marlett|bookshelf)/i, 'symbol'],
    [/(helvetica|arial|calibri|verdana|tahoma|segoe|roboto|lato|opensans|notosans|sourcesans|ptsans|liberationsans|dejavusans|nimbussans|freesans|franklin|futura|gillsans|univers|frutiger|myriad|optima|trebuchet|centurygothic|avantgarde|candara|corbel|aptos|inter|poppins|montserrat|nunito|raleway|ubuntu|firasans|worksans|rubik|karla|manrope|barlow|mulish|oswald|cabin|quicksand|asap|heebo|assistant|arimo|droidsans|microsoftsans|geneva|impact|haettenschweiler|eurostile|antiquesans|akzidenz|neuehaas|interstate|whitney|proximanova|avenir|circular|graphik|plexsans|overpass|redhat|figtree|outfit|sora|epilogue)/i, 'sans'],
];

/* A subset prefix is six uppercase letters and a plus: ABCDEF+Helvetica. */
export function stripSubsetPrefix(name) {
    return /^[A-Z]{6}\+/.test(name) ? name.slice(7) : name;
}

/* ── Font description ────────────────────────────────────────────────────── */

const N = {
    BaseFont: PDFName.of('BaseFont'), Subtype: PDFName.of('Subtype'),
    FontDescriptor: PDFName.of('FontDescriptor'), DescendantFonts: PDFName.of('DescendantFonts'),
    Flags: PDFName.of('Flags'), ToUnicode: PDFName.of('ToUnicode'),
    Encoding: PDFName.of('Encoding'), Differences: PDFName.of('Differences'),
    BaseEncoding: PDFName.of('BaseEncoding'), Widths: PDFName.of('Widths'),
    FirstChar: PDFName.of('FirstChar'), CIDSystemInfo: PDFName.of('CIDSystemInfo'),
    Ordering: PDFName.of('Ordering'), Font: PDFName.of('Font'), Type: PDFName.of('Type'),
};

const FONT_FILE_KEYS = ['FontFile', 'FontFile2', 'FontFile3'].map((k) => PDFName.of(k));

/* A font program smaller than this cannot hold real outlines. Tesseract's
 * glyphless font is 572 bytes; a genuine subset of a handful of glyphs is
 * several kilobytes. */
const MIN_REAL_PROGRAM_BYTES = 2048;

export function describeFont(doc, fontRef) {
    const dict = doc.context.lookup(fontRef);
    if (!(dict instanceof PDFDict)) return null;

    const rawName = String(dict.get(N.BaseFont) ?? '').replace(/^\//, '') || '(unnamed)';
    const name = stripSubsetPrefix(rawName);
    const subtype = String(dict.get(N.Subtype) ?? '').replace(/^\//, '');

    // A Type0 font keeps its descriptor on the descendant CIDFont.
    let descriptor = dict.lookupMaybe(N.FontDescriptor, PDFDict);
    let ordering = null;
    if (!descriptor) {
        const descendants = dict.lookupMaybe(N.DescendantFonts, PDFArray);
        const first = descendants ? doc.context.lookup(descendants.get(0)) : null;
        if (first instanceof PDFDict) {
            descriptor = first.lookupMaybe(N.FontDescriptor, PDFDict);
            const info = first.lookupMaybe(N.CIDSystemInfo, PDFDict);
            const value = info?.get(N.Ordering);
            if (value) ordering = String(value.decodeText?.() ?? value).replace(/[()]/g, '');
        }
    }

    let programBytes = 0;
    if (descriptor) {
        for (const key of FONT_FILE_KEYS) {
            const program = descriptor.lookup(key);
            if (program instanceof PDFStream) {
                programBytes = program.contents?.length ?? 0;
                break;
            }
        }
    }

    const flags = descriptor?.lookupMaybe(N.Flags, PDFNumber)?.asNumber() ?? 0;
    const embedded = programBytes > 0;
    const standard14 = !embedded && isStandard14(name);

    return {
        rawName, name, subtype, flags, embedded, programBytes, standard14, ordering,
        subset: rawName !== name,
        fixedPitch: (flags & 1) === 1,
        serifFlag: (flags & 2) === 2,
        bold: /bold|black|heavy|semibold/i.test(name) || (flags & (1 << 18)) !== 0,
        italic: /italic|oblique/i.test(name),
        // A font that is neither embedded nor one of the standard 14 is a bare
        // name: the viewer picks something, and so must we.
        unresolvable: !embedded && !standard14,
        glyphless: embedded && programBytes < MIN_REAL_PROGRAM_BYTES,
        category: categoriseFont(name, flags, ordering, dict, doc),
        dict,
        ref: fontRef instanceof PDFRef ? fontRef : null,
    };
}

const STANDARD_14 = new Set([
    'Helvetica', 'Helvetica-Bold', 'Helvetica-Oblique', 'Helvetica-BoldOblique',
    'Times-Roman', 'Times-Bold', 'Times-Italic', 'Times-BoldItalic',
    'Courier', 'Courier-Bold', 'Courier-Oblique', 'Courier-BoldOblique',
    'Symbol', 'ZapfDingbats', 'Arial', 'Arial-Bold', 'ArialMT', 'Arial-BoldMT',
    'TimesNewRoman', 'TimesNewRomanPSMT', 'CourierNew', 'CourierNewPSMT',
]);

function isStandard14(name) { return STANDARD_14.has(name); }

/* The cascade, in the order that survived measurement: name, then structural
 * signals, then flags. */
function categoriseFont(name, flags, ordering, dict, doc) {
    // 1. CJK — the CID ordering is authoritative when present.
    if (ordering && /^(GB1|CNS1|Japan1|Korea1|KR)$/i.test(ordering)) return 'cjk';

    const compact = name.replace(/[\s\-_,]/g, '');
    const isFalseFriend = CJK_FALSE_FRIENDS.test(name);
    for (const [pattern, category] of NAME_HINTS) {
        if (category === 'cjk' && isFalseFriend) continue;
        if (pattern.test(compact)) return category;
    }

    // 2. Monospace — every advance width identical is a strong, name-free signal.
    if ((flags & 1) === 1) return 'monospace';
    const widths = dict.lookupMaybe(N.Widths, PDFArray);
    if (widths && widths.size() > 4) {
        const values = widths.asArray()
            .map((w) => (w instanceof PDFNumber ? w.asNumber() : null))
            .filter((w) => w !== null && w > 0);
        if (values.length > 4 && values.every((w) => w === values[0])) return 'monospace';
    }

    // 3. Serif flag, as corroboration only — see the header note on why it
    //    cannot be trusted on its own.
    if ((flags & 2) === 2) return 'serif';

    // 4. Default. A face with no signal is far more often sans than serif.
    return 'sans';
}

/* ── Which characters can this font write? ───────────────────────────────── */

/* Two entirely different mechanisms, and conflating them is how a subset gets
 * written with a character it does not contain:
 *
 *   embedded subset  -> the /ToUnicode CMap, read backwards
 *   standard 14      -> the encoding table (WinAnsi plus /Differences)
 */
export function buildWritableMap(doc, font) {
    if (!font) return { map: new Map(), source: 'none' };

    const toUnicode = font.dict.lookup(N.ToUnicode);
    if (toUnicode instanceof PDFStream) {
        const map = invertToUnicode(decodeStream(toUnicode));
        if (map.size) return { map, source: 'ToUnicode' };
    }

    const map = encodingMap(doc, font);
    return { map, source: map.size ? 'encoding' : 'none' };
}

function decodeStream(stream) {
    try {
        // pdf-lib holds streams raw and still encoded; a /ToUnicode CMap is
        // almost always Flate-compressed, so it has to be decoded to be read.
        const bytes = stream instanceof PDFRawStream
            ? decodePDFRawStream(stream).decode()
            : stream.getContents();
        return new TextDecoder('latin1').decode(bytes);
    } catch {
        return '';
    }
}

/* Read a /ToUnicode CMap forwards: code -> the character it draws.
 *
 * The inverse of buildWritableMap. Needed to show a user the text that is
 * ALREADY on the page: a subset font's codes are arbitrary slot numbers, so
 * without this the existing text reads as control characters. */
export function buildReadableMap(doc, font) {
    if (!font) return new Map();

    const toUnicode = font.dict.lookup(N.ToUnicode);
    if (toUnicode instanceof PDFStream) {
        const forward = parseToUnicodeForward(decodeStream(toUnicode));
        if (forward.size) return forward;
    }

    // No /ToUnicode: the encoding table read the other way round.
    const map = new Map();
    for (const [char, code] of encodingMap(doc, font)) {
        if (!map.has(code)) map.set(code, char);
    }
    return map;
}

function parseToUnicodeForward(text) {
    const map = new Map();
    const fromHex = (hex) => {
        let out = '';
        for (let i = 0; i + 3 < hex.length; i += 4) out += String.fromCharCode(parseInt(hex.slice(i, i + 4), 16));
        return out || String.fromCharCode(parseInt(hex, 16));
    };
    for (const block of text.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
        for (const [, src, dst] of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) {
            map.set(parseInt(src, 16), fromHex(dst));
        }
    }
    for (const block of text.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
        for (const [, lo, hi, dst] of
             block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) {
            const start = parseInt(lo, 16);
            const end = parseInt(hi, 16);
            const base = parseInt(dst.slice(-4), 16);
            for (let i = 0; i <= Math.min(end - start, 65535); i += 1) {
                map.set(start + i, String.fromCharCode(base + i));
            }
        }
    }
    return map;
}

/* Advance widths by character code, for judging whether a replacement will
 * still fit the space the original occupied. */
export function widthMap(doc, font) {
    const widths = new Map();
    if (!font) return widths;
    const first = font.dict.lookupMaybe(N.FirstChar, PDFNumber)?.asNumber();
    const array = font.dict.lookupMaybe(N.Widths, PDFArray);
    if (first !== undefined && array) {
        array.asArray().forEach((value, index) => {
            if (value instanceof PDFNumber) widths.set(first + index, value.asNumber());
        });
    }
    return widths;
}

/* Read a /ToUnicode CMap backwards: character -> the code that draws it. */
function invertToUnicode(text) {
    const map = new Map();
    const put = (char, code) => { if (char && !map.has(char)) map.set(char, code); };
    const fromHex = (hex) => {
        let out = '';
        for (let i = 0; i + 3 < hex.length; i += 4) out += String.fromCharCode(parseInt(hex.slice(i, i + 4), 16));
        return out || String.fromCharCode(parseInt(hex, 16));
    };

    for (const block of text.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
        for (const [, src, dst] of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) {
            put(fromHex(dst), parseInt(src, 16));
        }
    }
    for (const block of text.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
        for (const [, lo, hi, dst] of
             block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) {
            const start = parseInt(lo, 16);
            const end = parseInt(hi, 16);
            const base = parseInt(dst.slice(-4), 16);
            // A runaway range would hang the tab on a malformed file.
            for (let i = 0; i <= Math.min(end - start, 65535); i += 1) {
                put(String.fromCharCode(base + i), start + i);
            }
        }
    }
    return map;
}

/* WinAnsiEncoding is cp1252. The 0x80-0x9F block is the part that differs from
 * Latin-1, so only it needs a table. */
const CP1252_HIGH = '€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ';

/* Glyph names that appear in real /Differences arrays. Not the full Adobe Glyph
 * List — the entries a WinAnsi or MacRoman document actually uses. */
const GLYPH_NAMES = {
    space: ' ', exclam: '!', quotedbl: '"', numbersign: '#', dollar: '$', percent: '%',
    ampersand: '&', quotesingle: "'", parenleft: '(', parenright: ')', asterisk: '*',
    plus: '+', comma: ',', hyphen: '-', period: '.', slash: '/', zero: '0', one: '1',
    two: '2', three: '3', four: '4', five: '5', six: '6', seven: '7', eight: '8',
    nine: '9', colon: ':', semicolon: ';', less: '<', equal: '=', greater: '>',
    question: '?', at: '@', bracketleft: '[', backslash: '\\', bracketright: ']',
    asciicircum: '^', underscore: '_', grave: '`', braceleft: '{', bar: '|',
    braceright: '}', asciitilde: '~', bullet: '•', dagger: '†', daggerdbl: '‡',
    ellipsis: '…', emdash: '—', endash: '–', florin: 'ƒ', fraction: '⁄',
    guilsinglleft: '‹', guilsinglright: '›', minus: '−', perthousand: '‰',
    quotedblbase: '„', quotedblleft: '“', quotedblright: '”', quoteleft: '‘',
    quoteright: '’', quotesinglbase: '‚', trademark: '™', fi: 'ﬁ', fl: 'ﬂ',
    Lslash: 'Ł', OE: 'Œ', Scaron: 'Š', Ydieresis: 'Ÿ', Zcaron: 'Ž', dotlessi: 'ı',
    lslash: 'ł', oe: 'œ', scaron: 'š', zcaron: 'ž', Euro: '€', currency: '¤',
    brokenbar: '¦', dieresis: '¨', copyright: '©', ordfeminine: 'ª',
    logicalnot: '¬', registered: '®', macron: '¯', degree: '°', plusminus: '±',
    twosuperior: '²', threesuperior: '³', acute: '´', mu: 'µ', periodcentered: '·',
    cedilla: '¸', onesuperior: '¹', ordmasculine: 'º', onequarter: '¼',
    onehalf: '½', threequarters: '¾', multiply: '×', divide: '÷', germandbls: 'ß',
    breve: '˘', caron: 'ˇ', circumflex: 'ˆ', dotaccent: '˙', hungarumlaut: '˝',
    ogonek: '˛', ring: '˚', tilde: '˜', exclamdown: '¡', questiondown: '¿',
    sterling: '£', yen: '¥', section: '§', paragraph: '¶', AE: 'Æ', ae: 'æ',
    Oslash: 'Ø', oslash: 'ø', Thorn: 'Þ', thorn: 'þ', Eth: 'Ð', eth: 'ð',
};

/* Accented Latin letters follow a regular naming scheme (Agrave, ccedilla…),
 * so they are generated rather than listed. */
const ACCENTS = {
    grave: { A: 'À', E: 'È', I: 'Ì', O: 'Ò', U: 'Ù', a: 'à', e: 'è', i: 'ì', o: 'ò', u: 'ù' },
    acute: { A: 'Á', E: 'É', I: 'Í', O: 'Ó', U: 'Ú', Y: 'Ý', a: 'á', e: 'é', i: 'í', o: 'ó', u: 'ú', y: 'ý' },
    circumflex: { A: 'Â', E: 'Ê', I: 'Î', O: 'Ô', U: 'Û', a: 'â', e: 'ê', i: 'î', o: 'ô', u: 'û' },
    tilde: { A: 'Ã', N: 'Ñ', O: 'Õ', a: 'ã', n: 'ñ', o: 'õ' },
    dieresis: { A: 'Ä', E: 'Ë', I: 'Ï', O: 'Ö', U: 'Ü', a: 'ä', e: 'ë', i: 'ï', o: 'ö', u: 'ü', y: 'ÿ' },
    ring: { A: 'Å', a: 'å' },
    cedilla: { C: 'Ç', c: 'ç' },
};

function glyphNameToChar(name) {
    if (GLYPH_NAMES[name]) return GLYPH_NAMES[name];
    if (/^[A-Za-z]$/.test(name)) return name;
    const accent = Object.keys(ACCENTS).find((a) => name.endsWith(a) && name.length > a.length);
    if (accent) {
        const letter = name.slice(0, name.length - accent.length);
        if (ACCENTS[accent][letter]) return ACCENTS[accent][letter];
    }
    const uni = /^uni([0-9A-Fa-f]{4})$/.exec(name);
    if (uni) return String.fromCharCode(parseInt(uni[1], 16));
    return null;
}

function encodingMap(doc, font) {
    const map = new Map();
    const encoding = font.dict.lookup(N.Encoding);
    const baseName = encoding instanceof PDFDict
        ? String(encoding.get(N.BaseEncoding) ?? '/WinAnsiEncoding')
        : String(encoding ?? '/StandardEncoding');

    // Base table. WinAnsi and Standard agree over ASCII, which is what matters
    // most; above it WinAnsi is the common case in practice.
    for (let code = 32; code < 127; code += 1) map.set(String.fromCharCode(code), code);
    if (/WinAnsi/.test(baseName)) {
        for (let i = 0; i < CP1252_HIGH.length; i += 1) {
            const char = CP1252_HIGH[i];
            if (char && char.charCodeAt(0) > 0x9f) map.set(char, 0x80 + i);
        }
        for (let code = 0xa0; code <= 0xff; code += 1) map.set(String.fromCharCode(code), code);
    }

    // /Differences overrides specific codes and is the authority where present.
    if (encoding instanceof PDFDict) {
        const differences = encoding.lookupMaybe(N.Differences, PDFArray);
        if (differences) {
            let code = 0;
            for (const item of differences.asArray()) {
                if (item instanceof PDFNumber) { code = item.asNumber(); continue; }
                const glyph = String(item).replace(/^\//, '');
                const char = glyphNameToChar(glyph);
                if (char) map.set(char, code);
                code += 1;
            }
        }
    }
    return map;
}

/* ── The decision ────────────────────────────────────────────────────────── */

/* Can this font write this text, and if not, what replaces it?
 *
 * Returns { usable, font, category, missing, reason, substituted }. `missing`
 * lists the exact characters that failed, because "some characters are missing"
 * is not something a user can act on. */
export function planText(doc, font, text) {
    const category = font?.category ?? 'sans';

    if (!font) {
        return { usable: false, substituted: true, category, missing: [],
                 reason: 'no-font-declared',
                 explain: 'No font is declared for this field, so one had to be chosen.' };
    }

    if (font.glyphless) {
        return { usable: false, substituted: true, category, missing: [],
                 reason: 'glyphless-font',
                 explain: `"${font.name}" carries no glyph outlines — it is the invisible text `
                        + `layer an OCR scan puts over the page image. Writing with it would `
                        + `produce text nobody can see.` };
    }

    if (font.unresolvable) {
        return { usable: false, substituted: true, category, missing: [],
                 reason: 'font-not-embedded',
                 explain: `"${font.name}" is neither embedded in this document nor one of the `
                        + `standard PDF fonts, so its outlines are not available here.` };
    }

    const { map } = buildWritableMap(doc, font);
    const missing = [...new Set([...text])].filter((char) => char !== '\n' && !map.has(char));

    if (!missing.length) {
        return { usable: true, substituted: false, category, missing: [],
                 reason: 'original', font, codes: map };
    }

    return { usable: false, substituted: true, category, missing,
             reason: 'glyph-missing', codes: map,
             explain: font.subset
                 ? `"${font.name}" is embedded as a subset — it contains only the glyphs the `
                 + `document already used, and ${missing.length === 1 ? 'this character is' : 'these characters are'} not among them: `
                 + `${missing.map((c) => JSON.stringify(c)).join(', ')}.`
                 : `"${font.name}" has no glyph for `
                 + `${missing.map((c) => JSON.stringify(c)).join(', ')}.` };
}

/* Pick the substitute face for a category, honouring weight and slant.
 * Returns null for CJK, which by decision has no substitute. */
export function substituteFor(category, { bold = false, italic = false } = {}) {
    const entry = CATEGORIES[category] ?? CATEGORIES.sans;
    if (!entry.regular) return null;
    if (bold && italic) return entry.boldItalic;
    if (bold) return entry.bold;
    if (italic) return entry.italic;
    return entry.regular;
}

export const __testing = { invertToUnicode, glyphNameToChar, categoriseFont, encodingMap };
