/* Security Buddy — pdf-lib adapter.
 *
 * pdf-lib 1.17.1 ships a UMD bundle that installs a `PDFLib` global. Everything
 * else in this feature is a plain ES module, so this file is the single seam
 * between the two: import from here, never touch `window.PDFLib` directly.
 *
 * Keeping it in one place means the pinned-version story stays honest — there is
 * exactly one line to change if the bundle ever moves.
 */

if (typeof window === 'undefined' || !window.PDFLib) {
    throw new Error(
        'pdf-lib was not loaded. static/vendor/pdf-lib/pdf-lib.min.js must be ' +
        'included with a classic <script> tag before any module that imports it.'
    );
}

export const PDFLib = window.PDFLib;

export const {
    PDFDocument,
    PDFContext,
    PDFDict,
    PDFArray,
    PDFName,
    PDFRef,
    PDFNumber,
    PDFString,
    PDFHexString,
    PDFBool,
    PDFNull,
    PDFStream,
    PDFRawStream,
    PDFPageLeaf,
    EncryptedPDFError,
    degrees,
    StandardFonts,
    decodePDFRawStream,
} = window.PDFLib;

/* Save options used for every document this feature writes.
 *
 * updateFieldAppearances:false is not a preference, it is a correctness
 * requirement. Left at its default (true), pdf-lib regenerates the appearance
 * stream of every form field using its own fonts and layout, which silently
 * changes how a filled form renders. Block 1 never writes text, so there is
 * nothing legitimate for it to regenerate.
 *
 * useObjectStreams:false costs some output size but keeps the file structure
 * inspectable with ordinary tools, which matters while tools/pdf_compare.py is
 * the thing standing between us and a silent regression.
 */
export const SAVE_OPTIONS = Object.freeze({
    updateFieldAppearances: false,
    useObjectStreams: false,
});

/* Load options. updateMetadata:false stops pdf-lib from stamping ModDate and
 * Producer onto the document at load time — we carry the originals across
 * ourselves in preserve.js, and cannot do that if they are overwritten first.
 *
 * ignoreEncryption is deliberately absent (i.e. false). It does NOT decrypt;
 * it only skips the check, leaving strings and streams encrypted and producing
 * a corrupt output file that still opens. That is the silent-corruption failure
 * mode this feature exists to avoid.
 */
export const LOAD_OPTIONS = Object.freeze({
    updateMetadata: false,
    throwOnInvalidObject: false,
});
