/* Security Buddy — PDF fidelity core.
 * ============================================================================
 *
 * WHAT THIS FILE IS FOR
 *
 * pdf-lib's `copyPages()` is lossless for the *page*: content streams, embedded
 * font programs, images and XObjects come across byte-for-byte. Nothing is
 * rasterised and nothing is redrawn. That is verified, not assumed — see
 * tools/pdf_compare.py.
 *
 * But `copyPages()` copies pages, not documents. Everything that lives in the
 * document catalog stays behind, and pdf-lib does not warn about it. A merge
 * built from `copyPages` alone quietly loses the outline, the AcroForm, the
 * metadata, the attachments, the named destinations, the page labels and the
 * optional-content configuration. The output opens fine and looks right, which
 * is exactly what makes it dangerous.
 *
 * This module carries that material across, and — where it genuinely cannot —
 * says so out loud in a structured report instead of dropping it in silence.
 *
 * ----------------------------------------------------------------------------
 * THE CENTRAL PROBLEM: DOUBLE-COPYING
 *
 * The naive fix ("deep-copy the catalog entries too") is worse than doing
 * nothing. Objects reachable from a page have ALREADY been copied by
 * `copyPages`, under new object numbers. Deep-copying `/AcroForm` on top of
 * that produces a second, parallel set of field objects: the page shows widget
 * A while the form dictionary points at widget B. The fields render and are
 * dead to the touch. The same trap swallows optional-content groups — the OCGs
 * in `/OCProperties` stop being the OCGs the content stream references, and
 * layers silently detach.
 *
 * So before copying anything, `buildCorrespondence()` walks the source page
 * graph and the destination page graph in lockstep and records, for every
 * object copyPages already brought over, which source ref became which
 * destination ref. Every later copy consults that map first. Nothing that
 * copyPages already copied is ever copied twice.
 *
 * ----------------------------------------------------------------------------
 * THE SECOND PROBLEM: DANGLING PAGE REFERENCES
 *
 * When only some pages are kept (split, extract, reorder), catalog structures
 * may still point at pages that did not come along. Deep-copying such a
 * reference would drag the excluded page into the output as an orphan object —
 * a page that is in the file but not in the page tree. `copyObject()` therefore
 * knows the full set of source page refs and refuses to follow one that is not
 * in the correspondence map, reporting it as dangling so the caller can prune
 * the structure that held it.
 *
 * ----------------------------------------------------------------------------
 * WHAT THIS MODULE DELIBERATELY DOES NOT DO
 *
 * It does not decrypt. It does not rasterise. It does not rebuild pages. It
 * does not touch a single byte of any content stream. If an operation cannot be
 * done while preserving the document, this module's job is to make that
 * visible, not to approximate it.
 */

import {
    PDFDict, PDFArray, PDFName, PDFRef, PDFNumber, PDFString, PDFHexString,
    PDFStream, PDFRawStream, PDFPageLeaf, PDFDocument, EncryptedPDFError,
    LOAD_OPTIONS,
} from './pdflib.js';

/* ── Name constants ──────────────────────────────────────────────────────── */

const N = {
    AcroForm: PDFName.of('AcroForm'),
    Annots: PDFName.of('Annots'),
    Count: PDFName.of('Count'),
    Dest: PDFName.of('Dest'),
    Dests: PDFName.of('Dests'),
    EmbeddedFiles: PDFName.of('EmbeddedFiles'),
    Fields: PDFName.of('Fields'),
    First: PDFName.of('First'),
    Info: PDFName.of('Info'),
    Kids: PDFName.of('Kids'),
    Lang: PDFName.of('Lang'),
    Last: PDFName.of('Last'),
    Limits: PDFName.of('Limits'),
    MarkInfo: PDFName.of('MarkInfo'),
    Metadata: PDFName.of('Metadata'),
    Names: PDFName.of('Names'),
    Next: PDFName.of('Next'),
    Nums: PDFName.of('Nums'),
    OCProperties: PDFName.of('OCProperties'),
    OpenAction: PDFName.of('OpenAction'),
    Outlines: PDFName.of('Outlines'),
    P: PDFName.of('P'),
    PageLabels: PDFName.of('PageLabels'),
    PageLayout: PDFName.of('PageLayout'),
    PageMode: PDFName.of('PageMode'),
    Parent: PDFName.of('Parent'),
    Perms: PDFName.of('Perms'),
    Prev: PDFName.of('Prev'),
    S: PDFName.of('S'),
    SigFlags: PDFName.of('SigFlags'),
    St: PDFName.of('St'),
    StructTreeRoot: PDFName.of('StructTreeRoot'),
    Subtype: PDFName.of('Subtype'),
    Title: PDFName.of('Title'),
    Type: PDFName.of('Type'),
    ViewerPreferences: PDFName.of('ViewerPreferences'),
    Widget: PDFName.of('Widget'),
    XFA: PDFName.of('XFA'),
    A: PDFName.of('A'),
    AA: PDFName.of('AA'),
    D: PDFName.of('D'),
    JavaScript: PDFName.of('JavaScript'),
    FT: PDFName.of('FT'),
    T: PDFName.of('T'),
};

/* ── Report ──────────────────────────────────────────────────────────────── */

/* Every operation returns one of these. `dropped` is the important field: it is
 * the explicit list the user asked for instead of silent loss. The UI must
 * render it — a report nobody reads is the same as no report.
 */
export function createReport() {
    return {
        preserved: [],  // carried across unchanged
        rebuilt: [],    // carried across, but restructured (and why)
        dropped: [],    // could NOT be carried across (and why)
        blocked: [],    // the operation must not run at all
        confirm: [],    // the user must be told BEFORE the operation runs
    };
}

/* `prominent` marks an entry the UI must surface on its own rather than leaving
 * inside a collapsed report — used where the output differs from the input in a
 * way the user would otherwise only discover later. */
const push = (list, item, detail, opts) =>
    list.push({ item, detail, prominent: !!(opts && opts.prominent) });

/* ── Loading ─────────────────────────────────────────────────────────────── */

/* Encrypted files are refused, not worked around.
 *
 * pdf-lib has no decryptor at all. Its `ignoreEncryption:true` option does not
 * decrypt — it suppresses the error and hands back a document whose strings and
 * streams are still ciphertext, which then gets written out as a corrupt file
 * that opens to garbage. Password removal is therefore not a feature of this
 * tool, and this is the point where that is enforced.
 */
export async function loadDocument(bytes, label) {
    let doc;
    try {
        doc = await PDFDocument.load(bytes, LOAD_OPTIONS);
    } catch (err) {
        if (isEncryptedError(err, bytes)) return encryptedResult(label);
        return {
            ok: false,
            label,
            reason: 'parse',
            message:
                'This file could not be read as a PDF. It may be corrupt, ' +
                'truncated, or not a PDF at all. Details: ' + (err?.message || String(err)),
        };
    }

    // Belt and braces: if a build of pdf-lib ever loads an encrypted document
    // instead of throwing, the output would be silently corrupt. Refuse here too.
    if (doc.context.trailerInfo?.Encrypt) return encryptedResult(label);

    return { ok: true, doc, label };
}

function encryptedResult(label) {
    return {
        ok: false,
        label,
        reason: 'encrypted',
        message:
            'This PDF is encrypted. Security Buddy does not open encrypted ' +
            'PDFs and does not remove PDF passwords or permissions — stripping ' +
            'a document\'s protection is not something a security tool should ' +
            'offer. Remove the protection in the application that applied it, ' +
            'then open the file here.',
    };
}

/* Deciding whether a load failure was "encrypted" or "corrupt".
 *
 * `instanceof EncryptedPDFError` does not work: pdf-lib's minified UMD bundle
 * loses the prototype chain of its custom errors, so what arrives is a plain
 * Error whose .name is "Error". Relying on either check meant every
 * password-protected PDF was reported to the user as a corrupt file — the exact
 * confusing message this was written to avoid.
 *
 * So: try the class, then the name, then pdf-lib's own wording, then look for
 * an /Encrypt entry in the bytes. The last one is a heuristic, but it is only
 * consulted once the load has ALREADY failed, where "encrypted" is a far more
 * likely explanation than "corrupt" and is the more useful thing to say.
 */
function isEncryptedError(err, bytes) {
    if (err instanceof EncryptedPDFError) return true;
    if (err?.name === 'EncryptedPDFError') return true;
    if (/\bis encrypted\b/i.test(String(err?.message ?? ''))) return true;
    return hasEncryptEntry(bytes);
}

function hasEncryptEntry(bytes) {
    if (!bytes || typeof bytes.length !== 'number') return false;
    // The trailer lives at the end of the file; scan a generous tail of it.
    const tail = bytes.subarray ? bytes.subarray(Math.max(0, bytes.length - 8192))
        : bytes.slice(Math.max(0, bytes.length - 8192));
    let text = '';
    for (let i = 0; i < tail.length; i += 1) text += String.fromCharCode(tail[i]);
    return text.includes('/Encrypt');
}

/* ── Inspection ──────────────────────────────────────────────────────────── */

/* What is in this document that a structural operation has to worry about?
 * Called before any work starts so the UI can warn (or refuse) up front rather
 * than after the user has already downloaded something. */
export function inspectDocument(doc) {
    const cat = doc.catalog;
    const acro = cat.lookupMaybe(N.AcroForm, PDFDict);
    const names = cat.lookupMaybe(N.Names, PDFDict);

    const signatureFields = acro ? countSignatureFields(doc, acro) : 0;
    const sigFlags = acro?.lookupMaybe(N.SigFlags, PDFNumber)?.asNumber() ?? 0;

    return {
        pageCount: doc.getPageCount(),
        hasOutlines: !!cat.get(N.Outlines),
        hasAcroForm: !!acro,
        hasXFA: !!acro?.get(N.XFA),
        signatureFields,
        // Bit 1 of /SigFlags means the document contains at least one signature.
        isSigned: signatureFields > 0 || (sigFlags & 1) === 1,
        hasStructTree: !!cat.get(N.StructTreeRoot),
        hasOCProperties: !!cat.get(N.OCProperties),
        hasXmp: !!cat.get(N.Metadata),
        hasEmbeddedFiles: !!names?.get(N.EmbeddedFiles),
        hasNamedDests: !!(names?.get(N.Dests) || cat.get(N.Dests)),
        hasPageLabels: !!cat.get(N.PageLabels),
        hasJavaScript: !!names?.get(N.JavaScript),
        hasOpenAction: !!cat.get(N.OpenAction),
        javaScript: findJavaScript(doc),
    };
}

/* Where executable JavaScript hides in a PDF.
 *
 * Three places, and a document can use any of them:
 *   - the /Names /JavaScript name tree, which runs on open;
 *   - an /OpenAction whose action is /S /JavaScript, which also runs on open;
 *   - /AA, the additional-actions dictionary, on the catalog (document events
 *     such as will-close and will-print) or on a page (open/close).
 *
 * Reported before an operation runs, not afterwards: a user handed a PDF that
 * executes code on open should hear about it while deciding what to do with the
 * file, not in a summary after they have already downloaded the result. */
function findJavaScript(doc) {
    const cat = doc.catalog;
    const found = [];

    const names = cat.lookupMaybe(N.Names, PDFDict);
    if (names?.get(N.JavaScript)) found.push('a document-level JavaScript name tree (runs on open)');

    const openAction = cat.lookup(N.OpenAction);
    if (openAction instanceof PDFDict && openAction.get(N.S) === PDFName.of('JavaScript')) {
        found.push('an /OpenAction that executes JavaScript when the file is opened');
    }

    if (cat.get(N.AA)) found.push('document-level additional actions (/AA)');

    let pagesWithActions = 0;
    for (const page of doc.getPages()) {
        if (page.node.get(N.AA)) pagesWithActions += 1;
    }
    if (pagesWithActions) {
        found.push(`page-level additional actions (/AA) on ${pagesWithActions} page(s)`);
    }

    return found;
}

function countSignatureFields(doc, acroForm) {
    const fields = acroForm.lookupMaybe(N.Fields, PDFArray);
    if (!fields) return 0;
    let count = 0;
    const seen = new Set();
    const visit = (ref) => {
        const tag = ref instanceof PDFRef ? ref.tag : null;
        if (tag) {
            if (seen.has(tag)) return;
            seen.add(tag);
        }
        const dict = doc.context.lookup(ref);
        if (!(dict instanceof PDFDict)) return;
        if (dict.get(N.FT) === PDFName.of('Sig')) count += 1;
        const kids = dict.lookupMaybe(N.Kids, PDFArray);
        if (kids) kids.asArray().forEach(visit);
    };
    fields.asArray().forEach(visit);
    return count;
}

/* Turn an inspection into human-readable warnings and blockers.
 *
 * The distinction matters: a `blocked` entry stops the operation, a `dropped`
 * entry lets it proceed but must be shown to the user afterwards. */
export function assessOperation(inspection, report, label) {
    const where = label ? `${label}: ` : '';

    if (inspection.hasXFA) {
        push(report.blocked, 'XFA form',
            `${where}this is a dynamic XFA form. Its layout lives in an XML stream ` +
            `that is bound to this exact document; any structural change ` +
            `invalidates it and the file stops rendering in Acrobat. This tool ` +
            `will not modify XFA documents.`);
    }

    if (inspection.isSigned) {
        push(report.blocked, 'Digital signature',
            `${where}this document carries ${inspection.signatureFields} digital ` +
            `signature field(s). A signature covers the bytes of the file, so ANY ` +
            `modification — including a lossless one — invalidates it. Rather than ` +
            `hand back a document with a broken signature, this tool refuses to ` +
            `modify signed files.`);
    }

    if (inspection.javaScript.length) {
        push(report.confirm, 'This PDF contains executable JavaScript',
            `${where}this PDF contains ${inspection.javaScript.join(', ')}. ` +
            `A PDF that runs code when it is opened is worth knowing about ` +
            `regardless of what you do with it here — it is a common delivery ` +
            `mechanism for malicious documents, though plenty of legitimate ` +
            `forms use it too. This tool does not carry that code into the ` +
            `output. Continue only if you know where the file came from and ` +
            `trust it; the pages themselves are copied unchanged either way.`);
    }

    if (inspection.hasStructTree) {
        push(report.dropped, 'Tagged PDF structure (/StructTreeRoot)',
            `${where}the logical structure tree cannot be carried across by ` +
            `pdf-lib. It is cross-linked with marked-content identifiers inside ` +
            `the content streams, and pdf-lib does not remap them. The output ` +
            `will render identically but will lose its accessibility tagging: ` +
            `screen readers fall back to raw reading order. This is a hard ` +
            `limitation of the library, not a shortcut taken here.`);
    }

    return report;
}

/* ── Correspondence map ──────────────────────────────────────────────────── */

/* Walk the source and destination page graphs in lockstep, recording which
 * source ref became which destination ref.
 *
 * This works because pdf-lib's copier is a faithful structural deep copy: the
 * destination graph has the same shape as the source graph, only with different
 * object numbers. Where that assumption fails (a shape mismatch), we stop
 * descending that subtree and record a warning rather than guessing — a wrong
 * mapping is far worse than a missing one, because a missing one only causes a
 * duplicate object while a wrong one silently rewires the document.
 */
export function buildCorrespondence(srcDoc, destDoc, pagePairs, srcPageTags) {
    const map = new Map();       // source ref tag -> destination PDFRef
    const divergences = [];
    const strays = new Map();    // stray destination tag -> the correct destination PDFRef
    const seenPairs = new Set();
    const queue = [];

    // Page mappings are authoritative: these are the pages that were actually
    // added to the destination page tree. Anything the walk turns up that
    // contradicts them is a duplicate, not a correction.
    const pinned = new Set();
    for (const [srcRef, destRef] of pagePairs) {
        map.set(srcRef.tag, destRef);
        pinned.add(srcRef.tag);
        queue.push([srcRef, destRef]);
    }

    const enqueue = (s, d) => {
        if (!(s instanceof PDFRef) || !(d instanceof PDFRef)) return;
        const existing = map.get(s.tag);
        if (existing && existing.tag !== d.tag) {
            if (pinned.has(s.tag)) {
                /* pdf-lib duplicated a page.
                 *
                 * `copyPages` hands the dereferenced page object to its copier, so
                 * the page's own ref never enters the copier's cache. When a widget
                 * annotation on that page carries a /P back-pointer to it, the
                 * copier resolves that ref and copies the whole page a SECOND time
                 * — producing an orphan page object that is in the file but not in
                 * the page tree, dragging a duplicate of the page's annotations
                 * along with it.
                 *
                 * Observed on any document with form fields: a two-page extract
                 * came out with four /Type /Page objects. The real page is the
                 * pinned one; the other is swept up by repairStrayPageCopies().
                 */
                strays.set(d.tag, existing);
                return;
            }
            // A non-page object mapped two ways means the source and destination
            // graphs genuinely disagree in shape. A wrong mapping silently rewires
            // the document, so refuse it and report instead of guessing.
            divergences.push(`source ${s.tag} maps to both ${existing.tag} and ${d.tag}`);
            return;
        }
        if (!existing && srcPageTags && srcPageTags.has(s.tag) && !pinned.has(s.tag)) {
            /* A copy of a page that was NOT selected.
             *
             * pdf-lib's copier reached it by walking out of a selected page —
             * through a widget's /Parent, across the field tree, into a sibling
             * widget's /P. Mapping it would make it look "kept" to every later
             * check, which is precisely how an unselected page ends up in the
             * output. Do not map it and do not descend into it; leave it
             * unreferenced for garbageCollect() to sweep. */
            return;
        }
        map.set(s.tag, d);
        queue.push([s, d]);
    };

    const walk = (sObj, dObj, isPageLeaf) => {
        if (sObj instanceof PDFStream && dObj instanceof PDFStream) {
            walk(sObj.dict, dObj.dict, false);
            return;
        }
        if (sObj instanceof PDFDict && dObj instanceof PDFDict) {
            for (const [key, sVal] of sObj.entries()) {
                // A page leaf's /Parent points into the source page tree. The
                // destination has its own tree, and descending here would map
                // source page refs that were never copied.
                if (isPageLeaf && key === N.Parent) continue;
                const dVal = dObj.get(key);
                if (dVal === undefined) continue;
                if (sVal instanceof PDFRef && dVal instanceof PDFRef) enqueue(sVal, dVal);
                else walk(sVal, dVal, false);
            }
            return;
        }
        if (sObj instanceof PDFArray && dObj instanceof PDFArray) {
            if (sObj.size() !== dObj.size()) {
                divergences.push(`array size ${sObj.size()} vs ${dObj.size()}`);
                return;
            }
            for (let i = 0; i < sObj.size(); i += 1) {
                const sVal = sObj.get(i);
                const dVal = dObj.get(i);
                if (sVal instanceof PDFRef && dVal instanceof PDFRef) enqueue(sVal, dVal);
                else walk(sVal, dVal, false);
            }
        }
    };

    while (queue.length) {
        const [sRef, dRef] = queue.shift();
        const key = `${sRef.tag}|${dRef.tag}`;
        if (seenPairs.has(key)) continue;
        seenPairs.add(key);
        const sObj = srcDoc.context.lookup(sRef);
        const dObj = destDoc.context.lookup(dRef);
        if (sObj === undefined || dObj === undefined) continue;
        walk(sObj, dObj, sObj instanceof PDFPageLeaf);
    }

    return { map, divergences, strays };
}

/* Remove the duplicate page objects pdf-lib's copier leaves behind.
 *
 * Every reference to a stray is repointed at the real page first — an
 * annotation's /P back-pointer being the usual one — and only then is the stray
 * deleted, so nothing is left pointing into empty space. The real page and the
 * stray share their content stream and resource refs (those DO go through the
 * copier's cache), so deleting the stray cannot orphan page content.
 *
 * Returns the number of duplicate page objects removed.
 */
export function repairStrayPageCopies(destDoc, strays) {
    if (!strays || strays.size === 0) return 0;

    const substitute = (obj, seen) => {
        if (obj instanceof PDFStream) return substitute(obj.dict, seen);
        if (obj instanceof PDFDict) {
            if (seen.has(obj)) return;
            seen.add(obj);
            for (const [key, value] of obj.entries()) {
                if (value instanceof PDFRef) {
                    const fixed = strays.get(value.tag);
                    if (fixed) obj.set(key, fixed);
                } else substitute(value, seen);
            }
            return;
        }
        if (obj instanceof PDFArray) {
            if (seen.has(obj)) return;
            seen.add(obj);
            for (let i = 0; i < obj.size(); i += 1) {
                const value = obj.get(i);
                if (value instanceof PDFRef) {
                    const fixed = strays.get(value.tag);
                    if (fixed) obj.set(i, fixed);
                } else substitute(value, seen);
            }
        }
    };

    const seen = new Set();
    for (const [ref, obj] of destDoc.context.enumerateIndirectObjects()) {
        if (strays.has(ref.tag)) continue;   // about to be deleted anyway
        substitute(obj, seen);
    }

    // The strays themselves are left for garbageCollect() to sweep: once nothing
    // points at them they are unreachable, and so is everything they alone kept
    // alive (their content streams and resources).
    return strays.size;
}

/* Mark-and-sweep from the trailer, deleting everything unreachable.
 *
 * THIS IS A CONFIDENTIALITY CONTROL, NOT AN OPTIMISATION.
 *
 * pdf-lib writes out every object in the context, reachable or not, and its
 * page copier follows references without regard for what was selected. Given a
 * document with form fields, copying page 1 walks: page 1's widget -> /Parent
 * -> its field -> the field's siblings -> their widgets -> /P -> the pages
 * THOSE widgets live on. Pages the user never asked for are copied into the
 * output in full.
 *
 * Measured on the test document: extracting pages 1-2 of a six-page form
 * produced a file containing four page objects, one of which was a complete
 * copy of page 3 — content stream included. No viewer shows it. Any parser
 * recovers it. Someone extracting two pages to send onward would be shipping a
 * page they believed they had left behind.
 *
 * Sweeping from the trailer is the only reliable fix: it does not matter how an
 * unwanted object got in, if the document does not reference it, it does not
 * ship.
 *
 * Returns the number of objects removed.
 */
export function garbageCollect(destDoc) {
    const context = destDoc.context;
    const reachable = new Set();
    const stack = [];

    const mark = (value) => {
        if (!(value instanceof PDFRef)) return false;
        if (reachable.has(value.tag)) return true;
        reachable.add(value.tag);
        stack.push(value);
        return true;
    };

    const walk = (obj, seen) => {
        if (obj instanceof PDFStream) return walk(obj.dict, seen);
        if (obj instanceof PDFDict) {
            if (seen.has(obj)) return;
            seen.add(obj);
            for (const [, value] of obj.entries()) if (!mark(value)) walk(value, seen);
            return;
        }
        if (obj instanceof PDFArray) {
            if (seen.has(obj)) return;
            seen.add(obj);
            for (const value of obj.asArray()) if (!mark(value)) walk(value, seen);
        }
    };

    mark(context.trailerInfo.Root);
    mark(context.trailerInfo.Info);
    mark(context.trailerInfo.Encrypt);

    const seen = new Set();
    while (stack.length) {
        const ref = stack.pop();
        const obj = context.lookup(ref);
        if (obj !== undefined) walk(obj, seen);
    }

    const doomed = [];
    for (const [ref] of context.enumerateIndirectObjects()) {
        if (!reachable.has(ref.tag)) doomed.push(ref);
    }
    for (const ref of doomed) context.delete(ref);
    return doomed.length;
}

/* ── Object copier ───────────────────────────────────────────────────────── */

/* Deep-copy an object graph from one document into another.
 *
 * Three behaviours distinguish this from a plain deep copy, and all three exist
 * to stop a specific way of corrupting the output:
 *
 *  1. A ref already in `correspondence` resolves to the object copyPages
 *     produced, instead of being copied again. Without this, form fields and
 *     optional-content groups detach from their pages.
 *  2. A ref that names a source page NOT in `correspondence` is refused and
 *     recorded in `dangling`. Without this, a split would pull excluded pages
 *     into the output as orphans.
 *  3. Streams are copied as raw bytes with their /Filter intact — never decoded
 *     and re-encoded. That is what keeps the SHA-256 comparison honest.
 */
export function createCopier(srcDoc, destDoc, correspondence, srcPageTags, keptPageTags) {
    const cache = new Map();     // source ref tag -> destination PDFRef
    const dangling = [];

    function copyRef(ref) {
        const tag = ref.tag;

        // Excluded pages are checked BEFORE the correspondence map, never after:
        // the map can contain a page pdf-lib over-copied, and consulting it first
        // would hand back a reference to a page the user did not select.
        if (srcPageTags.has(tag) && !keptPageTags.has(tag)) {
            dangling.push(tag);
            return null;
        }

        const known = correspondence.get(tag);
        if (known) return known;

        const cached = cache.get(tag);
        if (cached) return cached;

        const value = srcDoc.context.lookup(ref);
        if (value === undefined) return null;

        // Reserve the destination ref before recursing so that cycles (which are
        // normal in PDF: /Parent chains, sibling links) terminate.
        const newRef = destDoc.context.nextRef();
        cache.set(tag, newRef);
        const copied = copyObject(value);
        if (copied === null) {
            cache.delete(tag);
            return null;
        }
        destDoc.context.assign(newRef, copied);
        return newRef;
    }

    function copyObject(obj) {
        if (obj instanceof PDFRef) return copyRef(obj);

        if (obj instanceof PDFStream) {
            const dict = copyObject(obj.dict);
            if (dict === null) return null;
            // `contents` is the raw, still-encoded payload. Copying it verbatim
            // is the whole point: no decode, no re-encode, no re-compression.
            const raw = obj instanceof PDFRawStream ? obj.contents : obj.getContents();
            return PDFRawStream.of(dict, raw.slice());
        }

        if (obj instanceof PDFDict) {
            const out = PDFDict.withContext(destDoc.context);
            for (const [key, value] of obj.entries()) {
                const copied = copyObject(value);
                if (copied !== null) out.set(key, copied);
            }
            return out;
        }

        if (obj instanceof PDFArray) {
            const out = PDFArray.withContext(destDoc.context);
            for (const value of obj.asArray()) {
                const copied = copyObject(value);
                // Preserve arity: a dropped element would shift every index after
                // it, which silently corrupts destination arrays like [page /XYZ x y z].
                out.push(copied === null ? PDFName.of('SecurityBuddyDropped') : copied);
            }
            return out;
        }

        // Names, numbers, strings, booleans and null are immutable value objects
        // in pdf-lib and are safe to share across contexts.
        return obj;
    }

    return {
        copy: (obj) => copyObject(obj),
        copyIndirect: (obj) => {
            const copied = copyObject(obj);
            if (copied === null) return null;
            return copied instanceof PDFRef ? copied : destDoc.context.register(copied);
        },
        get dangling() { return dangling; },
    };
}

/* Collect the optional-content groups the SELECTED pages actually use.
 *
 * Same lesson as the page leak: decide from the source side, from what was
 * chosen, never from what the copier happened to touch. Without this,
 * /OCProperties keeps listing every layer in the original document — including
 * layers belonging to pages that were not selected. No page content escapes,
 * but the layer NAMES do, and a layer called "Draft pricing" or "Confidential
 * annex" tells a reader about material they were not given.
 *
 * Back-pointers (/Parent, /P) are skipped: following them walks out of the page
 * into the form-field tree and from there into other pages' resources, which is
 * exactly the path that leaked whole pages before.
 */
export function collectOptionalContentInUse(doc, keptPageTags) {
    const used = new Set();
    const seen = new Set();
    const OCG = PDFName.of('OCG');
    const OCMD = PDFName.of('OCMD');

    const visitRef = (ref) => {
        if (seen.has(ref.tag)) return;
        seen.add(ref.tag);
        const obj = doc.context.lookup(ref);
        if (obj instanceof PDFDict) {
            const type = obj.get(N.Type);
            if (type === OCG || type === OCMD) used.add(ref.tag);
        }
        walk(obj);
    };

    const walk = (obj) => {
        if (obj instanceof PDFStream) return walk(obj.dict);
        if (obj instanceof PDFDict) {
            for (const [key, value] of obj.entries()) {
                if (key === N.Parent || key === N.P) continue;
                if (value instanceof PDFRef) visitRef(value); else walk(value);
            }
            return;
        }
        if (obj instanceof PDFArray) {
            for (const value of obj.asArray()) {
                if (value instanceof PDFRef) visitRef(value); else walk(value);
            }
        }
    };

    for (const page of doc.getPages()) {
        if (keptPageTags.has(page.ref.tag)) walk(page.node);
    }
    return used;
}

/* Index every annotation by the page it sits on.
 *
 * Needed because the correspondence map is NOT a reliable answer to "did this
 * survive?": pdf-lib's copier over-copies (see garbageCollect), so an object
 * being in the map only means pdf-lib touched it, not that its page was kept.
 * Form-field pruning has to decide from the source side instead — which page is
 * this widget actually on, and was that page selected? */
export function buildAnnotationPageIndex(doc) {
    const index = new Map();   // annotation ref tag -> page ref tag
    for (const page of doc.getPages()) {
        const annots = page.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
        if (!annots) continue;
        for (const ref of annots.asArray()) {
            if (ref instanceof PDFRef) index.set(ref.tag, page.ref.tag);
        }
    }
    return index;
}

/* Collect every page ref of a document — including pages that will NOT be
 * copied. This is what lets the copier tell "excluded page" apart from
 * "ordinary object it should copy". */
export function allPageRefTags(doc) {
    const tags = new Set();
    for (const page of doc.getPages()) tags.add(page.ref.tag);
    return tags;
}

/* ── Destination resolution ──────────────────────────────────────────────── */

/* Work out which page an outline item or named destination points at.
 * Returns { kind: 'page', ref } | { kind: 'pageless' } | { kind: 'unknown' }. */
function resolveDestinationPage(doc, holder) {
    let dest = holder.get(N.Dest);

    if (dest === undefined) {
        const action = holder.lookupMaybe(N.A, PDFDict);
        if (!action) return { kind: 'unknown' };
        const type = action.get(N.S);
        // Only /GoTo targets a page in this document. /URI, /Launch, /GoToR and
        // friends point elsewhere and survive any page rearrangement untouched.
        if (type !== PDFName.of('GoTo')) return { kind: 'pageless' };
        dest = action.get(N.D);
    }

    if (dest === undefined) return { kind: 'unknown' };

    // A named destination: resolve it through the document's name tree.
    if (dest instanceof PDFString || dest instanceof PDFHexString || dest instanceof PDFName) {
        const resolved = lookupNamedDestination(doc, dest);
        if (!resolved) return { kind: 'unknown' };
        dest = resolved;
    }

    const array = doc.context.lookup(dest);
    if (!(array instanceof PDFArray) || array.size() === 0) return { kind: 'unknown' };

    const target = array.get(0);
    if (target instanceof PDFRef) return { kind: 'page', ref: target };
    // An explicit destination may also use a page *index* (used inside remote
    // GoToR actions). An index into this document cannot be trusted after a
    // rearrangement, so treat it as unknown rather than guessing.
    return { kind: 'unknown' };
}

function lookupNamedDestination(doc, nameObj) {
    // A destination may be named by a /Name or by a text string; only the text
    // string needs decoding (it can be UTF-16BE with a BOM).
    const key = nameObj instanceof PDFName ? nameObj.asString().replace(/^\//, '')
        : (nameObj.decodeText?.() ?? String(nameObj));

    // PDF 1.1 style: catalog /Dests is a plain dictionary.
    const legacy = doc.catalog.lookupMaybe(N.Dests, PDFDict);
    if (legacy) {
        const hit = legacy.get(PDFName.of(key));
        if (hit !== undefined) return hit;
    }

    // PDF 1.2+ style: catalog /Names /Dests is a name tree.
    const names = doc.catalog.lookupMaybe(N.Names, PDFDict);
    const tree = names?.lookupMaybe(N.Dests, PDFDict);
    if (!tree) return undefined;

    for (const [entryKey, value] of readNameTree(doc, tree)) {
        if (entryKey === key) {
            // Entries may be a dict with /D rather than a bare array.
            const resolved = doc.context.lookup(value);
            if (resolved instanceof PDFDict) return resolved.get(N.D);
            return value;
        }
    }
    return undefined;
}

/* Flatten a PDF name tree (which may be split across /Kids) into [key, value]
 * pairs. Depth-limited: a malformed file must not hang the tab. */
function readNameTree(doc, node, out = [], depth = 0) {
    if (depth > 64) return out;
    const names = node.lookupMaybe(N.Names, PDFArray);
    if (names) {
        for (let i = 0; i + 1 < names.size(); i += 2) {
            const key = names.lookup(i);
            const value = names.get(i + 1);
            const keyStr = key?.decodeText ? key.decodeText()
                : (key?.asString ? key.asString() : String(key));
            out.push([keyStr, value]);
        }
    }
    const kids = node.lookupMaybe(N.Kids, PDFArray);
    if (kids) {
        for (const kidRef of kids.asArray()) {
            const kid = doc.context.lookup(kidRef);
            if (kid instanceof PDFDict) readNameTree(doc, kid, out, depth + 1);
        }
    }
    return out;
}

/* Flatten a PDF number tree into [index, value] pairs, sorted by index. */
function readNumberTree(doc, node, out = [], depth = 0) {
    if (depth > 64) return out;
    const nums = node.lookupMaybe(N.Nums, PDFArray);
    if (nums) {
        for (let i = 0; i + 1 < nums.size(); i += 2) {
            const key = nums.lookup(i);
            if (key instanceof PDFNumber) out.push([key.asNumber(), nums.get(i + 1)]);
        }
    }
    const kids = node.lookupMaybe(N.Kids, PDFArray);
    if (kids) {
        for (const kidRef of kids.asArray()) {
            const kid = doc.context.lookup(kidRef);
            if (kid instanceof PDFDict) readNumberTree(doc, kid, out, depth + 1);
        }
    }
    out.sort((a, b) => a[0] - b[0]);
    return out;
}

export const __testing = {
    readNameTree, readNumberTree, resolveDestinationPage, lookupNamedDestination,
};
