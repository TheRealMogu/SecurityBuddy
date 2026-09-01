/* Security Buddy — catalog preservation.
 * ============================================================================
 *
 * Everything `copyPages()` leaves behind, carried across one structure at a
 * time. Each function here returns nothing and reports into the shared report
 * object: what survived unchanged, what had to be restructured, and what could
 * not come across at all.
 *
 * The rule this file follows: if a structure cannot be reproduced faithfully,
 * it is recorded in `report.dropped` with the reason. Nothing is approximated
 * and nothing disappears quietly.
 */

import {
    PDFDict, PDFArray, PDFName, PDFRef, PDFNumber, PDFString, PDFHexString,
    PDFStream,
} from './pdflib.js';

import {
    createReport, buildCorrespondence, createCopier, allPageRefTags,
    inspectDocument, assessOperation, repairStrayPageCopies, garbageCollect,
    buildAnnotationPageIndex, collectOptionalContentInUse,
} from './preserve.js';

const N = {
    A: PDFName.of('A'), AcroForm: PDFName.of('AcroForm'), Count: PDFName.of('Count'),
    D: PDFName.of('D'), DR: PDFName.of('DR'), Dest: PDFName.of('Dest'),
    Dests: PDFName.of('Dests'), EmbeddedFiles: PDFName.of('EmbeddedFiles'),
    Fields: PDFName.of('Fields'), First: PDFName.of('First'), Info: PDFName.of('Info'),
    JavaScript: PDFName.of('JavaScript'), Kids: PDFName.of('Kids'), Lang: PDFName.of('Lang'),
    Last: PDFName.of('Last'), Metadata: PDFName.of('Metadata'), Names: PDFName.of('Names'),
    Next: PDFName.of('Next'), Nums: PDFName.of('Nums'), OCGs: PDFName.of('OCGs'),
    OCProperties: PDFName.of('OCProperties'), OFF: PDFName.of('OFF'), ON: PDFName.of('ON'),
    OpenAction: PDFName.of('OpenAction'), Order: PDFName.of('Order'),
    Outlines: PDFName.of('Outlines'), P: PDFName.of('P'), PageLabels: PDFName.of('PageLabels'),
    PageLayout: PDFName.of('PageLayout'), PageMode: PDFName.of('PageMode'),
    Parent: PDFName.of('Parent'), Prev: PDFName.of('Prev'), S: PDFName.of('S'),
    St: PDFName.of('St'), Subtype: PDFName.of('Subtype'), T: PDFName.of('T'),
    Title: PDFName.of('Title'), Type: PDFName.of('Type'),
    ViewerPreferences: PDFName.of('ViewerPreferences'), Widget: PDFName.of('Widget'),
};

const push = (list, item, detail, opts) =>
    list.push({ item, detail, prominent: !!(opts && opts.prominent) });

/* ── Orchestrator ────────────────────────────────────────────────────────── */

/* Carry every catalog-level structure from the source documents into the
 * destination.
 *
 * `sources` is [{ doc, label, pagePairs }] where pagePairs is
 * [[sourcePageRef, destinationPageRef], ...] for the pages that were copied,
 * in output order. Build it right after copyPages/addPage.
 */
export function preserveAll({ destDoc, sources, report = createReport() }) {
    const allStrays = new Map();

    const contexts = sources.map((source) => {
        const srcPageTags = allPageRefTags(source.doc);
        const keptPages = new Set(source.pagePairs.map(([srcRef]) => srcRef.tag));
        const { map, divergences, strays } = buildCorrespondence(
            source.doc, destDoc, source.pagePairs, srcPageTags,
        );
        for (const [strayTag, correctRef] of strays) allStrays.set(strayTag, correctRef);
        if (divergences.length) {
            push(report.dropped, `Object mapping (${source.label})`,
                `The copied page graph did not match the source graph in ` +
                `${divergences.length} place(s), so some catalog structures may ` +
                `not have been reconnected: ${divergences.slice(0, 3).join('; ')}. ` +
                `This is unexpected — please report the file.`);
        }
        return {
            ...source,
            correspondence: map,
            srcPageTags,
            annotPage: buildAnnotationPageIndex(source.doc),
            keptPages,
            usedOC: collectOptionalContentInUse(source.doc, keptPages),
            copier: createCopier(source.doc, destDoc, map, srcPageTags, keptPages),
            inspection: inspectDocument(source.doc),
        };
    });

    for (const ctx of contexts) {
        assessOperation(ctx.inspection, report, sources.length > 1 ? ctx.label : '');
    }

    const isMerge = contexts.length > 1;

    preserveInfo(destDoc, contexts, report, isMerge);
    preserveXmp(destDoc, contexts, report, isMerge);
    preserveOutlines(destDoc, contexts, report);
    preserveAcroForm(destDoc, contexts, report, isMerge);
    preserveNameTrees(destDoc, contexts, report, isMerge);
    preservePageLabels(destDoc, contexts, report);
    preserveOptionalContent(destDoc, contexts, report, isMerge);
    preserveSimpleCatalogEntries(destDoc, contexts, report, isMerge);

    // Repoint /P back-pointers at the real pages, then sweep. Order matters: a
    // stray that is still referenced is still reachable, and would survive.
    repairStrayPageCopies(destDoc, allStrays);
    const collected = garbageCollect(destDoc);
    if (collected) {
        push(report.rebuilt, 'Unreferenced objects removed',
            `${collected} object(s) that pdf-lib's page copier pulled in but the ` +
            `document does not reference were swept from the output. This ` +
            `includes duplicate page objects and, on documents with form fields, ` +
            `complete copies of pages that were not selected — those would ` +
            `otherwise have shipped inside the file, invisible to a viewer but ` +
            `readable by any parser.`);
    }

    for (const ctx of contexts) {
        if (ctx.copier.dangling.length) {
            push(report.rebuilt, `Internal links (${ctx.label})`,
                `${ctx.copier.dangling.length} reference(s) pointed at pages that ` +
                `are not in the output and were removed rather than dragging those ` +
                `pages into the file as orphans.`);
        }
    }

    return report;
}

/* ── /Info — document metadata ───────────────────────────────────────────── */

/* pdf-lib stamps its own Producer and dates onto every document it creates.
 * Copying the source /Info dictionary wholesale (rather than using the typed
 * setters) also preserves any custom keys the producing application wrote. */
function preserveInfo(destDoc, contexts, report, isMerge) {
    const primary = contexts[0];
    const infoRef = primary.doc.context.trailerInfo.Info;
    const info = infoRef ? primary.doc.context.lookup(infoRef) : undefined;

    if (!(info instanceof PDFDict)) {
        push(report.dropped, 'Document metadata (/Info)',
            'The source document had no /Info dictionary. The output carries ' +
            'pdf-lib\'s default Producer string.');
        return;
    }

    const copied = primary.copier.copyIndirect(info);
    if (!copied) return;
    destDoc.context.trailerInfo.Info = copied;

    push(report.preserved, 'Document metadata (/Info)',
        `Title, Author, Subject, Keywords, Creator, Producer and dates carried ` +
        `across verbatim${isMerge ? ` from "${primary.label}"` : ''}.`);

    if (isMerge) {
        const others = contexts.slice(1).filter((c) => {
            const ref = c.doc.context.trailerInfo.Info;
            return ref && c.doc.context.lookup(ref) instanceof PDFDict;
        });
        if (others.length) {
            push(report.dropped, 'Document metadata of the other inputs',
                `A PDF has exactly one /Info dictionary, so only the first ` +
                `document's metadata could be kept. Dropped: ` +
                `${others.map((c) => c.label).join(', ')}.`);
        }
    }
}

/* ── XMP metadata ────────────────────────────────────────────────────────── */

function preserveXmp(destDoc, contexts, report, isMerge) {
    const withXmp = contexts.filter((c) => c.doc.catalog.get(N.Metadata));
    if (!withXmp.length) return;

    if (isMerge) {
        push(report.dropped, 'XMP metadata (/Metadata)',
            `${withXmp.length} input document(s) carried an XMP metadata stream. ` +
            `XMP describes one specific document — merging several would produce ` +
            `a packet that misstates the file it is attached to, so none was ` +
            `carried across. The /Info dictionary of the first document is kept.`);
        return;
    }

    const ctx = withXmp[0];
    const stream = ctx.doc.catalog.lookup(N.Metadata);
    if (!(stream instanceof PDFStream)) return;

    const copied = ctx.copier.copyIndirect(stream);
    if (!copied) return;
    destDoc.catalog.set(N.Metadata, copied);

    const pagesChanged = ctx.pagePairs.length !== ctx.inspection.pageCount;
    if (pagesChanged) {
        push(report.rebuilt, 'XMP metadata (/Metadata)',
            `Carried across verbatim, but the page count changed ` +
            `(${ctx.inspection.pageCount} to ${ctx.pagePairs.length}). Any ` +
            `page-dependent statement inside the XMP packet now describes the ` +
            `original document. The packet was not edited because rewriting XMP ` +
            `reliably is outside what this tool does.`);
    } else {
        push(report.preserved, 'XMP metadata (/Metadata)', 'Carried across verbatim.');
    }
}

/* ── Outlines / bookmarks ────────────────────────────────────────────────── */

/* The outline is rebuilt rather than deep-copied.
 *
 * A deep copy would either drag excluded pages into the output (via bookmarks
 * pointing at them) or leave dangling destinations behind. Rebuilding lets us
 * prune precisely: an item whose target page is gone is removed, unless it has
 * surviving children, in which case it is kept as a heading with its
 * destination stripped. /First, /Last, /Next, /Prev, /Parent and /Count are
 * all recomputed so the tree is internally consistent.
 */
function preserveOutlines(destDoc, contexts, report) {
    const trees = [];
    let sourceCount = 0;
    let prunedTotal = 0;

    for (const ctx of contexts) {
        const root = ctx.doc.catalog.lookupMaybe(N.Outlines, PDFDict);
        if (!root) continue;
        sourceCount += 1;
        const items = readOutlineItems(ctx.doc, root.get(N.First), 0, new Set());
        const stats = { pruned: 0, stripped: 0 };
        const kept = filterOutlineItems(items, ctx.keptPages, stats);
        prunedTotal += stats.pruned;
        if (kept.length) trees.push({ ctx, items: kept, stats });
    }

    if (!sourceCount) return;

    const allItems = [];
    for (const tree of trees) {
        for (const item of tree.items) allItems.push({ item, ctx: tree.ctx });
    }

    if (!allItems.length) {
        push(report.dropped, 'Outline / bookmarks',
            'Every bookmark pointed at a page that is not in the output, so the ' +
            'outline was removed. Keeping it would have left bookmarks that ' +
            'navigate nowhere.');
        return;
    }

    const rootDict = PDFDict.withContext(destDoc.context);
    const rootRef = destDoc.context.register(rootDict);
    rootDict.set(N.Type, N.Outlines);

    const built = writeOutlineLevel(destDoc, allItems, rootRef);
    if (built.first) rootDict.set(N.First, built.first);
    if (built.last) rootDict.set(N.Last, built.last);
    rootDict.set(N.Count, PDFNumber.of(built.visible));
    destDoc.catalog.set(N.Outlines, rootRef);

    if (prunedTotal || contexts.length > 1) {
        push(report.rebuilt, 'Outline / bookmarks',
            `Rebuilt with ${allItems.length} top-level entr(ies)` +
            (prunedTotal ? `; ${prunedTotal} bookmark(s) pointing at pages not in ` +
                `the output were removed` : '') +
            (contexts.length > 1 ? '; the outlines of the input documents were ' +
                'concatenated in input order' : '') +
            '. Titles, nesting and open/closed state are preserved.');
    } else {
        push(report.preserved, 'Outline / bookmarks',
            `${allItems.length} top-level entr(ies) carried across with nesting, ` +
            `titles and open/closed state intact.`);
    }
}

function readOutlineItems(doc, firstRef, depth, guard) {
    const items = [];
    if (depth > 64) return items;
    let ref = firstRef;

    while (ref instanceof PDFRef) {
        if (guard.has(ref.tag)) break;   // malformed sibling loop
        guard.add(ref.tag);
        const dict = doc.context.lookup(ref);
        if (!(dict instanceof PDFDict)) break;

        const countObj = dict.lookupMaybe(N.Count, PDFNumber);
        items.push({
            dict,
            // A positive /Count means the item is open (children visible).
            open: countObj ? countObj.asNumber() > 0 : false,
            dest: resolveOutlineDestination(doc, dict),
            children: readOutlineItems(doc, dict.get(N.First), depth + 1, guard),
            stripDest: false,
        });
        ref = dict.get(N.Next);
    }
    return items;
}

function resolveOutlineDestination(doc, dict) {
    let dest = dict.get(N.Dest);
    if (dest === undefined) {
        const action = doc.context.lookup(dict.get(N.A));
        if (!(action instanceof PDFDict)) return { kind: 'unknown' };
        if (action.get(N.S) !== PDFName.of('GoTo')) return { kind: 'pageless' };
        dest = action.get(N.D);
    }
    if (dest === undefined) return { kind: 'unknown' };
    const array = doc.context.lookup(dest);
    if (!(array instanceof PDFArray) || array.size() === 0) return { kind: 'unknown' };
    const target = array.get(0);
    return target instanceof PDFRef ? { kind: 'page', ref: target } : { kind: 'unknown' };
}

/* `keptPages` holds SOURCE page refs that were actually selected — deliberately
 * not the correspondence map, which also contains pages pdf-lib over-copied and
 * would therefore answer "kept" for a page the user excluded. */
function filterOutlineItems(items, keptPages, stats) {
    const kept = [];
    for (const item of items) {
        item.children = filterOutlineItems(item.children, keptPages, stats);
        const targetsMissingPage =
            item.dest.kind === 'page' && !keptPages.has(item.dest.ref.tag);

        if (targetsMissingPage && item.children.length === 0) {
            stats.pruned += 1;
            continue;
        }
        if (targetsMissingPage) {
            // Keep it as a container so its surviving children stay reachable,
            // but remove the destination that no longer resolves.
            item.stripDest = true;
            stats.stripped += 1;
        }
        kept.push(item);
    }
    return kept;
}

function writeOutlineLevel(destDoc, entries, parentRef) {
    const refs = [];
    const built = [];

    for (const entry of entries) {
        const item = entry.item;
        const ctx = entry.ctx;
        const dict = PDFDict.withContext(destDoc.context);
        const ref = destDoc.context.register(dict);

        // Copy the item's own attributes, but never its tree linkage — those are
        // recomputed below so the rebuilt tree is self-consistent.
        for (const [key, value] of item.dict.entries()) {
            if (key === N.First || key === N.Last || key === N.Next
                || key === N.Prev || key === N.Parent || key === N.Count) continue;
            if (item.stripDest && (key === N.Dest || key === N.A)) continue;
            const copied = ctx.copier.copy(value);
            if (copied !== null) dict.set(key, copied);
        }

        dict.set(N.Parent, parentRef);
        refs.push(ref);
        built.push({ ref, dict, item, ctx });
    }

    // Sibling chain.
    for (let i = 0; i < built.length; i += 1) {
        if (i > 0) built[i].dict.set(N.Prev, refs[i - 1]);
        if (i < built.length - 1) built[i].dict.set(N.Next, refs[i + 1]);
    }

    // Children, and the signed /Count each item advertises.
    let visibleHere = built.length;
    for (const node of built) {
        if (!node.item.children.length) continue;
        const childEntries = node.item.children.map((c) => ({ item: c, ctx: node.ctx }));
        const child = writeOutlineLevel(destDoc, childEntries, node.ref);
        if (child.first) node.dict.set(N.First, child.first);
        if (child.last) node.dict.set(N.Last, child.last);
        // Negative /Count = closed: the descendants exist but are not counted as
        // visible by the viewer.
        node.dict.set(N.Count, PDFNumber.of(
            node.item.open ? child.visible : -child.visible,
        ));
        if (node.item.open) visibleHere += child.visible;
    }

    return {
        first: refs[0] ?? null,
        last: refs[refs.length - 1] ?? null,
        visible: visibleHere,
    };
}

/* ── AcroForm ────────────────────────────────────────────────────────────── */

/* The single most dangerous structure to copy naively.
 *
 * For a simple field the field dictionary and its widget annotation are the
 * same object, and that object is already in the output because it was on a
 * page. Deep-copying /Fields would create a second copy, and the form would
 * point at fields the pages do not show: they render, and they are not
 * fillable. `copier` resolves those refs through the correspondence map
 * instead, so the form points at exactly the widgets the pages carry.
 */
function preserveAcroForm(destDoc, contexts, report, isMerge) {
    const withForms = contexts.filter((c) => c.doc.catalog.lookupMaybe(N.AcroForm, PDFDict));
    if (!withForms.length) return;

    const destFields = PDFArray.withContext(destDoc.context);
    const acro = PDFDict.withContext(destDoc.context);
    const fieldNames = new Map();   // fully-qualified name -> source label
    const collisions = [];
    let droppedFields = 0;
    let totalKept = 0;

    for (const ctx of withForms) {
        const srcAcro = ctx.doc.catalog.lookupMaybe(N.AcroForm, PDFDict);
        const srcFields = srcAcro.lookupMaybe(N.Fields, PDFArray);
        if (!srcFields) continue;

        for (const fieldRef of srcFields.asArray()) {
            const result = copyFieldTree(destDoc, ctx, fieldRef, null, new Set());
            if (!result) { droppedFields += 1; continue; }
            destFields.push(result.ref);
            totalKept += 1;

            for (const name of result.names) {
                if (fieldNames.has(name) && fieldNames.get(name) !== ctx.label) {
                    collisions.push(name);
                } else {
                    fieldNames.set(name, ctx.label);
                }
            }
        }

        // /DR (the form's default resources) is where field fonts live. Merge
        // rather than overwrite, so a later document does not lose its fonts.
        const srcDR = srcAcro.lookupMaybe(N.DR, PDFDict);
        if (srcDR) {
            let destDR = acro.lookupMaybe(N.DR, PDFDict);
            if (!destDR) {
                destDR = PDFDict.withContext(destDoc.context);
                acro.set(N.DR, destDR);
            }
            mergeResourceDict(destDR, srcDR, ctx, destDoc);
        }

        // Scalar form-wide settings: first document wins.
        for (const key of [PDFName.of('DA'), PDFName.of('Q'),
            PDFName.of('NeedAppearances'), PDFName.of('SigFlags')]) {
            if (!acro.get(key) && srcAcro.get(key) !== undefined) {
                const copied = ctx.copier.copy(srcAcro.get(key));
                if (copied !== null) acro.set(key, copied);
            }
        }
    }

    if (!destFields.size()) {
        push(report.dropped, 'Form fields (/AcroForm)',
            'Every form field belonged to a page that is not in the output, so ' +
            'the form dictionary was removed.');
        return;
    }

    acro.set(N.Fields, destFields);
    destDoc.catalog.set(N.AcroForm, destDoc.context.register(acro));

    const detail = [`${totalKept} top-level field(s) reconnected to the widgets on ` +
        `the copied pages, so they stay fillable.`];
    if (droppedFields) {
        detail.push(`${droppedFields} field(s) were removed because all of their ` +
            `widgets were on pages that are not in the output.`);
    }
    push(droppedFields ? report.rebuilt : report.preserved, 'Form fields (/AcroForm)',
        detail.join(' '));

    if (collisions.length) {
        const unique = [...new Set(collisions)];
        push(report.dropped, 'Form field independence',
            `${unique.length} field name(s) appear in more than one input ` +
            `document: ${unique.slice(0, 5).join(', ')}` +
            `${unique.length > 5 ? ', …' : ''}. In PDF, fields sharing a fully ` +
            `qualified name are one field with one value — typing in one now ` +
            `changes the others. This cannot be fixed by renaming without ` +
            `rewriting the field appearances, which this tool will not do. ` +
            `Consider merging these documents separately.`);
    }

    if (isMerge) {
        push(report.rebuilt, 'Form default resources (/DR)',
            'The default resource dictionaries of the input forms were merged. ' +
            'Where two documents used the same resource name for different ' +
            'objects, the first document\'s entry was kept (listed separately if ' +
            'any collision occurred).');
    }
}

/* Copy one field subtree.
 *
 * Returns null when nothing of the field survives — i.e. every widget under it
 * sits on a page that is not in the output. */
function copyFieldTree(destDoc, ctx, fieldRef, parentRef, guard) {
    if (!(fieldRef instanceof PDFRef)) return null;
    if (guard.has(fieldRef.tag)) return null;
    guard.add(fieldRef.tag);

    const dict = ctx.doc.context.lookup(fieldRef);
    if (!(dict instanceof PDFDict)) return null;

    const names = [];
    const titleObj = dict.get(N.T);
    if (titleObj instanceof PDFString || titleObj instanceof PDFHexString) {
        // decodeText(), not asString(): a PDF text string may be UTF-16BE with a
        // byte-order mark, and asString() would hand back the raw hex. These
        // names are shown to the user in the collision warning.
        names.push(titleObj.decodeText());
    }

    /* Case 1: this node is a widget annotation sitting on a page.
     *
     * Survival is decided from the SOURCE side — which page is this widget on,
     * and was that page selected — never from the correspondence map. The map
     * says only that pdf-lib's copier touched the object, and that copier walks
     * from a selected page through the field tree into widgets on pages nobody
     * asked for. Trusting it here is what let an unselected page reach the
     * output in the first place. */
    const onPageTag = ctx.annotPage.get(fieldRef.tag)
        ?? (dict.get(N.P) instanceof PDFRef ? dict.get(N.P).tag : undefined);

    if (onPageTag !== undefined) {
        if (!ctx.keptPages.has(onPageTag)) return null;
        const existing = ctx.correspondence.get(fieldRef.tag);
        if (!existing) return null;
        if (parentRef) {
            const destDict = destDoc.context.lookup(existing);
            if (destDict instanceof PDFDict) destDict.set(N.Parent, parentRef);
        }
        return { ref: existing, names };
    }

    // Case 2: a non-terminal field whose widgets are its /Kids.
    const kids = dict.lookupMaybe(N.Kids, PDFArray);
    if (!kids) {
        // A terminal field that is not on any page at all.
        return null;
    }

    const newDict = PDFDict.withContext(destDoc.context);
    const newRef = destDoc.context.register(newDict);

    const survivingKids = PDFArray.withContext(destDoc.context);
    for (const kidRef of kids.asArray()) {
        const kid = copyFieldTree(destDoc, ctx, kidRef, newRef, guard);
        if (!kid) continue;
        survivingKids.push(kid.ref);
        for (const name of kid.names) names.push(name);
    }

    if (!survivingKids.size()) {
        // Nothing under this field survived; drop the whole branch.
        destDoc.context.delete(newRef);
        return null;
    }

    for (const [key, value] of dict.entries()) {
        if (key === N.Kids || key === N.Parent) continue;
        const copied = ctx.copier.copy(value);
        if (copied !== null) newDict.set(key, copied);
    }
    newDict.set(N.Kids, survivingKids);
    if (parentRef) newDict.set(N.Parent, parentRef);

    return { ref: newRef, names };
}

function mergeResourceDict(destDR, srcDR, ctx, destDoc) {
    for (const [category, value] of srcDR.entries()) {
        const srcCategory = ctx.doc.context.lookup(value);
        if (!(srcCategory instanceof PDFDict)) {
            if (!destDR.get(category)) {
                const copied = ctx.copier.copy(value);
                if (copied !== null) destDR.set(category, copied);
            }
            continue;
        }
        let destCategory = destDR.lookupMaybe(category, PDFDict);
        if (!destCategory) {
            destCategory = PDFDict.withContext(destDoc.context);
            destDR.set(category, destCategory);
        }
        for (const [key, entry] of srcCategory.entries()) {
            if (destCategory.get(key)) continue;   // first document wins
            const copied = ctx.copier.copy(entry);
            if (copied !== null) destCategory.set(key, copied);
        }
    }
}

/* ── Name trees: named destinations, attachments, document JavaScript ────── */

function preserveNameTrees(destDoc, contexts, report, isMerge) {
    preserveNamedDestinations(destDoc, contexts, report);
    preserveEmbeddedFiles(destDoc, contexts, report, isMerge);
    preserveDocumentJavaScript(destDoc, contexts, report);
}

function getOrCreateNames(destDoc) {
    let names = destDoc.catalog.lookupMaybe(N.Names, PDFDict);
    if (!names) {
        names = PDFDict.withContext(destDoc.context);
        destDoc.catalog.set(N.Names, destDoc.context.register(names));
    }
    return names;
}

function preserveNamedDestinations(destDoc, contexts, report) {
    const entries = [];
    let dropped = 0;
    let sawAny = false;

    for (const ctx of contexts) {
        const names = ctx.doc.catalog.lookupMaybe(N.Names, PDFDict);
        const tree = names?.lookupMaybe(N.Dests, PDFDict);
        const legacy = ctx.doc.catalog.lookupMaybe(N.Dests, PDFDict);
        if (!tree && !legacy) continue;
        sawAny = true;

        const pairs = [];
        if (tree) flattenNameTree(ctx.doc, tree, pairs, 0);
        if (legacy) for (const [key, value] of legacy.entries()) {
            pairs.push([key.asString().replace(/^\//, ''), value]);   // a /Name, not a text string
        }

        for (const [key, value] of pairs) {
            // Only keep destinations whose target page came across; a name that
            // resolves to nothing is worse than a name that is absent.
            if (!destinationTargetsKeptPage(ctx, value)) { dropped += 1; continue; }
            const copied = ctx.copier.copy(value);
            if (copied === null) { dropped += 1; continue; }
            entries.push([key, copied]);
        }
    }

    if (!sawAny) return;

    if (!entries.length) {
        push(report.dropped, 'Named destinations',
            'Every named destination pointed at a page that is not in the ' +
            'output, so the destination table was removed.');
        return;
    }

    // Emit a single flat name tree. Keys must be sorted for /Limits to be valid.
    entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const array = PDFArray.withContext(destDoc.context);
    const seen = new Set();
    for (const [key, value] of entries) {
        if (seen.has(key)) continue;    // a merge can produce duplicate names
        seen.add(key);
        array.push(PDFString.of(key));
        array.push(value);
    }
    const tree = PDFDict.withContext(destDoc.context);
    tree.set(N.Names, array);
    getOrCreateNames(destDoc).set(N.Dests, destDoc.context.register(tree));

    const duplicates = entries.length - seen.size;
    if (dropped || duplicates) {
        push(report.rebuilt, 'Named destinations',
            `${seen.size} destination(s) kept` +
            (dropped ? `; ${dropped} removed because their target page is not in ` +
                `the output` : '') +
            (duplicates ? `; ${duplicates} duplicate name(s) across the input ` +
                `documents resolved in favour of the first` : '') + '.');
    } else {
        push(report.preserved, 'Named destinations', `${seen.size} destination(s) carried across.`);
    }
}

function destinationTargetsKeptPage(ctx, value) {
    let resolved = ctx.doc.context.lookup(value);
    if (resolved instanceof PDFDict) resolved = ctx.doc.context.lookup(resolved.get(N.D));
    if (!(resolved instanceof PDFArray) || resolved.size() === 0) return false;
    const target = resolved.get(0);
    if (!(target instanceof PDFRef)) return false;
    return ctx.keptPages.has(target.tag);
}

function preserveEmbeddedFiles(destDoc, contexts, report, isMerge) {
    const entries = [];
    let sawAny = false;

    for (const ctx of contexts) {
        const names = ctx.doc.catalog.lookupMaybe(N.Names, PDFDict);
        const tree = names?.lookupMaybe(N.EmbeddedFiles, PDFDict);
        if (!tree) continue;
        sawAny = true;
        const pairs = [];
        flattenNameTree(ctx.doc, tree, pairs, 0);
        for (const [key, value] of pairs) {
            const copied = ctx.copier.copy(value);
            if (copied !== null) entries.push([key, copied]);
        }
    }

    if (!sawAny) return;
    if (!entries.length) {
        push(report.dropped, 'Attachments (/EmbeddedFiles)',
            'The attachment table could not be copied.');
        return;
    }

    entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const array = PDFArray.withContext(destDoc.context);
    const used = new Set();
    let renamed = 0;
    for (const [key, value] of entries) {
        // Attachments are addressed by name; a collision would hide a file.
        let name = key;
        if (used.has(name)) { renamed += 1; let i = 2; while (used.has(`${key} (${i})`)) i += 1; name = `${key} (${i})`; }
        used.add(name);
        array.push(PDFString.of(name));
        array.push(value);
    }
    const tree = PDFDict.withContext(destDoc.context);
    tree.set(N.Names, array);
    getOrCreateNames(destDoc).set(N.EmbeddedFiles, destDoc.context.register(tree));

    push(renamed ? report.rebuilt : report.preserved, 'Attachments (/EmbeddedFiles)',
        `${used.size} attached file(s) carried across with their bytes intact` +
        (renamed ? `; ${renamed} were renamed because the input documents used ` +
            `the same attachment name` : '') + '.');
}

function preserveDocumentJavaScript(destDoc, contexts, report) {
    const present = contexts.filter((c) => {
        const names = c.doc.catalog.lookupMaybe(N.Names, PDFDict);
        return !!names?.get(N.JavaScript);
    });
    if (!present.length) return;

    // Deliberately not carried across. Document-level JavaScript is executable
    // content whose behaviour depends on the document it was written for; after
    // a structural change it may act on pages that moved or vanished. On a
    // security tool, silently transplanting it into a new file is the wrong
    // default.
    push(report.dropped, 'Document JavaScript',
        `${present.length} input document(s) contained document-level ` +
        `JavaScript. It was not carried across: it is executable code written ` +
        `against the original page structure, and this tool does not transplant ` +
        `it into a rearranged document.`);
}

function flattenNameTree(doc, node, out, depth) {
    if (depth > 64) return out;
    const names = node.lookupMaybe(N.Names, PDFArray);
    if (names) {
        for (let i = 0; i + 1 < names.size(); i += 2) {
            const key = names.lookup(i);
            const keyStr = key?.decodeText ? key.decodeText()
                : (key?.asString ? key.asString() : String(key));
            out.push([keyStr, names.get(i + 1)]);
        }
    }
    const kids = node.lookupMaybe(N.Kids, PDFArray);
    if (kids) {
        for (const kidRef of kids.asArray()) {
            const kid = doc.context.lookup(kidRef);
            if (kid instanceof PDFDict) flattenNameTree(doc, kid, out, depth + 1);
        }
    }
    return out;
}

/* ── Page labels ─────────────────────────────────────────────────────────── */

/* Page labels are what the viewer shows in its page box: "iv", "A-3", "12".
 *
 * They are stored as *rules* keyed by page index ("from page 0, lowercase
 * roman, starting at 1"). Reordering or extracting pages invalidates those
 * indices. When the page set is unchanged the tree is copied verbatim; when it
 * is not, each output page gets its source label as a literal prefix. The
 * labels a reader sees are identical either way, but in the second case the
 * generative rules are gone, and that is reported rather than hidden.
 */
function preservePageLabels(destDoc, contexts, report) {
    const withLabels = contexts.filter((c) => c.doc.catalog.get(N.PageLabels));
    if (!withLabels.length) return;

    const single = contexts.length === 1 ? contexts[0] : null;
    const isIdentity = single
        && single.pagePairs.length === single.inspection.pageCount
        && single.pagePairs.every(([srcRef], i) => srcRef.tag === single.doc.getPage(i).ref.tag);

    if (isIdentity) {
        const copied = single.copier.copy(single.doc.catalog.get(N.PageLabels));
        if (copied !== null) {
            destDoc.catalog.set(N.PageLabels, copied);
            push(report.preserved, 'Page labels (/PageLabels)',
                'The page set is unchanged, so the numbering rules were carried ' +
                'across exactly as they were.');
            return;
        }
    }

    const nums = PDFArray.withContext(destDoc.context);
    let index = 0;
    let labelled = 0;

    for (const ctx of contexts) {
        const rules = readPageLabelRules(ctx.doc);
        for (const [srcRef] of ctx.pagePairs) {
            const srcIndex = ctx.doc.getPages().findIndex((p) => p.ref.tag === srcRef.tag);
            const label = srcIndex >= 0 ? computePageLabel(rules, srcIndex) : null;
            if (label !== null) {
                const entry = PDFDict.withContext(destDoc.context);
                // A rule with only /P and no /S renders as the prefix alone —
                // which is exactly how we pin a literal label.
                entry.set(N.P, PDFString.of(label));
                nums.push(PDFNumber.of(index));
                nums.push(entry);
                labelled += 1;
            }
            index += 1;
        }
    }

    if (!labelled) {
        push(report.dropped, 'Page labels (/PageLabels)',
            'No source page carried a resolvable label, so no label table was written.');
        return;
    }

    const tree = PDFDict.withContext(destDoc.context);
    tree.set(N.Nums, nums);
    destDoc.catalog.set(N.PageLabels, destDoc.context.register(tree));

    push(report.rebuilt, 'Custom page numbering converted to fixed values',
        `This document numbered its pages with rules (for example "lowercase ` +
        `roman from page 1, then decimal from page 3"). Reordering the pages ` +
        `invalidates those rules, so each of the ${labelled} labelled page(s) ` +
        `now carries its label as a fixed value instead. You will see the same ` +
        `page numbers you saw before; an application that reads the numbering ` +
        `rules will find fixed labels rather than ranges.`,
        { prominent: true });
}

function readPageLabelRules(doc) {
    const tree = doc.catalog.lookupMaybe(N.PageLabels, PDFDict);
    if (!tree) return [];
    const out = [];
    collectNumberTree(doc, tree, out, 0);
    out.sort((a, b) => a[0] - b[0]);
    return out;
}

function collectNumberTree(doc, node, out, depth) {
    if (depth > 64) return;
    const nums = node.lookupMaybe(N.Nums, PDFArray);
    if (nums) {
        for (let i = 0; i + 1 < nums.size(); i += 2) {
            const key = nums.lookup(i);
            if (key instanceof PDFNumber) out.push([key.asNumber(), nums.lookup(i + 1)]);
        }
    }
    const kids = node.lookupMaybe(N.Kids, PDFArray);
    if (kids) {
        for (const kidRef of kids.asArray()) {
            const kid = doc.context.lookup(kidRef);
            if (kid instanceof PDFDict) collectNumberTree(doc, kid, out, depth + 1);
        }
    }
}

function computePageLabel(rules, pageIndex) {
    let rule = null;
    let rangeStart = 0;
    for (const [start, dict] of rules) {
        if (start <= pageIndex) { rule = dict; rangeStart = start; } else break;
    }
    if (!(rule instanceof PDFDict)) return null;

    const prefixObj = rule.get(N.P);
    const prefix = (prefixObj instanceof PDFString || prefixObj instanceof PDFHexString)
        ? prefixObj.asString() : '';

    const styleObj = rule.get(N.S);
    if (!(styleObj instanceof PDFName)) return prefix || null;

    const startObj = rule.lookupMaybe(N.St, PDFNumber);
    const start = startObj ? startObj.asNumber() : 1;
    const value = start + (pageIndex - rangeStart);
    const style = styleObj.asString().replace(/^\//, '');

    switch (style) {
        case 'D': return prefix + String(value);
        case 'R': return prefix + toRoman(value).toUpperCase();
        case 'r': return prefix + toRoman(value).toLowerCase();
        case 'A': return prefix + toAlpha(value).toUpperCase();
        case 'a': return prefix + toAlpha(value).toLowerCase();
        default: return prefix || null;
    }
}

function toRoman(n) {
    if (n <= 0) return String(n);
    const table = [[1000, 'M'], [900, 'CM'], [500, 'D'], [400, 'CD'], [100, 'C'],
        [90, 'XC'], [50, 'L'], [40, 'XL'], [10, 'X'], [9, 'IX'],
        [5, 'V'], [4, 'IV'], [1, 'I']];
    let out = '';
    let value = n;
    for (const [amount, numeral] of table) {
        while (value >= amount) { out += numeral; value -= amount; }
    }
    return out;
}

/* PDF alphabetic labels repeat the letter: A..Z, then AA, BB, CC — not AA, AB. */
function toAlpha(n) {
    if (n <= 0) return String(n);
    const letter = String.fromCharCode(65 + ((n - 1) % 26));
    return letter.repeat(Math.floor((n - 1) / 26) + 1);
}

/* ── Optional content (layers) ───────────────────────────────────────────── */

/* /OCProperties names the layers and stores their default visibility. The OCG
 * dictionaries themselves are referenced from page resources, so copyPages has
 * already brought them over — the copier resolves them through the
 * correspondence map. Deep-copying instead would create a second set of OCGs,
 * and the layer panel would control groups the content does not use.
 */
function preserveOptionalContent(destDoc, contexts, report, isMerge) {
    const withOC = contexts.filter((c) => c.doc.catalog.get(N.OCProperties));
    if (!withOC.length) return;

    const allOCGs = PDFArray.withContext(destDoc.context);
    const on = PDFArray.withContext(destDoc.context);
    const off = PDFArray.withContext(destDoc.context);
    const order = PDFArray.withContext(destDoc.context);
    let listed = 0;
    let pruned = 0;
    const carried = [];

    for (const ctx of withOC) {
        const src = ctx.doc.catalog.lookupMaybe(N.OCProperties, PDFDict);
        if (!src) continue;

        /* Only groups the selected pages actually reference. `usedOC` holds
         * SOURCE refs gathered by walking the selected pages, deliberately not
         * the correspondence map: a layer belonging to an excluded page is not
         * in the copier's output either, but the copier would happily make a
         * fresh copy of it here, carrying that page's layer name into a
         * document that does not contain the page. */
        const keep = (ref) => ref instanceof PDFRef && ctx.usedOC.has(ref.tag);

        const srcOCGs = src.lookupMaybe(N.OCGs, PDFArray);
        if (srcOCGs) {
            for (const ref of srcOCGs.asArray()) {
                if (!keep(ref)) { pruned += 1; continue; }
                const copied = ctx.copier.copy(ref);
                if (copied === null) { pruned += 1; continue; }
                allOCGs.push(copied);
                listed += 1;
            }
        }

        const config = src.lookupMaybe(N.D, PDFDict);
        if (!config) continue;

        for (const [key, target] of [[N.ON, on], [N.OFF, off]]) {
            const array = config.lookupMaybe(key, PDFArray);
            if (!array) continue;
            for (const ref of array.asArray()) {
                if (!keep(ref)) continue;
                const copied = ctx.copier.copy(ref);
                if (copied !== null) target.push(copied);
            }
        }

        const srcOrder = config.lookupMaybe(N.Order, PDFArray);
        if (srcOrder) {
            const filtered = filterOrderArray(destDoc, ctx, srcOrder, keep, 0);
            for (const entry of filtered) order.push(entry);
        }

        carried.push(ctx.label);
    }

    if (!allOCGs.size()) {
        push(report.dropped, 'Layers (/OCProperties)',
            'None of the document\'s optional-content groups are used by the ' +
            'pages in the output, so the layer configuration was removed. ' +
            'Keeping it would have listed layers that control nothing and named ' +
            'content that is not in this file.');
        return;
    }

    const config = PDFDict.withContext(destDoc.context);
    if (on.size()) config.set(N.ON, on);
    if (off.size()) config.set(N.OFF, off);
    if (order.size()) config.set(N.Order, order);
    const props = PDFDict.withContext(destDoc.context);
    props.set(N.OCGs, allOCGs);
    props.set(N.D, config);
    destDoc.catalog.set(N.OCProperties, destDoc.context.register(props));

    const detail = [`${listed} layer(s) carried across, still bound to the ` +
        `optional-content groups the page content references.`];
    if (pruned) {
        detail.push(`${pruned} layer(s) belonging to pages that are not in the ` +
            `output were removed — their names would otherwise have described ` +
            `content this document does not contain.`);
    }
    if (isMerge) {
        detail.push(`Layers from ${carried.length} documents were combined into ` +
            `one configuration; groups that shared a name across documents ` +
            `appear separately, because they are genuinely different groups.`);
    }
    push(pruned || isMerge ? report.rebuilt : report.preserved,
        'Layers (/OCProperties)', detail.join(' '));
}

/* /Order is a nested array mixing group references with label strings:
 * [ocgA, "Section", [ocgB, ocgC], ocgD]. Filtering has to keep the nesting,
 * drop groups that are gone, drop arrays that empty out, and drop a label whose
 * array emptied — otherwise the layer panel shows headings over nothing. */
function filterOrderArray(destDoc, ctx, array, keep, depth) {
    if (depth > 32) return [];
    const out = [];
    const items = array.asArray();

    for (let i = 0; i < items.length; i += 1) {
        const item = items[i];

        if (item instanceof PDFRef) {
            const target = ctx.doc.context.lookup(item);
            if (target instanceof PDFArray) {
                const nested = filterOrderArray(destDoc, ctx, target, keep, depth + 1);
                if (nested.length) {
                    const arr = PDFArray.withContext(destDoc.context);
                    for (const entry of nested) arr.push(entry);
                    out.push(arr);
                }
                continue;
            }
            if (!keep(item)) continue;
            const copied = ctx.copier.copy(item);
            if (copied !== null) out.push(copied);
            continue;
        }

        if (item instanceof PDFArray) {
            const nested = filterOrderArray(destDoc, ctx, item, keep, depth + 1);
            if (!nested.length) continue;
            const arr = PDFArray.withContext(destDoc.context);
            for (const entry of nested) arr.push(entry);
            out.push(arr);
            continue;
        }

        if (item instanceof PDFString || item instanceof PDFHexString) {
            // A label applies to the array that follows it; keep it only if that
            // array survives with something in it.
            const next = items[i + 1];
            const nextArray = next instanceof PDFArray ? next
                : (next instanceof PDFRef ? ctx.doc.context.lookup(next) : null);
            if (!(nextArray instanceof PDFArray)) continue;
            if (!filterOrderArray(destDoc, ctx, nextArray, keep, depth + 1).length) continue;
            out.push(ctx.copier.copy(item));
        }
    }
    return out;
}

/* ── Simple catalog entries ──────────────────────────────────────────────── */

function preserveSimpleCatalogEntries(destDoc, contexts, report, isMerge) {
    const primary = contexts[0];
    const carried = [];

    for (const key of [N.ViewerPreferences, N.PageLayout, N.PageMode, N.Lang]) {
        const value = primary.doc.catalog.get(key);
        if (value === undefined) continue;
        const copied = primary.copier.copy(value);
        if (copied !== null) {
            destDoc.catalog.set(key, copied);
            carried.push(key.asString().replace(/^\//, ''));
        }
    }

    // /OpenAction may target a page; the copier turns a reference to an excluded
    // page into null, in which case we simply do not set it.
    const openAction = primary.doc.catalog.get(N.OpenAction);
    if (openAction !== undefined) {
        const copied = primary.copier.copy(openAction);
        if (copied !== null) {
            destDoc.catalog.set(N.OpenAction, copied);
            carried.push('OpenAction');
        } else {
            push(report.dropped, 'Open action',
                'The document\'s open action pointed at a page that is not in ' +
                'the output and was removed.');
        }
    }

    if (carried.length) {
        push(report.preserved, 'Document attributes',
            `${carried.join(', ')} carried across` +
            `${isMerge ? ` from "${primary.label}"` : ''}.`);
    }
}

export const __testing = {
    computePageLabel, toRoman, toAlpha, readOutlineItems, filterOutlineItems,
};
