/* Security Buddy — PDF tools UI.
 *
 * The flow is deliberately ordered: a file is inspected the moment it is
 * chosen, and everything the user needs to decide with — encrypted, signed,
 * XFA, executable JavaScript, accessibility tagging that will be lost — is on
 * screen BEFORE any operation can be started. Nothing here is discovered by
 * attempting an operation and having it fail.
 *
 * Blocking findings disable the operations outright. Findings that need
 * acknowledgement must each be ticked before the run button becomes live.
 */

import { loadDocument, inspectDocument } from './preserve.js';
import * as shell from './shell.js';
import * as ops from './operations.js';
import { openForPreview, renderThumbnail, renderForPlacement } from './preview.js';
import * as viewer from './viewer.js';
import { listTextFields, planFill, fillForm } from './fill.js';
import { CATEGORIES, CHOOSABLE_CATEGORIES } from './fonts.js';
import { planOverlay, addOverlay } from './overlay.js';
import { classifyPage } from './pagetype.js';
import {
    readableRuns, runAtPoint, planReplacement, replaceText, runBox,
} from './replace.js';

const $ = (id) => document.getElementById(id);

const state = {
    docs: [],        // { name, size, bytes, doc, inspection, preflight, pdf }
    rejected: [],    // { name, reason, message }
    tool: 'merge',
    selection: new Set(),
    order: [],
    rotations: {},
    acknowledged: new Set(),
    outputs: [],
    fieldValues: {},
    placements: [],
    placementPage: 0,
    placementSeq: 0,
    edits: {},
    editPage: 0,
};

/* ── File intake ─────────────────────────────────────────────────────────── */

async function addFiles(fileList) {
    setBusy(true);
    for (const file of fileList) {
        if (state.docs.some((d) => d.name === file.name && d.size === file.size)) continue;
        const bytes = new Uint8Array(await file.arrayBuffer());
        const result = await loadDocument(bytes, file.name);

        if (!result.ok) {
            state.rejected.push({ name: file.name, reason: result.reason, message: result.message });
            continue;
        }

        const doc = result.doc;
        const entry = {
            name: file.name,
            size: file.size,
            bytes,
            doc,
            inspection: inspectDocument(doc),
            preflight: ops.preflight([{ doc, label: file.name }]),
            pdf: null,
        };
        state.docs.push(entry);
    }
    resetSelections();
    setBusy(false);
    render();
}

function resetSelections() {
    const primary = state.docs[0];
    const count = primary ? primary.doc.getPageCount() : 0;
    state.selection = new Set(Array.from({ length: count }, (_, i) => i));
    state.order = Array.from({ length: count }, (_, i) => i);
    state.rotations = {};
    state.outputs = [];
    state.fieldValues = {};
    state.placements = [];
    state.placementPage = 0;
    state.edits = {};
    state.editPage = 0;
}

/* ── Pre-flight gate ─────────────────────────────────────────────────────── */

function allBlocked() {
    return state.docs.flatMap((d) => d.preflight.blocked.map((e) => ({ ...e, file: d.name })));
}

function allConfirms() {
    return state.docs.flatMap((d) => d.preflight.confirm.map((e) => ({ ...e, file: d.name })));
}

const confirmKey = (entry) => `${entry.file}::${entry.item}`;


/* ── Rendering ───────────────────────────────────────────────────────────── */

/* The workbench replaces the tab panels: one document, kept open, with the
 * operations applied to it. Mounting happens once per loaded file — remounting
 * on every render would throw away the undo history and the scroll position. */
let mounted = null;

function render() {
    renderFiles();
    renderPreflight();
    const entry = state.docs[0];
    const usable = entry && !allBlocked().length;
    $('pdfWorkspace').hidden = !usable;
    // With a document open, the hero and the drop zone step aside: the document
    // is the page now, not one card among several on a marketing page.
    $('pdfHero').hidden = usable;
    $('pdfIntake').hidden = usable;
    $('pdfOpenBar').hidden = !usable;
    if (usable) $('pdfOpenName').textContent = entry.name;
    if (usable && mounted !== entry) {
        mounted = entry;
        shell.mount(entry.name, entry.bytes).catch((err) => {
            const box = $('pdfError');
            box.textContent = err?.message || String(err);
            box.hidden = false;
        });
    }
    if (!usable) mounted = null;
    if (window.lucide) window.lucide.createIcons();
}

function renderFiles() {
    const list = $('pdfFileList');
    list.textContent = '';

    for (const [index, entry] of state.docs.entries()) {
        const item = document.createElement('div');
        item.className = 'pdf-file';

        const main = document.createElement('div');
        main.className = 'pdf-file-main';
        const name = document.createElement('strong');
        name.textContent = entry.name;
        const meta = document.createElement('span');
        meta.className = 'pdf-file-meta';
        meta.textContent = `${entry.doc.getPageCount()} pages · ${formatSize(entry.size)}`;
        main.append(name, meta);

        const tags = document.createElement('div');
        tags.className = 'pdf-tags';
        for (const tag of describeContents(entry.inspection)) {
            const chip = document.createElement('span');
            chip.className = `pdf-tag pdf-tag-${tag.tone}`;
            chip.textContent = tag.label;
            tags.append(chip);
        }
        main.append(tags);

        const preview = document.createElement('button');
        preview.type = 'button';
        preview.className = 'pdf-icon-btn';
        preview.textContent = '⛶';
        preview.title = `Preview ${entry.name}`;
        preview.setAttribute('aria-label', `Preview ${entry.name} full screen`);
        preview.addEventListener('click', () => {
            const all = Array.from({ length: entry.doc.getPageCount() }, (_, i) => i);
            openViewerAt(entry, 'preview', all, 0);
        });

        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'pdf-icon-btn';
        remove.setAttribute('aria-label', `Remove ${entry.name}`);
        remove.textContent = '✕';
        remove.addEventListener('click', () => {
            state.docs.splice(index, 1);
            state.acknowledged.clear();
            resetSelections();
            render();
            renderThumbnails();
        });

        const controls = document.createElement('div');
        controls.className = 'pdf-file-controls';
        controls.append(preview, remove);
        item.append(main, controls);
        list.append(item);
    }

    for (const [index, entry] of state.rejected.entries()) {
        const item = document.createElement('div');
        item.className = 'pdf-file pdf-file-rejected';
        const main = document.createElement('div');
        main.className = 'pdf-file-main';
        const name = document.createElement('strong');
        name.textContent = entry.name;
        const why = document.createElement('span');
        why.className = 'pdf-file-meta';
        why.textContent = entry.message;
        main.append(name, why);

        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'pdf-icon-btn';
        remove.setAttribute('aria-label', `Dismiss ${entry.name}`);
        remove.textContent = '✕';
        remove.addEventListener('click', () => {
            state.rejected.splice(index, 1);
            render();
        });

        item.append(main, remove);
        list.append(item);
    }
}

function describeContents(inspection) {
    const tags = [];
    if (inspection.hasAcroForm) tags.push({ label: 'fillable form', tone: 'neutral' });
    if (inspection.hasOutlines) tags.push({ label: 'bookmarks', tone: 'neutral' });
    if (inspection.hasOCProperties) tags.push({ label: 'layers', tone: 'neutral' });
    if (inspection.hasEmbeddedFiles) tags.push({ label: 'attachments', tone: 'neutral' });
    if (inspection.hasStructTree) tags.push({ label: 'tagged (accessible)', tone: 'warn' });
    if (inspection.javaScript.length) tags.push({ label: 'runs JavaScript', tone: 'danger' });
    if (inspection.isSigned) tags.push({ label: 'digitally signed', tone: 'danger' });
    if (inspection.hasXFA) tags.push({ label: 'XFA form', tone: 'danger' });
    return tags;
}

/* Everything the user must see before choosing an operation. */
function renderPreflight() {
    const panel = $('pdfPreflight');
    panel.textContent = '';

    const blocked = allBlocked();
    const confirms = allConfirms();
    panel.hidden = blocked.length === 0 && confirms.length === 0;
    if (panel.hidden) return;

    for (const entry of blocked) {
        panel.append(noticeBox('block', entry, null));
    }

    for (const entry of confirms) {
        const key = confirmKey(entry);
        const box = noticeBox('confirm', entry, (checked) => {
            if (checked) state.acknowledged.add(key); else state.acknowledged.delete(key);
            render();
        });
        panel.append(box);
    }
}

function noticeBox(kind, entry, onToggle) {
    const box = document.createElement('div');
    box.className = `pdf-notice pdf-notice-${kind}`;

    const heading = document.createElement('div');
    heading.className = 'pdf-notice-head';
    heading.textContent = kind === 'block'
        ? `Cannot process: ${entry.item}`
        : entry.item;
    box.append(heading);

    if (state.docs.length > 1 && entry.file) {
        const file = document.createElement('div');
        file.className = 'pdf-notice-file';
        file.textContent = entry.file;
        box.append(file);
    }

    const detail = document.createElement('p');
    detail.className = 'pdf-notice-detail';
    detail.textContent = entry.detail;
    box.append(detail);

    if (onToggle) {
        const label = document.createElement('label');
        label.className = 'pdf-ack';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.checked = state.acknowledged.has(confirmKey(entry));
        input.addEventListener('change', () => onToggle(input.checked));
        const text = document.createElement('span');
        text.textContent = 'I understand — continue anyway';
        label.append(input, text);
        box.append(label);
    }

    return box;
}




/* The provenance badge, mapped one-to-one onto the states the engine produces.
 * No state is invented here: a badge that said something the engine did not
 * would be exactly the guessed "Arial 9pt" this is meant to replace. */
const PROVENANCE = {
    original:   { label: 'from the document', tone: 'doc' },
    USER:       { label: 'set by you',        tone: 'doc' },
    SUBSTITUTE: { label: 'substitute',        tone: 'sub' },
    ESTIMATED:  { label: 'estimated',         tone: 'est' },
    DEFAULT:    { label: 'default',           tone: 'est' },
};




/* ── The in-place editor ─────────────────────────────────────────────────── */

/* How long to wait after the last keystroke before redrawing the page.
 *
 * The redraw is not a mock-up: it applies the edit through the real engine and
 * renders the bytes that would be saved, so what is on screen is what the file
 * would contain. Measured at 3-7ms for the engine step on the test corpus, so
 * the delay is here to avoid redrawing mid-word, not because it is expensive. */
const PREVIEW_DELAY_MS = 200;

/* The open editor lives here rather than in `state` on purpose: `state` changes
 * go through renderTool(), which rebuilds the panel, and rebuilding the panel
 * while someone is typing takes the caret out of the field mid-word. */
let session = null;



































/* Open the viewer over the sequence the tool is currently showing, so a
 * reordered document is walked in the user's order and a page with a pending
 * rotation is previewed rotated. */
async function openViewerAt(entry, mode, sequence, position) {
    try {
        if (!entry.pdf) entry.pdf = await openForPreview(entry.bytes);
    } catch {
        return;
    }
    const pages = sequence.map((pageIndex, index) => ({
        pageIndex,
        label: mode === 'reorder'
            ? `Position ${index + 1} — was page ${pageIndex + 1}`
            : `Page ${pageIndex + 1}`,
        rotation: mode === 'rotate' ? (state.rotations[pageIndex] || 0) : 0,
    }));
    viewer.open(entry.pdf, pages, position, entry.name);
}

/* ── Thumbnails ──────────────────────────────────────────────────────────── */

async function renderThumbnails() {
    const entry = state.docs[0];
    if (!entry) return;
    const grid = $('pdfGrid');
    if (grid) paintThumbnails(entry, grid);
}

async function paintThumbnails(entry, grid) {
    try {
        if (!entry.pdf) entry.pdf = await openForPreview(entry.bytes);
        for (const canvas of grid.querySelectorAll('canvas.pdf-thumb')) {
            const pageNumber = Number(canvas.dataset.page);
            if (canvas.dataset.painted === '1') continue;
            canvas.dataset.painted = '1';
            renderThumbnail(entry.pdf, pageNumber, canvas, 130).catch(() => {
                canvas.dataset.painted = '';
            });
        }
    } catch {
        // A preview that will not render is not a reason to block an operation:
        // the operations never depend on pdf.js. Leave the placeholders.
    }
}




/* The fidelity report. `dropped` is the reason this exists: everything the
 * operation could not carry across, named, rather than lost quietly. */
export function reportBlock(report) {
    const sections = [
        ['dropped', 'Not carried across', 'danger'],
        ['rebuilt', 'Rebuilt', 'warn'],
        ['preserved', 'Preserved', 'ok'],
    ].filter(([key]) => report[key].length);

    const details = document.createElement('details');
    details.className = 'pdf-report';
    // Open by default when something was lost: that is not a footnote.
    details.open = report.dropped.length > 0;

    const summary = document.createElement('summary');
    const counts = sections.map(([key, label]) => `${report[key].length} ${label.toLowerCase()}`);
    summary.textContent = `What happened to the document — ${counts.join(', ')}`;
    details.append(summary);

    for (const [key, label, tone] of sections) {
        const group = document.createElement('div');
        group.className = 'pdf-report-group';
        const title = document.createElement('h4');
        title.className = `pdf-report-title pdf-report-${tone}`;
        title.textContent = label;
        group.append(title);

        const list = document.createElement('ul');
        for (const entry of report[key]) {
            const item = document.createElement('li');
            const name = document.createElement('strong');
            name.textContent = entry.item;
            const detail = document.createElement('span');
            detail.textContent = ` — ${entry.detail}`;
            item.append(name, detail);
            list.append(item);
        }
        group.append(list);
        details.append(group);
    }

    return details;
}


function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function setBusy(busy) {
    $('pdfBusy').hidden = !busy;
}

/* ── Wiring ──────────────────────────────────────────────────────────────── */

export function init() {
    const input = $('pdfFileInput');
    const drop = $('pdfDropZone');

    $('pdfOpenAnother').addEventListener('click', () => {
        $('pdfHero').hidden = false;
        $('pdfIntake').hidden = false;
        $('pdfOpenBar').hidden = true;
        $('pdfIntake').scrollIntoView({ behavior: 'smooth', block: 'center' });
        input.click();
    });

    input.addEventListener('change', () => {
        if (input.files?.length) addFiles([...input.files]);
        input.value = '';
    });

    drop.addEventListener('dragover', (event) => {
        event.preventDefault();
        drop.classList.add('pdf-drop-over');
    });
    drop.addEventListener('dragleave', () => drop.classList.remove('pdf-drop-over'));
    drop.addEventListener('drop', (event) => {
        event.preventDefault();
        drop.classList.remove('pdf-drop-over');
        const files = [...(event.dataTransfer?.files || [])]
            .filter((f) => f.type === 'application/pdf' || /\.pdf$/i.test(f.name));
        if (files.length) addFiles(files);
    });

    render();
}
