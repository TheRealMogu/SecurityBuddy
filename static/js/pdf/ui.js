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
    renderThumbnails();
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

function canRun() {
    if (!state.docs.length) return false;
    if (allBlocked().length) return false;
    return allConfirms().every((entry) => state.acknowledged.has(confirmKey(entry)));
}

/* ── Rendering ───────────────────────────────────────────────────────────── */

function render() {
    renderFiles();
    renderPreflight();
    renderTool();
    renderOutputs();
    $('pdfWorkspace').hidden = state.docs.length === 0 && state.rejected.length === 0;
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
            renderTool();
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

/* ── Tool panels ─────────────────────────────────────────────────────────── */

function renderTool() {
    // The panel is about to be thrown away, so any in-place editor attached to
    // it goes too: a pending preview would otherwise redraw a detached canvas
    // and hold its pdf.js document open.
    closeSession();
    for (const button of document.querySelectorAll('[data-tool]')) {
        const active = button.dataset.tool === state.tool;
        button.classList.toggle('pdf-tab-active', active);
        button.setAttribute('aria-selected', String(active));
    }

    const panel = $('pdfToolPanel');
    panel.textContent = '';

    if (!state.docs.length) {
        panel.append(hint('Add a PDF to begin.'));
        return;
    }

    const blocked = allBlocked();
    if (blocked.length) {
        panel.append(hint('The findings above prevent this file from being processed. '
            + 'Remove it to continue with the others.'));
        return;
    }

    switch (state.tool) {
        case 'merge': renderMergePanel(panel); break;
        case 'extract': renderPagePanel(panel, 'extract'); break;
        case 'reorder': renderPagePanel(panel, 'reorder'); break;
        case 'rotate': renderPagePanel(panel, 'rotate'); break;
        case 'fill': renderFillPanel(panel); break;
        case 'text': renderTextPanel(panel); break;
        case 'edit': renderEditPanel(panel); break;
        default: break;
    }
}

function hint(text) {
    const p = document.createElement('p');
    p.className = 'pdf-hint';
    p.textContent = text;
    return p;
}

/* ── Recognised-text outlines ────────────────────────────────────────────── */

/* Draw a light box around every run the extractor found, before any click.
 *
 * This replaces "click somewhere and hope there is text nearby" with a direct
 * answer to "what does this tool see on the page". The geometry comes from
 * runBox(): a MEASURED width from the font's own /Widths, and a height derived
 * from the type size for drawing only.
 *
 * `mode` decides what a box means. In 'edit' a box is a target — clicking it
 * replaces those words. In 'add' a box is a warning — the text there stays, and
 * anything typed lands on top of it.
 */
function drawRunBoxes(container, viewport, runs, mode, selectedId) {
    for (const run of runs) {
        const box = runBox(run);
        if (box.width <= 0) continue;

        const [x1, y1] = viewport.convertToViewportPoint(box.x, box.top);
        const [x2, y2] = viewport.convertToViewportPoint(box.x + box.width, box.bottom);

        const el = document.createElement('span');
        el.className = `pdf-run-box pdf-run-box-${mode}`;
        if (run.id === selectedId) el.classList.add('pdf-run-box-sel');
        el.style.left = `${Math.min(x1, x2)}px`;
        el.style.top = `${Math.min(y1, y2)}px`;
        el.style.width = `${Math.abs(x2 - x1)}px`;
        el.style.height = `${Math.abs(y2 - y1)}px`;
        el.title = mode === 'edit'
            ? `${run.text} — ${run.font.name} ${run.size}pt`
            : `Existing text: ${run.text}`;
        container.append(el);
    }
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

function provenanceBadge(source, face, size) {
    const entry = PROVENANCE[source] ?? { label: source, tone: 'sub' };
    const badge = document.createElement('span');
    badge.className = `pdf-prov pdf-prov-${entry.tone}`;

    const dot = document.createElement('span');
    dot.className = 'pdf-prov-dot';
    const name = document.createElement('span');
    name.className = 'pdf-prov-face';
    name.textContent = face ?? '—';
    const sep = document.createElement('span');
    sep.className = 'pdf-prov-sep';
    sep.textContent = '·';
    const src = document.createElement('span');
    src.className = 'pdf-prov-src';
    src.textContent = size ? `${entry.label} · ${size}pt` : entry.label;

    badge.append(dot, name, sep, src);
    return badge;
}

/* Which mechanism is in play, stated rather than left to be inferred. */
function mechanismChip(mode) {
    const chip = document.createElement('span');
    chip.className = `pdf-mech pdf-mech-${mode === 'edit' ? 'rep' : 'add'}`;
    chip.textContent = mode === 'edit' ? 'Replaces the text' : 'Adds on top';
    chip.title = mode === 'edit'
        ? 'The old words are removed from the file, and the page\'s content stream is rewritten.'
        : 'The page keeps its bytes exactly; the new text goes into a stream alongside them.';
    return chip;
}

/* ── Editing text already on the page ────────────────────────────────────── */

/* Click a word to change it. This is the one tool that rewrites the page's own
 * content stream, and the one where a substitute font is refused rather than
 * offered: half a line in a different face would not match the words either
 * side of it. */
function renderEditPanel(panel) {
    const entry = state.docs[0];
    const pageCount = entry.doc.getPageCount();

    if (pageCount > 1) {
        const bar = document.createElement('div');
        bar.className = 'pdf-actions-bar';
        for (let i = 0; i < pageCount; i += 1) {
            const button = smallButton(`Page ${i + 1}`, () => {
                state.editPage = i;
                renderTool();
            });
            if (i === state.editPage) button.classList.add('pdf-small-btn-active');
            bar.append(button);
        }
        panel.append(bar);
    }

    let runs = [];
    try {
        runs = readableRuns(entry.doc, entry.doc.getPage(state.editPage));
    } catch {
        panel.append(hint('The text on this page could not be read.'));
        return;
    }

    if (!runs.length) {
        panel.append(hint('No editable text was found on this page. A scanned page has no '
            + 'text to change — use "Add text" to write over it instead.'));
        return;
    }

    const contextBar = document.createElement('div');
    contextBar.className = 'pdf-context-bar';
    panel.append(contextBar);

    panel.append(hint('Click any outlined text to put the cursor in it and type. The page '
        + 'below redraws with the real replacement as you go — the font is the document\'s '
        + 'own, and nothing after the text moves, so a longer replacement runs on and a '
        + 'shorter one leaves a gap. Esc undoes the piece you are in, Tab moves to the next.'));

    const stage = document.createElement('div');
    stage.className = 'pdf-place-stage';
    const canvas = document.createElement('canvas');
    canvas.className = 'pdf-place-canvas';
    const markers = document.createElement('div');
    markers.className = 'pdf-place-markers';
    const layer = document.createElement('div');
    layer.className = 'pdf-edit-layer';
    stage.append(canvas, markers, layer);
    panel.append(stage);

    const notes = document.createElement('div');
    notes.className = 'pdf-edit-notes';
    panel.append(notes);

    session = {
        entry, runs, canvas, markers, layer, stage, contextBar, notes,
        pageIndex: state.editPage,
        viewport: null, pdf: null, field: null, activeId: null,
        token: 0, timer: 0, history: [],
    };
    startSession();

    panel.append(runButton('Save PDF with the changed text', async (button) => {
        commitField();
        await runOperation(button, async () => {
            const edits = collectEdits();
            if (!edits.length) throw new Error('Change the wording of at least one piece of text.');
            const { bytes, report, written } = await replaceText(entry.doc, entry.name, edits);
            return [{
                name: ops.outputName(entry.name, 'edited'),
                bytes, report,
                summary: `${written.length} piece(s) of text replaced`,
            }];
        });
    }));
}

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

function closeSession() {
    if (!session) return;
    clearTimeout(session.timer);
    session.pdf?.destroy?.();
    session = null;
}

async function startSession() {
    const s = session;
    try {
        if (!s.entry.pdf) s.entry.pdf = await openForPreview(s.entry.bytes);
        s.viewport = await renderForPlacement(s.entry.pdf, s.pageIndex + 1, s.canvas, 520);
    } catch {
        s.stage.append(hint('This page could not be rendered.'));
        return;
    }
    if (session !== s) return;

    s.stage.addEventListener('mousedown', (event) => {
        if (event.target === s.field) return;
        const rect = s.canvas.getBoundingClientRect();
        const [x, y] = s.viewport.convertToPdfPoint(
            event.clientX - rect.left, event.clientY - rect.top);
        const run = runAtPoint(s.runs, x, y);
        event.preventDefault();          // keep the click from stealing focus first
        if (run) openField(run);
        else commitField();
    });

    paintSurface();
}

/* The rectangle a run's field sits in. While a run is being edited the width
 * follows the REPLACEMENT, not the original, so the box grows with what is
 * typed and running past where the original ended is visible as it happens. */
function fieldRect(run) {
    const s = session;
    const box = runBox(run);
    let width = box.width;
    const edit = state.edits[run.id];
    if (edit && edit.text) {
        try {
            const plan = planReplacement(s.entry.doc, s.entry.doc.getPage(s.pageIndex),
                                        run, edit.text);
            if (!plan.blocked && plan.newWidth > 0) width = plan.newWidth;
        } catch { /* an unplannable edit keeps the original width */ }
    }
    const [x1, y1] = s.viewport.convertToViewportPoint(box.x, box.top);
    const [x2, y2] = s.viewport.convertToViewportPoint(box.x + width, box.bottom);
    return {
        left: Math.min(x1, x2), top: Math.min(y1, y2),
        width: Math.max(Math.abs(x2 - x1), 8), height: Math.abs(y2 - y1),
    };
}

function openField(run) {
    const s = session;
    if (s.activeId === run.id) { s.field?.focus(); return; }
    commitField();

    if (!state.edits[run.id]) {
        state.edits[run.id] = { pageIndex: s.pageIndex, text: run.text, original: run.text };
    }
    s.activeId = run.id;

    const field = document.createElement('input');
    field.type = 'text';
    field.className = 'pdf-edit-field';
    field.value = state.edits[run.id].text;
    field.spellcheck = false;
    field.style.fontSize = `${run.size * s.viewport.scale}px`;

    field.addEventListener('input', () => {
        state.edits[run.id].text = field.value;
        // Opaque again the moment a key lands: the rendering underneath is now
        // one keystroke out of date, and showing it as if it were current is
        // the one thing this preview must never do.
        field.classList.remove('pdf-edit-field-live');
        positionField();
        schedulePreview();
    });
    field.addEventListener('keydown', onFieldKey);
    field.addEventListener('blur', () => { field.classList.remove('pdf-edit-field-live'); });

    s.field = field;
    s.layer.append(field);
    positionField();
    field.focus();
    field.select();
    paintSurface();
    schedulePreview();
}

function positionField() {
    const s = session;
    if (!s?.field) return;
    const run = s.runs.find((r) => r.id === s.activeId);
    if (!run) return;
    const rect = fieldRect(run);
    s.field.style.left = `${rect.left}px`;
    s.field.style.top = `${rect.top}px`;
    s.field.style.width = `${rect.width + 2}px`;
    s.field.style.height = `${rect.height}px`;
}

function onFieldKey(event) {
    const s = session;
    if (event.key === 'Escape') {
        event.preventDefault();
        revertActive();
        return;
    }
    if (event.key === 'Enter') {
        event.preventDefault();
        commitField();
        paintSurface();
        return;
    }
    if (event.key === 'Tab') {
        event.preventDefault();
        const order = s.runs.findIndex((r) => r.id === s.activeId);
        const next = s.runs[order + (event.shiftKey ? -1 : 1)];
        commitField();
        if (next) openField(next); else paintSurface();
        return;
    }
    // Ctrl/Cmd-Z inside the field is the browser's own undo, which fires an
    // input event, so the edit state follows it without special handling. Only
    // an undo with nothing left to undo in the field reaches back to the
    // previous run's committed text.
    if ((event.ctrlKey || event.metaKey) && event.key === 'z' && !event.shiftKey
        && s.field.value === (state.edits[s.activeId]?.original ?? '')) {
        event.preventDefault();
        undoLastCommit();
    }
}

function revertActive() {
    const s = session;
    const id = s.activeId;
    if (id === null) return;
    const original = state.edits[id]?.original;
    delete state.edits[id];
    s.field?.remove();
    s.field = null;
    s.activeId = null;
    if (original !== undefined) s.notes.textContent = '';
    paintSurface();
    schedulePreview();
}

function commitField() {
    const s = session;
    if (!s?.field) return;
    const id = s.activeId;
    const edit = state.edits[id];
    if (edit) {
        if (edit.text === edit.original) delete state.edits[id];
        else s.history.push({ id, text: edit.text, previous: edit.original });
    }
    s.field.remove();
    s.field = null;
    s.activeId = null;
}

function undoLastCommit() {
    const s = session;
    const last = s.history.pop();
    if (!last) return;
    delete state.edits[last.id];
    paintSurface();
    schedulePreview();
}

function collectEdits() {
    return Object.entries(state.edits)
        .filter(([, value]) => value && value.text && value.text.trim() !== ''
                            && value.text !== value.original)
        .map(([id, value]) => ({
            pageIndex: value.pageIndex, runId: Number(id), newText: value.text,
        }));
}

/* Redraw the page from the real engine output. */
function schedulePreview() {
    const s = session;
    clearTimeout(s.timer);
    s.timer = setTimeout(() => { refreshPreview(); }, PREVIEW_DELAY_MS);
}

async function refreshPreview() {
    const s = session;
    const token = ++s.token;
    const edits = collectEdits();

    let bytes = s.entry.bytes;
    if (edits.length) {
        try {
            ({ bytes } = await replaceText(s.entry.doc, s.entry.name, edits));
        } catch (err) {
            // A refused edit is shown as a refusal, and the page keeps showing
            // the last thing that was actually true.
            if (session !== s || token !== s.token) return;
            const blocked = err.blocked?.[0];
            showNotes(blocked
                ? [{ tone: 'block', title: 'This font cannot write that text', body: blocked.explain }]
                : [{ tone: 'block', title: 'This change could not be applied', body: err.message }]);
            return;
        }
    }
    if (session !== s || token !== s.token) return;

    try {
        const pdf = await openForPreview(bytes);
        const viewport = await renderForPlacement(pdf, s.pageIndex + 1, s.canvas, 520);
        if (session !== s || token !== s.token) { pdf.destroy?.(); return; }
        s.pdf?.destroy?.();
        s.pdf = pdf;
        s.viewport = viewport;
    } catch {
        return;                       // keep the last good rendering on screen
    }

    // What is on the canvas now IS the replacement, so the field stops painting
    // its own copy of the text and leaves only the caret.
    if (s.field && document.activeElement === s.field) {
        s.field.classList.add('pdf-edit-field-live');
    }
    paintSurface();
}

/* The outlines, the context bar and the notes, all from current state. */
function paintSurface() {
    const s = session;
    if (!s?.viewport) return;

    s.markers.textContent = '';
    drawRunBoxes(s.markers, s.viewport, s.runs, 'edit', s.activeId);
    positionField();

    const run = s.runs.find((r) => r.id === s.activeId);
    s.contextBar.textContent = '';
    s.contextBar.append(mechanismChip('edit'));
    if (run) {
        s.contextBar.append(provenanceBadge('original', run.font.name, run.size));
    } else {
        const idle = document.createElement('span');
        idle.className = 'pdf-context-idle';
        const changed = collectEdits().length;
        idle.textContent = changed
            ? `${changed} piece(s) changed — click another to keep going, or save`
            : `${s.runs.length} pieces of text found on this page — click one to change it`;
        s.contextBar.append(idle);
    }

    if (!run) { showNotes([]); return; }
    const edit = state.edits[run.id];
    if (!edit || edit.text === edit.original) { showNotes([]); return; }

    let plan = null;
    try {
        plan = planReplacement(s.entry.doc, s.entry.doc.getPage(s.pageIndex), run, edit.text);
    } catch { /* reported by the preview instead */ }
    if (!plan) { showNotes([]); return; }
    if (plan.blocked) {
        showNotes([{ tone: 'block', title: 'This font cannot write that text', body: plan.explain }]);
        return;
    }
    showNotes([
        { tone: 'info', title: `Stays in ${plan.face} at ${plan.size}pt`,
          body: `${plan.oldWidth}pt wide before, ${plan.newWidth}pt after.` },
        ...plan.notes.map((note) => ({ tone: 'warn', title: 'Worth knowing', body: note })),
    ]);
}

function showNotes(items) {
    const s = session;
    s.notes.textContent = '';
    for (const item of items) {
        const box = document.createElement('div');
        box.className = `pdf-field-note pdf-edit-note-${item.tone}`;
        const head = document.createElement('strong');
        head.textContent = item.title;
        const body = document.createElement('span');
        body.textContent = item.body;
        box.append(head, body);
        s.notes.append(box);
    }
}

/* ── Free text overlay ───────────────────────────────────────────────────── */

/* Click a page to place text. Every placement shows where its size and typeface
 * came from and lets the user change both BEFORE anything is written — an
 * estimate the user cannot correct is just a guess they have been told about. */
function renderTextPanel(panel) {
    const entry = state.docs[0];
    const pageCount = entry.doc.getPageCount();

    if (state.docs.length > 1) {
        panel.append(hint(`This tool works on one document. Using "${entry.name}".`));
    }

    if (pageCount > 1) {
        const bar = document.createElement('div');
        bar.className = 'pdf-actions-bar';
        for (let i = 0; i < pageCount; i += 1) {
            const button = smallButton(`Page ${i + 1}`, () => {
                state.placementPage = i;
                renderTool();
            });
            if (i === state.placementPage) button.classList.add('pdf-small-btn-active');
            bar.append(button);
        }
        panel.append(bar);
    }

    const contextBar = document.createElement('div');
    contextBar.className = 'pdf-context-bar';
    paintPlacementContext(entry, contextBar);
    panel.append(contextBar);

    // An OCR layer is text the page has and the user cannot see: it draws no
    // ink, so nothing outlines it and nothing is clickable, yet it is there and
    // it is what a copy-and-paste or a search will find. Saying so is the point
    // — an outline that is simply absent reads as "no text here", which on this
    // page is the opposite of the truth.
    const hidden = hiddenTextLayer(entry.doc, state.placementPage);
    if (hidden) {
        panel.append(verdictBox(
            'This page carries an invisible text layer',
            `${hidden} text operation(s) on this page are drawn in an invisible render `
            + 'mode — the signature of an OCR layer under a scan. That text is not '
            + 'outlined and cannot be clicked, because there is no ink to point at, but '
            + 'it is in the file and a search or a copy-and-paste will find it. Anything '
            + 'you add here is written on top of it and leaves it in place.'));
    }

    panel.append(hint('Click the page where the text should start. The click point is '
        + 'the left end of the text baseline. Text already on the page is outlined: '
        + 'anything placed over it is added on top, and the original stays.'));

    const stage = document.createElement('div');
    stage.className = 'pdf-place-stage';
    const canvas = document.createElement('canvas');
    canvas.className = 'pdf-place-canvas';
    const markers = document.createElement('div');
    markers.className = 'pdf-place-markers';
    stage.append(canvas, markers);
    panel.append(stage);

    paintPlacementSurface(entry, canvas, markers, stage);

    const list = document.createElement('div');
    list.className = 'pdf-fields';
    panel.append(list);
    renderPlacementCards(entry, list, contextBar);

    panel.append(runButton('Save PDF with the added text', async (button) => {
        await runOperation(button, async () => {
            const ready = state.placements.filter((p) => p.text && p.text.trim() !== '');
            if (!ready.length) throw new Error('Place at least one piece of text.');
            const { bytes, report, written } = await addOverlay(entry.doc, entry.name, ready);
            const estimated = written.filter((w) =>
                w.fontSource === 'ESTIMATED' || w.fontSource === 'DEFAULT').length;
            return [{
                name: ops.outputName(entry.name, 'text'),
                bytes, report,
                summary: `${written.length} text placement(s)`
                    + (estimated ? `, ${estimated} using an estimated or default size` : ''),
            }];
        });
    }));
}

async function paintPlacementSurface(entry, canvas, markers, stage) {
    try {
        if (!entry.pdf) entry.pdf = await openForPreview(entry.bytes);
        const viewport = await renderForPlacement(
            entry.pdf, state.placementPage + 1, canvas, 520);
        stage.dataset.ready = '1';

        stage.addEventListener('click', (event) => {
            const rect = canvas.getBoundingClientRect();
            // pdf.js converts canvas pixels back to PDF user space, rotation
            // included; doing this arithmetic by hand is how a placement ends
            // up mirrored on a rotated page.
            const [x, y] = viewport.convertToPdfPoint(
                event.clientX - rect.left, event.clientY - rect.top);
            state.placementSeq += 1;
            state.placements.push({
                id: state.placementSeq,
                pageIndex: state.placementPage,
                x: Math.round(x * 10) / 10,
                y: Math.round(y * 10) / 10,
                text: '',
            });
            renderTool();
        });

        markers.textContent = '';
        // The same measured boxes as the edit tab, drawn as a caution rather
        // than a target: this text stays, and anything typed lands over it.
        try {
            const runs = readableRuns(entry.doc, entry.doc.getPage(state.placementPage));
            drawRunBoxes(markers, viewport, runs, 'add', null);
        } catch { /* a page whose text cannot be read simply gets no outlines */ }
        drawMarkers(markers, viewport);
    } catch {
        stage.append(hint('This page could not be rendered for placement.'));
    }
}

function drawMarkers(container, viewport) {
    for (const placement of state.placements) {
        if (placement.pageIndex !== state.placementPage) continue;
        const [vx, vy] = viewport.convertToViewportPoint(placement.x, placement.y);
        const dot = document.createElement('span');
        dot.className = 'pdf-place-marker';
        dot.style.left = `${vx}px`;
        dot.style.top = `${vy}px`;
        dot.textContent = String(placement.id);
        container.append(dot);
    }
}

/* One card per placement: the text, and the two values the user may override. */
/* Text the page draws in an invisible render mode, counted from the same
 * signals the TYPE A / TYPE B classifier already computes — no second reading
 * of the content stream, and no separate idea of what "invisible" means. */
function hiddenTextLayer(doc, pageIndex) {
    try {
        const { signals } = classifyPage(doc, doc.getPage(pageIndex));
        const invisible = signals.textOps - signals.visibleTextOps;
        return invisible > 0 && signals.visibleTextOps === 0 ? invisible : 0;
    } catch {
        return 0;
    }
}

/* The overlay context bar. Kept separate from the panel because a placement's
 * font is only decided once there is text to write with it: the badge has to be
 * repainted on every keystroke, and rebuilding the whole panel would take the
 * focus out of the field being typed into. */
function paintPlacementContext(entry, bar) {
    bar.textContent = '';
    bar.append(mechanismChip('add'));
    const last = [...state.placements].reverse()
        .find((p) => p.pageIndex === state.placementPage && p.text);
    let plan = null;
    try {
        plan = last ? planOverlay(entry.doc, [last]).plans[0] : null;
    } catch { /* a placement the planner refuses simply gets no badge */ }
    if (plan) {
        bar.append(provenanceBadge(plan.source, plan.face ?? plan.font?.name, plan.size));
    } else {
        const idle = document.createElement('span');
        idle.className = 'pdf-context-idle';
        idle.textContent = state.placements.length
            ? 'Type the text — the font is read from the spot you clicked'
            : 'Click the page to place text — the font is read from that spot';
        bar.append(idle);
    }
}

function renderPlacementCards(entry, list, bar) {
    list.textContent = '';
    if (bar) paintPlacementContext(entry, bar);
    if (!state.placements.length) return;

    let plans = [];
    let blocked = [];
    try {
        ({ plans, blocked } = planOverlay(
            entry.doc, state.placements.filter((p) => p.text && p.text.trim() !== '')));
    } catch { /* an unreadable page simply yields no plan */ }

    const planFor = new Map(plans.map((p) => [p.placement.id, p]));
    const blockedFor = new Map(blocked.map((b) => [b.placement.id, b]));

    for (const placement of state.placements) {
        const plan = planFor.get(placement.id);
        const stop = blockedFor.get(placement.id);

        const card = document.createElement('div');
        card.className = 'pdf-field';
        if (stop) card.classList.add('pdf-field-block');
        else if (plan && (plan.source === 'ESTIMATED' || plan.source === 'DEFAULT'
                          || plan.source === 'SUBSTITUTE')) card.classList.add('pdf-field-warn');

        const head = document.createElement('div');
        head.className = 'pdf-place-head';
        const title = document.createElement('span');
        title.className = 'pdf-field-label';
        title.textContent = `#${placement.id} — page ${placement.pageIndex + 1} `
            + `at ${placement.x}, ${placement.y}`;
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'pdf-icon-btn';
        remove.textContent = '✕';
        remove.setAttribute('aria-label', `Remove placement ${placement.id}`);
        remove.addEventListener('click', () => {
            state.placements = state.placements.filter((p) => p.id !== placement.id);
            renderTool();
        });
        head.append(title, remove);
        card.append(head);

        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'pdf-field-input';
        input.value = placement.text;
        input.placeholder = 'Text to add';
        input.addEventListener('input', () => {
            placement.text = input.value;
            renderPlacementCards(entry, list, bar);
        });
        card.append(input);

        if (stop) {
            card.append(verdictBox('Cannot write this text here', stop.explain));
            list.append(card);
            continue;
        }

        if (plan) card.append(correctionControls(entry, list, bar, placement, plan));
        list.append(card);
    }

    // Keep focus where the user was typing.
    const active = list.querySelector('input[data-focus="1"]');
    if (active) active.focus();
}

/* The controls that make an estimate correctable rather than merely announced. */
function correctionControls(entry, list, bar, placement, plan) {
    const wrap = document.createElement('div');
    wrap.className = 'pdf-correct';

    const ORIGIN = {
        original: ['from the document', 'ok'],
        SUBSTITUTE: ['substitute font', 'warn'],
        ESTIMATED: ['ESTIMATED from the OCR layer', 'warn'],
        DEFAULT: ['DEFAULT — no signal in the document', 'warn'],
        USER: ['set by you', 'ok'],
    };
    const [originLabel, tone] = ORIGIN[plan.source] ?? [plan.source, 'warn'];

    const badge = document.createElement('span');
    badge.className = `pdf-origin pdf-origin-${tone}`;
    badge.textContent = originLabel;
    wrap.append(badge);

    const row = document.createElement('div');
    row.className = 'pdf-correct-row';

    const sizeLabel = document.createElement('label');
    sizeLabel.textContent = 'Size';
    const size = document.createElement('input');
    size.type = 'number';
    size.min = '4';
    size.max = '96';
    size.step = '0.5';
    size.className = 'pdf-correct-num';
    size.value = String(placement.sizeOverride ?? plan.size);
    size.addEventListener('change', () => {
        const value = parseFloat(size.value);
        placement.sizeOverride = Number.isFinite(value) ? value : undefined;
        renderPlacementCards(entry, list, bar);
    });
    sizeLabel.append(size);

    const catLabel = document.createElement('label');
    catLabel.textContent = 'Typeface';
    const category = document.createElement('select');
    category.className = 'pdf-correct-select';
    for (const key of CHOOSABLE_CATEGORIES) {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = CATEGORIES[key].label;
        option.selected = key === (placement.categoryOverride ?? plan.category);
        category.append(option);
    }
    category.addEventListener('change', () => {
        placement.categoryOverride = category.value;
        renderPlacementCards(entry, list, bar);
    });
    catLabel.append(category);

    row.append(sizeLabel, catLabel);

    if (placement.sizeOverride !== undefined || placement.categoryOverride !== undefined) {
        const reset = document.createElement('button');
        reset.type = 'button';
        reset.className = 'pdf-small-btn';
        reset.textContent = 'Use the document\'s value';
        reset.addEventListener('click', () => {
            delete placement.sizeOverride;
            delete placement.categoryOverride;
            renderPlacementCards(entry, list, bar);
        });
        row.append(reset);
    }
    wrap.append(row);

    const summary = document.createElement('p');
    summary.className = 'pdf-correct-summary';
    summary.textContent = `Will be written in ${plan.face ?? plan.font?.name} `
        + `at ${plan.size}pt (${CATEGORIES[plan.category]?.label ?? plan.category}).`;
    wrap.append(summary);

    if (plan.explain) {
        const note = document.createElement('p');
        note.className = 'pdf-correct-note';
        note.textContent = plan.explain;
        wrap.append(note);
    }
    return wrap;
}

/* ── Fill form ───────────────────────────────────────────────────────────── */

/* Each field carries its own font verdict, updated as the user types. The
 * warning belongs beside the field it applies to — a substitution announced in
 * a summary at the bottom is a substitution the user will not connect to
 * anything. */
function renderFillPanel(panel) {
    const entry = state.docs[0];

    if (state.docs.length > 1) {
        panel.append(hint(`This tool works on one document. Using "${entry.name}"; `
            + 'remove the others or switch to Merge.'));
    }

    let fields = [];
    try {
        fields = listTextFields(entry.doc);
    } catch (err) {
        panel.append(hint('The form in this document could not be read: ' + err.message));
        return;
    }

    if (!fields.length) {
        panel.append(hint('This PDF has no fillable text fields. '
            + 'Free text anywhere on the page is a separate tool, not yet available.'));
        return;
    }

    const list = document.createElement('div');
    list.className = 'pdf-fields';

    for (const field of fields) {
        const row = document.createElement('div');
        row.className = 'pdf-field';

        const label = document.createElement('label');
        label.className = 'pdf-field-label';
        label.setAttribute('for', `fld-${field.name}`);
        label.textContent = field.name;

        const meta = document.createElement('span');
        meta.className = 'pdf-field-meta';
        const face = field.font?.name ?? 'no font declared';
        const category = CATEGORIES[field.font?.category]?.label ?? 'unknown';
        meta.textContent = `page ${field.pageIndex + 1} · ${face} · ${category}`
            + (field.font?.subset ? ' · subset' : '');

        const input = document.createElement('input');
        input.type = 'text';
        input.id = `fld-${field.name}`;
        input.className = 'pdf-field-input';
        input.value = state.fieldValues[field.name] ?? field.currentValue ?? '';
        input.placeholder = field.currentValue ? '' : 'Leave empty to keep unchanged';

        const verdict = document.createElement('div');
        verdict.className = 'pdf-field-verdict';

        input.addEventListener('input', () => {
            state.fieldValues[field.name] = input.value;
            updateVerdicts(entry, list);
        });

        row.append(label, meta, input, verdict);
        row.dataset.field = field.name;
        list.append(row);
    }

    panel.append(list);
    updateVerdicts(entry, list);

    panel.append(runButton('Save filled PDF', async (button) => {
        await runOperation(button, async () => {
            const values = Object.fromEntries(
                Object.entries(state.fieldValues).filter(([, v]) => v && v.trim() !== ''));
            if (!Object.keys(values).length) throw new Error('Type a value into at least one field.');
            const { bytes, report, written } = await fillForm(entry.doc, entry.name, values);
            const substituted = written.filter((w) => w.fontSource === 'SUBSTITUTE').length;
            return [{
                name: ops.outputName(entry.name, 'filled'),
                bytes, report,
                summary: `${written.length} field(s) filled`
                    + (substituted ? `, ${substituted} with a substitute font` : ''),
            }];
        });
    }));
}

/* Recompute every field's verdict against what is currently typed. */
function updateVerdicts(entry, list) {
    const values = Object.fromEntries(
        Object.entries(state.fieldValues).filter(([, v]) => v && v.trim() !== ''));

    let plan = { plans: [], blocked: [] };
    try {
        plan = planFill(entry.doc, values);
    } catch {
        return;
    }

    const byField = new Map(plan.plans.map((p) => [p.name, p]));
    const blockedBy = new Map(plan.blocked.map((b) => [b.field, b]));

    for (const row of list.querySelectorAll('.pdf-field')) {
        const name = row.dataset.field;
        const verdict = row.querySelector('.pdf-field-verdict');
        verdict.textContent = '';
        row.classList.remove('pdf-field-warn', 'pdf-field-block');

        const blocked = blockedBy.get(name);
        if (blocked) {
            row.classList.add('pdf-field-block');
            verdict.append(verdictBox('Cannot write this text', blocked.detail));
            continue;
        }

        const decision = byField.get(name);
        if (!decision || decision.usedOriginal) continue;

        row.classList.add('pdf-field-warn');
        const category = CATEGORIES[decision.category]?.label ?? decision.category;
        verdict.append(verdictBox(
            `Substitute font used here — ${category}`,
            `${decision.explain} It will be written in ${decision.substituteFace} instead, `
            + `which is legible but will not match the rest of the document exactly.`));
    }
}

function verdictBox(title, detail) {
    const box = document.createElement('div');
    box.className = 'pdf-field-note';
    const head = document.createElement('strong');
    head.textContent = title;
    const body = document.createElement('span');
    body.textContent = detail;
    box.append(head, body);
    return box;
}

function runButton(label, handler) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-primary pdf-run';
    button.textContent = label;
    button.disabled = !canRun();
    if (!canRun() && allConfirms().length) {
        button.title = 'Acknowledge the notices above to continue';
    }
    button.addEventListener('click', () => handler(button));
    return button;
}

function renderMergePanel(panel) {
    if (state.docs.length < 2) {
        panel.append(hint('Add at least two PDFs to merge. They are joined in the order '
            + 'listed above; use the arrows to change it.'));
        return;
    }

    const list = document.createElement('ol');
    list.className = 'pdf-merge-order';
    for (const [index, entry] of state.docs.entries()) {
        const item = document.createElement('li');
        const label = document.createElement('span');
        label.textContent = `${entry.name} (${entry.doc.getPageCount()} pages)`;
        const controls = document.createElement('span');
        controls.className = 'pdf-move';
        controls.append(
            moveButton('▲', index > 0, () => swapDocs(index, index - 1)),
            moveButton('▼', index < state.docs.length - 1, () => swapDocs(index, index + 1)),
        );
        item.append(label, controls);
        list.append(item);
    }
    panel.append(list);

    panel.append(runButton('Merge into one PDF', async (button) => {
        await runOperation(button, async () => {
            const { bytes, report } = await ops.merge(
                state.docs.map(({ doc, name }) => ({ doc, label: name })));
            return [{
                name: ops.outputName(state.docs[0].name, 'merged'),
                bytes, report,
                summary: `${state.docs.reduce((n, d) => n + d.doc.getPageCount(), 0)} pages `
                    + `from ${state.docs.length} documents`,
            }];
        });
    }));
}

function moveButton(glyph, enabled, handler) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'pdf-icon-btn';
    button.textContent = glyph;
    button.disabled = !enabled;
    button.addEventListener('click', handler);
    return button;
}

function swapDocs(a, b) {
    [state.docs[a], state.docs[b]] = [state.docs[b], state.docs[a]];
    render();
    renderThumbnails();
}

function renderPagePanel(panel, mode) {
    const entry = state.docs[0];
    const pageCount = entry.doc.getPageCount();

    if (state.docs.length > 1) {
        panel.append(hint(`This tool works on one document. Using "${entry.name}"; `
            + 'remove the others or switch to Merge.'));
    }

    const bar = document.createElement('div');
    bar.className = 'pdf-actions-bar';

    if (mode === 'extract') {
        bar.append(
            smallButton('Select all', () => {
                state.selection = new Set(Array.from({ length: pageCount }, (_, i) => i));
                renderTool(); refreshGridState();
            }),
            smallButton('Select none', () => {
                state.selection = new Set(); renderTool(); refreshGridState();
            }),
        );
    }
    if (mode === 'reorder') {
        bar.append(
            smallButton('Reverse', () => { state.order.reverse(); renderTool(); refreshGridState(); }),
            smallButton('Reset order', () => {
                state.order = Array.from({ length: pageCount }, (_, i) => i);
                renderTool(); refreshGridState();
            }),
        );
    }
    if (mode === 'rotate') {
        bar.append(
            smallButton('Rotate all left', () => rotateAll(-90)),
            smallButton('Rotate all right', () => rotateAll(90)),
            smallButton('Reset rotation', () => { state.rotations = {}; renderTool(); refreshGridState(); }),
        );
    }
    panel.append(bar);

    const grid = document.createElement('div');
    grid.className = 'pdf-grid';
    grid.id = 'pdfGrid';
    panel.append(grid);
    buildGrid(grid, mode, entry, pageCount);

    if (mode === 'extract') {
        const count = state.selection.size;
        const status = document.createElement('p');
        status.className = 'pdf-hint';
        status.textContent = count === pageCount
            ? `All ${pageCount} pages selected — the output will be the whole document.`
            : `${count} of ${pageCount} pages selected.`;
        panel.append(status);

        panel.append(runButton('Extract selected pages', async (button) => {
            await runOperation(button, async () => {
                const indices = [...state.selection].sort((a, b) => a - b);
                if (!indices.length) throw new Error('Select at least one page.');
                const { bytes, report } = await ops.extract(entry.doc, entry.name, indices);
                return [{
                    name: ops.outputName(entry.name, 'extract'),
                    bytes, report,
                    summary: `${indices.length} page(s): ${describeRanges(indices)}`,
                }];
            });
        }));

        panel.append(splitControls(entry, pageCount));
    }

    if (mode === 'reorder') {
        panel.append(runButton('Save reordered PDF', async (button) => {
            await runOperation(button, async () => {
                const { bytes, report } = await ops.reorder(entry.doc, entry.name, [...state.order]);
                return [{
                    name: ops.outputName(entry.name, 'reordered'),
                    bytes, report,
                    summary: `${pageCount} pages, new order: `
                        + `${state.order.slice(0, 12).map((i) => i + 1).join(', ')}`
                        + (pageCount > 12 ? '…' : ''),
                }];
            });
        }));
    }

    if (mode === 'rotate') {
        const changed = Object.values(state.rotations).filter(Boolean).length;
        panel.append(hint(changed
            ? `${changed} page(s) will be rotated. Only the page's rotation attribute `
              + 'changes — the page itself is not redrawn.'
            : 'Click a page to rotate it, or use the buttons above.'));
        panel.append(runButton('Save rotated PDF', async (button) => {
            await runOperation(button, async () => {
                const { bytes, report } = await ops.rotate(entry.doc, entry.name, { ...state.rotations });
                return [{
                    name: ops.outputName(entry.name, 'rotated'),
                    bytes, report,
                    summary: `${changed} page(s) rotated`,
                }];
            });
        }));
    }
}

function splitControls(entry, pageCount) {
    const wrap = document.createElement('div');
    wrap.className = 'pdf-split';

    const heading = document.createElement('h3');
    heading.textContent = 'Or split into separate documents';
    wrap.append(heading);

    const row = document.createElement('div');
    row.className = 'pdf-split-row';
    const label = document.createElement('label');
    label.setAttribute('for', 'pdfSplitAt');
    label.textContent = 'Start a new document before page';
    const input = document.createElement('input');
    input.type = 'text';
    input.id = 'pdfSplitAt';
    input.inputMode = 'numeric';
    input.placeholder = `e.g. 3, 7  (1–${pageCount})`;
    row.append(label, input);
    wrap.append(row);

    wrap.append(hint('Each part is a complete document with its own bookmarks, form fields '
        + 'and metadata, and downloads separately.'));

    wrap.append(runButton('Split', async (button) => {
        await runOperation(button, async () => {
            const boundaries = input.value.split(',')
                .map((v) => parseInt(v.trim(), 10) - 1)
                .filter((v) => Number.isInteger(v));
            if (!boundaries.length) throw new Error('Enter at least one page number to split at.');
            const parts = await ops.split(entry.doc, entry.name, boundaries);
            return parts.map((part, index) => ({
                name: ops.outputName(entry.name, `part-${index + 1}`),
                bytes: part.bytes,
                report: part.report,
                summary: `${part.indices.length} page(s): ${describeRanges(part.indices)}`,
            }));
        });
    }));

    return wrap;
}

function smallButton(label, handler) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'pdf-small-btn';
    button.textContent = label;
    button.addEventListener('click', handler);
    return button;
}

function rotateAll(delta) {
    const entry = state.docs[0];
    for (let i = 0; i < entry.doc.getPageCount(); i += 1) {
        state.rotations[i] = ((state.rotations[i] || 0) + delta + 360) % 360;
    }
    renderTool();
    refreshGridState();
}

function buildGrid(grid, mode, entry, pageCount) {
    const sequence = mode === 'reorder' ? state.order
        : Array.from({ length: pageCount }, (_, i) => i);

    for (const [position, pageIndex] of sequence.entries()) {
        const cell = document.createElement(mode === 'extract' ? 'label' : 'div');
        cell.className = 'pdf-page';
        cell.dataset.page = String(pageIndex);

        const frame = document.createElement('div');
        frame.className = 'pdf-page-frame';
        const canvas = document.createElement('canvas');
        canvas.className = 'pdf-thumb';
        canvas.dataset.page = String(pageIndex + 1);
        frame.append(canvas);

        // Available in every mode: a thumbnail is enough to recognise a page,
        // not enough to decide anything about it.
        const zoom = document.createElement('button');
        zoom.type = 'button';
        zoom.className = 'pdf-zoom-btn';
        zoom.textContent = '⛶';
        zoom.title = `Preview page ${pageIndex + 1} full screen`;
        zoom.setAttribute('aria-label', `Preview page ${pageIndex + 1} full screen`);
        zoom.addEventListener('click', (event) => {
            // On the extract tab the cell is a <label>; without this the click
            // would toggle the checkbox instead of opening the viewer.
            event.preventDefault();
            event.stopPropagation();
            openViewerAt(entry, mode, sequence, position);
        });
        frame.append(zoom);
        cell.append(frame);

        const caption = document.createElement('span');
        caption.className = 'pdf-page-label';
        caption.textContent = mode === 'reorder'
            ? `${position + 1}  (was ${pageIndex + 1})`
            : `Page ${pageIndex + 1}`;
        cell.append(caption);

        if (mode === 'extract') {
            const box = document.createElement('input');
            box.type = 'checkbox';
            box.className = 'pdf-page-check';
            box.checked = state.selection.has(pageIndex);
            box.addEventListener('change', () => {
                if (box.checked) state.selection.add(pageIndex);
                else state.selection.delete(pageIndex);
                renderTool();
                refreshGridState();
            });
            cell.prepend(box);
        }

        if (mode === 'reorder') {
            const controls = document.createElement('div');
            controls.className = 'pdf-move';
            controls.append(
                moveButton('◀', position > 0, () => {
                    [state.order[position], state.order[position - 1]] =
                        [state.order[position - 1], state.order[position]];
                    renderTool(); refreshGridState();
                }),
                moveButton('▶', position < sequence.length - 1, () => {
                    [state.order[position], state.order[position + 1]] =
                        [state.order[position + 1], state.order[position]];
                    renderTool(); refreshGridState();
                }),
            );
            cell.append(controls);
        }

        if (mode === 'rotate') {
            const angle = state.rotations[pageIndex] || 0;
            frame.style.setProperty('--pdf-rot', `${angle}deg`);
            cell.classList.toggle('pdf-page-rotated', angle !== 0);
            const controls = document.createElement('div');
            controls.className = 'pdf-move';
            controls.append(
                moveButton('↺', true, () => {
                    state.rotations[pageIndex] = ((state.rotations[pageIndex] || 0) - 90 + 360) % 360;
                    renderTool(); refreshGridState();
                }),
                moveButton('↻', true, () => {
                    state.rotations[pageIndex] = ((state.rotations[pageIndex] || 0) + 90) % 360;
                    renderTool(); refreshGridState();
                }),
            );
            cell.append(controls);
            if (angle) {
                const badge = document.createElement('span');
                badge.className = 'pdf-rot-badge';
                badge.textContent = `${angle}°`;
                frame.append(badge);
            }
        }

        grid.append(cell);
    }

    paintThumbnails(entry, grid);
}

function refreshGridState() { /* renderTool() rebuilds the grid; kept for call sites. */ }

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

/* ── Running and results ─────────────────────────────────────────────────── */

async function runOperation(button, work) {
    const original = button.textContent;
    button.disabled = true;
    button.textContent = 'Working…';
    $('pdfError').hidden = true;
    try {
        state.outputs = await work();
        renderOutputs();
        $('pdfResults').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (err) {
        const box = $('pdfError');
        box.textContent = err?.message || String(err);
        box.hidden = false;
    } finally {
        button.disabled = !canRun();
        button.textContent = original;
        if (window.lucide) window.lucide.createIcons();
    }
}

function renderOutputs() {
    const results = $('pdfResults');
    results.textContent = '';
    results.hidden = state.outputs.length === 0;
    if (results.hidden) return;

    const heading = document.createElement('h2');
    heading.textContent = state.outputs.length === 1 ? 'Result' : `Result — ${state.outputs.length} files`;
    results.append(heading);

    for (const output of state.outputs) {
        results.append(outputCard(output));
    }
}

function outputCard(output) {
    const card = document.createElement('div');
    card.className = 'pdf-output';

    const head = document.createElement('div');
    head.className = 'pdf-output-head';
    const info = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = output.name;
    const meta = document.createElement('span');
    meta.className = 'pdf-file-meta';
    meta.textContent = `${output.summary} · ${formatSize(output.bytes.length)}`;
    info.append(name, meta);

    const download = document.createElement('a');
    download.className = 'btn btn-primary pdf-download';
    download.textContent = 'Download';
    const blob = new Blob([output.bytes], { type: 'application/pdf' });
    download.href = URL.createObjectURL(blob);
    download.download = output.name;

    head.append(info, download);
    card.append(head);

    // Anything the operation had to change about the document, surfaced on its
    // own rather than folded into the report below.
    for (const entry of output.report.rebuilt.filter((e) => e.prominent)) {
        const notice = document.createElement('div');
        notice.className = 'pdf-notice pdf-notice-confirm';
        const head2 = document.createElement('div');
        head2.className = 'pdf-notice-head';
        head2.textContent = entry.item;
        const detail = document.createElement('p');
        detail.className = 'pdf-notice-detail';
        detail.textContent = entry.detail;
        notice.append(head2, detail);
        card.append(notice);
    }

    card.append(reportBlock(output.report));
    return card;
}

/* The fidelity report. `dropped` is the reason this exists: everything the
 * operation could not carry across, named, rather than lost quietly. */
function reportBlock(report) {
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

/* ── Helpers ─────────────────────────────────────────────────────────────── */

function describeRanges(indices) {
    if (!indices.length) return 'none';
    const sorted = [...indices];
    const ranges = [];
    let start = sorted[0];
    let previous = sorted[0];
    for (const index of sorted.slice(1)) {
        if (index === previous + 1) { previous = index; continue; }
        ranges.push([start, previous]);
        start = previous = index;
    }
    ranges.push([start, previous]);
    return ranges.map(([a, b]) => (a === b ? `${a + 1}` : `${a + 1}–${b + 1}`)).join(', ');
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

    for (const button of document.querySelectorAll('[data-tool]')) {
        button.addEventListener('click', () => {
            state.tool = button.dataset.tool;
            state.outputs = [];
            render();
            renderThumbnails();
        });
    }

    render();
}
