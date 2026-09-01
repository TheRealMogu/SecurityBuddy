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
import { openForPreview, renderThumbnail } from './preview.js';
import * as viewer from './viewer.js';

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
        default: break;
    }
}

function hint(text) {
    const p = document.createElement('p');
    p.className = 'pdf-hint';
    p.textContent = text;
    return p;
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
