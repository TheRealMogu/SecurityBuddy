/* Security Buddy — the workbench shell.
 * ============================================================================
 *
 * The chrome around the document: the tool bar, the page rail, the contextual
 * inspector, the keyboard, and the fidelity strip along the bottom.
 *
 * Every operation here goes through the same engine calls that produced a file
 * to download before. What changed is that the output goes back into the
 * working document (workbench.js) instead of into a card at the bottom of the
 * page, so a second operation starts from the first one's result instead of
 * from a file the user had to download and load again.
 */

import * as wb from './workbench.js';
import * as ops from './operations.js';
import { readableRuns, runAtPoint, planEdit, replaceText, runBox } from './replace.js';
import * as fonts from './fontsource.js';
import { planOverlay, addOverlay } from './overlay.js';
import { planCrop, cropPages } from './crop.js';
import { listTextFields, planFill, fillForm } from './fill.js';
import { classifyPage } from './pagetype.js';
import { CATEGORIES, CHOOSABLE_CATEGORIES } from './fonts.js';
import { reportBlock } from './ui.js';

const $ = (id) => document.getElementById(id);

/* Tool identity in one place: the bar, the keyboard shortcut, the inspector and
 * the fidelity lamps all read from here, so a tool cannot say one thing in the
 * toolbar and another in the status strip. */
const TOOLS = [
    { id: 'pages', label: 'Pages', key: '1', group: 0, icon:
        '<rect x="3" y="4" width="11" height="15" rx="1.5"/><path d="M17 7h4v13H10"/>' },
    { id: 'crop', label: 'Crop', key: '2', group: 0, icon:
        '<path d="M6 2v14a2 2 0 0 0 2 2h14"/><path d="M2 6h14a2 2 0 0 1 2 2v14"/>' },
    { id: 'edit', label: 'Edit text', key: '3', group: 1, icon:
        '<path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"/><path d="M14.5 6.5l3 3"/>' },
    { id: 'add', label: 'Add text', key: '4', group: 1, icon:
        '<path d="M5 7V5h14v2"/><path d="M12 5v14"/><path d="M9 19h6"/>' },
    { id: 'form', label: 'Forms', key: '5', group: 1, icon:
        '<rect x="3" y="5" width="18" height="5" rx="1.5"/><rect x="3" y="14" width="18" height="5" rx="1.5"/>' },
];

const ui = {
    tool: 'pages',
    viewer: null,
    page: 0,
    selection: new Set(),      // page indices, for the Pages tool
    edits: {},                 // runId -> { pageIndex, text, original }
    activeRun: null,
    field: null,
    placements: [],
    placementSeq: 0,
    cropRect: null,
    cropPlan: null,
    cropAccepted: false,
    busy: false,
    timer: 0,
    planToken: 0,
};

/* ── Mounting ────────────────────────────────────────────────────────────── */

export async function mount(name, bytes) {
    await wb.open(name, bytes);
    ui.selection = new Set();
    buildToolbar();
    buildQuickBar();
    bindChrome();

    ui.viewer = new wb.Viewer($('wbScroller'), {
        onPage: (index) => { ui.page = index; paintRail(); },
        onOverlay: (index, layer, viewport) => paintOverlay(index, layer, viewport),
    });
    await ui.viewer.build();
    $('wbScroller').addEventListener('click', onStageClick);
    $('wbScroller').addEventListener('pointerdown', onStagePointerDown);
    $('wbScroller').addEventListener('wheel', onStageWheel, { passive: false });

    wb.onChange(async () => {
        await ui.viewer.build();
        paintAll();
    });

    sizeWorkbench();
    window.addEventListener('resize', sizeWorkbench);
    paintAll();
    $('wbStage').focus({ preventScroll: true });
}

/* Fit the workbench between its own top and the bottom of the window.
 *
 * Without this the stage keeps a fixed height, the page scrolls to reach the
 * document, and the site's sticky navbar ends up covering the very text the
 * user is trying to click. An application does not make its window scroll to
 * reach its own canvas. */
function sizeWorkbench() {
    const shell = document.querySelector('.wb');
    if (!shell) return;
    const body = shell.querySelector('.wb-body');
    const top = shell.getBoundingClientRect().top;
    const chrome = shell.querySelector('.wb-titlebar').offsetHeight
                 + $('wbQuick').offsetHeight
                 + $('wbFidelity').offsetHeight;
    const available = window.innerHeight - top - chrome - 28;
    body.style.height = `${Math.max(380, Math.round(available))}px`;
    // The scroller's height has only just changed, and "fit" is computed from
    // it, so the pages are re-laid out and redrawn against the new one.
    if (ui.viewer) {
        ui.viewer.layout();
        for (const [index, page] of ui.viewer.pages.entries()) {
            if (ui.viewer.near(page)) ui.viewer.draw(index);
        }
        paintZoom();
    }
}

function paintAll() {
    paintTitle();
    refreshQuickBar();
    paintReportCount();
    paintRail();
    paintInspector();
    paintFidelity();
    paintZoom();
}

/* ── Chrome ──────────────────────────────────────────────────────────────── */

function buildToolbar() {
    const bar = $('wbToolbar');
    bar.textContent = '';
    let group = -1;
    for (const tool of TOOLS) {
        if (group !== -1 && tool.group !== group) {
            const sep = document.createElement('span');
            sep.className = 'wb-tsep';
            bar.append(sep);
        }
        group = tool.group;
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'wb-tool';
        button.dataset.wbTool = tool.id;
        button.setAttribute('aria-pressed', String(tool.id === ui.tool));
        button.title = `${tool.label} (${tool.key})`;
        button.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
            stroke-linecap="round" stroke-linejoin="round">${tool.icon}</svg>
            <span>${tool.label}</span>`;
        button.setAttribute('aria-keyshortcuts', tool.key);
        button.addEventListener('click', () => selectTool(tool.id));
        bar.append(button);
    }
}

function selectTool(id) {
    if (ui.tool === id) return;
    commitField();
    ui.tool = id;
    ui.cropRect = null;
    ui.cropPlan = null;
    ui.cropAccepted = false;
    ui.activeRun = null;
    for (const button of document.querySelectorAll('[data-wb-tool]')) {
        button.setAttribute('aria-pressed', String(button.dataset.wbTool === id));
    }
    ui.viewer.redrawOverlays();
    paintAll();
}

/* The five or six things people reach for constantly, out of the tool rail and
 * onto one strip. Page work is most of the day's use, so rotate and delete are
 * here rather than two clicks into a tool. */
function buildQuickBar() {
    const bar = $('wbQuick');
    bar.textContent = '';
    const add = (label, icon, handler, enabled = () => true) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
            stroke-linecap="round" stroke-linejoin="round">${icon}</svg><span>${label}</span>`;
        b.addEventListener('click', () => run(b, handler));
        b.dataset.enabled = 'quick';
        b._enabled = enabled;
        bar.append(b);
        return b;
    };

    add('Rotate left', '<path d="M9 14L4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-4"/>',
        () => rotateSelected(-90));
    add('Rotate right', '<path d="M15 14l5-5-5-5"/><path d="M20 9H9a5 5 0 0 0 0 10h4"/>',
        () => rotateSelected(90));
    add('Delete page', '<path d="M4 7h16"/><path d="M9 7V5h6v2"/><path d="M6 7l1 13h10l1-13"/>',
        () => deleteSelected());

    const sep = document.createElement('span');
    sep.className = 'wb-tsep';
    bar.append(sep);

    add('Extract selected', '<rect x="3" y="4" width="11" height="15" rx="1.5"/><path d="M17 7h4v13H10"/>',
        () => keepSelected());
    refreshQuickBar();
}

function refreshQuickBar() {
    for (const b of $('wbQuick').querySelectorAll('button')) {
        b.disabled = ui.busy || !b._enabled?.();
    }
}

async function rotateSelected(angle) {
    const picked = pickedPages();
    const angles = {};
    for (const index of picked) angles[index] = angle;
    const result = await ops.rotate(wb.doc.lib, wb.doc.name, angles);
    await wb.apply({ ...result, label: angle > 0 ? 'rotate right' : 'rotate left' });
}

async function deleteSelected() {
    const picked = new Set(pickedPages());
    const keep = [...Array(wb.doc.lib.getPageCount()).keys()].filter((i) => !picked.has(i));
    if (!keep.length) throw new Error('That would delete every page.');
    const result = await ops.extract(wb.doc.lib, wb.doc.name, keep);
    ui.selection = new Set();
    await wb.apply({ ...result, label: 'delete page(s)' });
}

async function keepSelected() {
    const picked = pickedPages();
    if (picked.length === wb.doc.lib.getPageCount()) throw new Error('That is every page.');
    const result = await ops.extract(wb.doc.lib, wb.doc.name, picked);
    ui.selection = new Set([...Array(picked.length).keys()]);
    await wb.apply({ ...result, label: 'keep pages' });
}

/* With no explicit selection the quick actions act on the page in view, which
 * is what someone scrolling to a page and hitting "rotate" means. */
function pickedPages() {
    const picked = [...ui.selection].sort((a, b) => a - b);
    return picked.length ? picked : [ui.page];
}

function bindChrome() {
    $('wbRightToggle').addEventListener('click', () => {
        const rail = $('wbRight');
        const collapsed = rail.dataset.collapsed === '1';
        rail.dataset.collapsed = collapsed ? '0' : '1';
        $('wbRightToggle').textContent = collapsed ? '−' : '+';
        $('wbRightToggle').title = collapsed ? 'Hide pages' : 'Show pages';
    });
    $('wbReport').addEventListener('click', showReport);
    $('wbScroller').addEventListener('contextmenu', onContextMenu);
    $('wbRail').addEventListener('contextmenu', onRailContextMenu);
    $('wbUndo').addEventListener('click', () => wb.undo());
    $('wbRedo').addEventListener('click', () => wb.redo());
    $('wbSave').addEventListener('click', saveDocument);
    $('wbZoomIn').addEventListener('click', () => { ui.viewer.zoomBy(1); paintZoom(); });
    $('wbZoomOut').addEventListener('click', () => { ui.viewer.zoomBy(-1); paintZoom(); });
    $('wbZoomFit').addEventListener('click', () => { ui.viewer.setZoom('fit'); paintZoom(); });
    document.addEventListener('keydown', onKey);
}

/* The keyboard a document application is expected to have. Shortcuts are
 * ignored while a text field has focus, except the ones a text field does not
 * claim, so typing "3" into a replacement does not switch tools. */
function onKey(event) {
    const typing = event.target instanceof HTMLInputElement
                || event.target instanceof HTMLTextAreaElement
                || event.target instanceof HTMLSelectElement;
    const accel = event.ctrlKey || event.metaKey;

    if (accel && event.key.toLowerCase() === 'z') {
        event.preventDefault();
        if (typing && event.target === ui.field) return;   // the field's own undo
        (event.shiftKey ? wb.redo() : wb.undo());
        return;
    }
    if (accel && event.key.toLowerCase() === 's') { event.preventDefault(); saveDocument(); return; }
    if (typing) return;

    if (accel && (event.key === '=' || event.key === '+')) { event.preventDefault(); ui.viewer.zoomBy(1); paintZoom(); return; }
    if (accel && event.key === '-') { event.preventDefault(); ui.viewer.zoomBy(-1); paintZoom(); return; }
    switch (event.key) {
        case '+': case '=': ui.viewer.zoomBy(1); paintZoom(); break;
        case '-': ui.viewer.zoomBy(-1); paintZoom(); break;
        case '0': ui.viewer.setZoom('fit'); paintZoom(); break;
        case 'PageDown': ui.viewer.goTo(Math.min(ui.page + 1, ui.viewer.pages.length - 1)); break;
        case 'PageUp': ui.viewer.goTo(Math.max(ui.page - 1, 0)); break;
        case 'Home': ui.viewer.goTo(0); break;
        case 'End': ui.viewer.goTo(ui.viewer.pages.length - 1); break;
        default: {
            const tool = TOOLS.find((t) => t.key === event.key);
            if (tool) selectTool(tool.id);
        }
    }
}

function onStageWheel(event) {
    if (!(event.ctrlKey || event.metaKey)) return;   // plain wheel still scrolls
    event.preventDefault();
    const box = $('wbScroller').getBoundingClientRect();
    ui.viewer.zoomBy(event.deltaY < 0 ? 1 : -1,
                     { x: event.clientX - box.left, y: event.clientY - box.top });
    paintZoom();
}

function paintZoom() {
    $('wbZoomVal').textContent = `${Math.round(ui.viewer.scale * 100)}%`;
}

function paintTitle() {
    $('wbName').textContent = wb.doc.name + (wb.doc.dirty ? ' •' : '');
    const first = wb.doc.lib.getPage(0).getSize();
    $('wbFacts').textContent = `${wb.doc.lib.getPageCount()} page(s) · `
        + `${Math.round(first.width)} × ${Math.round(first.height)} pt · `
        + `${Math.max(1, Math.round(wb.doc.bytes.length / 1024))} KB`;
    $('wbUndo').disabled = !wb.canUndo();
    $('wbRedo').disabled = !wb.canRedo();
    $('wbUndo').title = wb.canUndo() ? `Undo ${wb.lastLabel()} (Ctrl+Z)` : 'Nothing to undo';
    $('wbRedo').title = wb.canRedo() ? `Redo ${wb.nextLabel()} (Ctrl+Shift+Z)` : 'Nothing to redo';
}

async function saveDocument() {
    const blob = new Blob([wb.doc.bytes], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = wb.doc.name.replace(/\.pdf$/i, '') + '-edited.pdf';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/* ── The fidelity strip ──────────────────────────────────────────────────── */

/* What this tool is doing to the file, said out loud, all the time. */
function paintFidelity() {
    const strip = $('wbFidelity');
    strip.textContent = '';
    const cells = [];

    const rewrites = ui.tool === 'edit' || ui.tool === 'crop';
    cells.push(['ok', 'Operation', rewrites
        ? 'Rewrites the page content stream'
        : ui.tool === 'add' ? 'Appends a content stream'
        : ui.tool === 'form' ? 'Writes field values'
        : 'Copies pages, never rebuilds them']);

    if (!rewrites && ui.tool !== 'add') {
        cells.push(['ok', 'Page bytes', 'Untouched']);
    } else if (ui.tool === 'add') {
        cells.push(['ok', 'Page bytes', 'Untouched — the new text goes alongside']);
    } else {
        cells.push(['ok', 'Old content', 'Removed from the file, not covered over']);
    }

    if (ui.tool === 'crop' && ui.cropPlan?.blocked.length) {
        cells.push(['bad', 'Redaction',
            `Incomplete — ${ui.cropPlan.blocked.length} item(s) stay in the file`]);
    }
    const dropped = wb.reportCount('dropped');
    if (dropped) cells.push(['warn', 'Not carried over', `${dropped} item(s)`]);

    for (const [lamp, key, value] of cells) {
        const cell = document.createElement('div');
        cell.className = 'wb-fid';
        const dot = document.createElement('span');
        dot.className = `wb-lamp wb-lamp-${lamp}`;
        const k = document.createElement('span');
        k.className = 'wb-fid-key';
        k.textContent = key;
        const v = document.createElement('span');
        v.className = 'wb-fid-val';
        v.textContent = value;
        cell.append(dot, k, v);
        strip.append(cell);
    }

    const push = document.createElement('div');
    push.className = 'wb-fid wb-fid-push';
    push.textContent = 'All in the browser · nothing uploaded';
    strip.append(push);
}

/* ── The page rail ───────────────────────────────────────────────────────── */

function paintRail() {
    const rail = $('wbRail');
    if (rail.dataset.count !== String(wb.doc.pdf.numPages)) {
        rail.dataset.count = String(wb.doc.pdf.numPages);
        wb.paintThumbnails(rail, { current: ui.page, onPick: pickPage });
    }
    for (const [index, button] of [...rail.children].entries()) {
        button.setAttribute('aria-current', String(index === ui.page));
        button.classList.toggle('wb-thumb-picked',
            ui.tool === 'pages' && ui.selection.has(index));
    }
}

function pickPage(index) {
    if (ui.tool === 'pages') {
        if (ui.selection.has(index)) ui.selection.delete(index);
        else ui.selection.add(index);
        paintRail();
        paintInspector();
    }
    ui.viewer.goTo(index);
}


/* ── Right-click menus ───────────────────────────────────────────────────── */

/* The shortcut people actually learn. Right-clicking the thing you mean beats
 * finding the tool that owns it, so the menu is built from what is under the
 * cursor rather than from the tool in hand. */
let openMenu = null;

function closeMenu() {
    openMenu?.remove();
    openMenu = null;
}

function showMenu(x, y, items) {
    closeMenu();
    const menu = document.createElement('div');
    menu.className = 'wb-menu';
    for (const item of items) {
        if (item === '-') { menu.append(h('div', 'wb-menu-sep')); continue; }
        if (item.head) { menu.append(h('div', 'wb-menu-head', item.head)); continue; }
        const button = h('button', null);
        button.type = 'button';
        button.append(h('span', null, item.label));
        if (item.key) button.append(h('span', 'wb-menu-key', item.key));
        button.disabled = item.disabled === true;
        button.addEventListener('click', () => {
            closeMenu();
            if (item.run) run(button, item.run);
            else item.act?.();
        });
        menu.append(button);
    }
    document.body.append(menu);
    // Keep it on screen when the click lands near an edge.
    const box = menu.getBoundingClientRect();
    menu.style.left = `${Math.min(x, window.innerWidth - box.width - 8)}px`;
    menu.style.top = `${Math.min(y, window.innerHeight - box.height - 8)}px`;
    openMenu = menu;
    // A pointerdown outside dismisses the menu — but one INSIDE it must not,
    // or the menu closes before the click reaches the item and the command
    // never runs.
    const dismiss = (event) => {
        if (menu.contains(event.target)) return;
        window.removeEventListener('pointerdown', dismiss, true);
        closeMenu();
    };
    const onEsc = (event) => {
        if (event.key !== 'Escape') return;
        window.removeEventListener('keydown', onEsc, true);
        window.removeEventListener('pointerdown', dismiss, true);
        closeMenu();
    };
    setTimeout(() => {
        window.addEventListener('pointerdown', dismiss, true);
        window.addEventListener('keydown', onEsc, true);
    }, 0);
    menu.addEventListener('remove', () => {
        window.removeEventListener('pointerdown', dismiss, true);
        window.removeEventListener('keydown', onEsc, true);
    });
}

function onContextMenu(event) {
    const hit = ui.viewer.locate(event);
    if (!hit) return;
    event.preventDefault();

    let runs = [];
    try { runs = readableRuns(wb.doc.lib, wb.doc.lib.getPage(hit.pageIndex)); } catch { /* */ }
    const under = runAtPoint(runs, hit.x, hit.y);

    const items = [{ head: `Page ${hit.pageIndex + 1}` }];
    if (under) {
        items.push(
            { label: `Edit “${under.text.slice(0, 22)}${under.text.length > 22 ? '…' : ''}”`,
              key: '3', act: () => { selectTool('edit'); openRun(hit); } },
            { label: 'Add text on top here', key: '4',
              act: () => { selectTool('add'); placeAt(hit); } },
            '-');
    } else {
        items.push({ label: 'Add text here', key: '4',
                     act: () => { selectTool('add'); placeAt(hit); } }, '-');
    }
    items.push(
        { label: 'Crop from here', key: '2', act: () => selectTool('crop') },
        '-',
        { label: 'Rotate this page right', run: async () => {
            ui.selection = new Set([hit.pageIndex]);
            await rotateSelected(90);
        } },
        { label: 'Delete this page', run: async () => {
            ui.selection = new Set([hit.pageIndex]);
            await deleteSelected();
        }, disabled: wb.doc.lib.getPageCount() < 2 });
    showMenu(event.clientX, event.clientY, items);
}

function onRailContextMenu(event) {
    const thumb = event.target.closest('.wb-thumb');
    if (!thumb) return;
    event.preventDefault();
    const index = [...$('wbRail').children].indexOf(thumb);
    if (index < 0) return;
    // Right-clicking a page that is not part of the selection makes it the
    // selection, the way it does in every file manager. Right-clicking one
    // that IS part of it keeps the group, so a multi-page action still works.
    if (!ui.selection.has(index)) ui.selection = new Set([index]);
    ui.page = index;
    paintRail();
    const picked = pickedPages();
    showMenu(event.clientX, event.clientY, [
        { head: picked.length > 1 ? `${picked.length} pages selected` : `Page ${index + 1}` },
        { label: 'Rotate right', run: () => rotateSelected(90) },
        { label: 'Rotate left', run: () => rotateSelected(-90) },
        '-',
        { label: 'Keep only these', run: () => keepSelected(),
          disabled: picked.length === wb.doc.lib.getPageCount() },
        { label: 'Delete', run: () => deleteSelected(),
          disabled: picked.length >= wb.doc.lib.getPageCount() },
    ]);
}

function placeAt(hit) {
    ui.placementSeq += 1;
    ui.placements.push({
        id: ui.placementSeq, pageIndex: hit.pageIndex,
        x: Math.round(hit.x * 10) / 10, y: Math.round(hit.y * 10) / 10, text: '',
    });
    ui.viewer.redrawOverlays();
    paintInspector();
}

/* ── The accumulated report ──────────────────────────────────────────────── */

/* The strip says what the current operation does; this says what has already
 * been done to this document, across every operation, in one place. Losing
 * that when the tools became a workbench would have been the worst kind of
 * regression: the quiet kind. */
function paintReportCount() {
    const total = ['dropped', 'rebuilt', 'preserved']
        .reduce((n, key) => n + wb.reportCount(key), 0);
    $('wbReportCount').textContent = String(total);
    $('wbReport').disabled = total === 0;
}

function showReport() {
    const panel = $('wbInspector');
    panel.textContent = '';
    panel.append(title('What happened to the document'));
    const total = ['dropped', 'rebuilt', 'preserved']
        .reduce((n, key) => n + wb.reportCount(key), 0);
    if (!total) {
        panel.append(note('info', 'Nothing has been changed yet',
            'This document is exactly as it was loaded.'));
    } else {
        panel.append(reportBlock(wb.doc.report));
    }
    const back = h('button', 'btn btn-secondary', 'Back to the tool');
    back.type = 'button';
    back.addEventListener('click', paintInspector);
    panel.append(back);
}

/* ── Overlays drawn on the document ──────────────────────────────────────── */

function paintOverlay(index, layer, viewport) {
    if (ui.tool === 'edit' || ui.tool === 'add') {
        let runs = [];
        try { runs = readableRuns(wb.doc.lib, wb.doc.lib.getPage(index)); } catch { return; }
        for (const run of runs) {
            const box = runBox(run);
            if (box.width <= 0) continue;
            const [x1, y1] = viewport.convertToViewportPoint(box.x, box.top);
            const [x2, y2] = viewport.convertToViewportPoint(box.x + box.width, box.bottom);
            const el = document.createElement('span');
            el.className = `pdf-run-box pdf-run-box-${ui.tool === 'edit' ? 'edit' : 'add'}`;
            if (ui.tool === 'edit' && ui.activeRun?.pageIndex === index
                && ui.activeRun.id === run.id) el.classList.add('pdf-run-box-sel');
            el.style.left = `${Math.min(x1, x2)}px`;
            el.style.top = `${Math.min(y1, y2)}px`;
            el.style.width = `${Math.abs(x2 - x1)}px`;
            el.style.height = `${Math.abs(y2 - y1)}px`;
            el.title = ui.tool === 'edit'
                ? `${run.text} — ${run.font.name} ${run.size}pt`
                : `Existing text: ${run.text}`;
            layer.append(el);
        }
    }

    if (ui.tool === 'add') {
        for (const place of ui.placements.filter((p) => p.pageIndex === index)) {
            const [x, y] = viewport.convertToViewportPoint(place.x, place.y);
            const dot = document.createElement('span');
            dot.className = 'pdf-place-marker';
            dot.style.left = `${x}px`;
            dot.style.top = `${y}px`;
            dot.textContent = String(ui.placements.indexOf(place) + 1);
            layer.append(dot);
        }
    }

    if (ui.tool === 'crop' && ui.cropRect && ui.cropRect.pageIndex === index) {
        const r = ui.cropRect;
        const [x1, y1] = viewport.convertToViewportPoint(r.x, r.y + r.height);
        const [x2, y2] = viewport.convertToViewportPoint(r.x + r.width, r.y);
        const box = {
            left: Math.min(x1, x2), top: Math.min(y1, y2),
            width: Math.abs(x2 - x1), height: Math.abs(y2 - y1),
        };
        const shade = document.createElement('div');
        shade.className = 'pdf-crop-shade';
        shade.style.clipPath = `polygon(0 0, 100% 0, 100% 100%, 0 100%, 0 0,
            ${box.left}px ${box.top}px, ${box.left}px ${box.top + box.height}px,
            ${box.left + box.width}px ${box.top + box.height}px,
            ${box.left + box.width}px ${box.top}px, ${box.left}px ${box.top}px)`;
        const frame = document.createElement('div');
        frame.className = 'pdf-crop-frame';
        Object.assign(frame.style, {
            left: `${box.left}px`, top: `${box.top}px`,
            width: `${box.width}px`, height: `${box.height}px`,
        });
        for (const corner of ['nw', 'ne', 'se', 'sw']) {
            const handle = document.createElement('span');
            handle.className = `pdf-crop-handle pdf-crop-handle-${corner}`;
            frame.append(handle);
        }
        layer.append(shade, frame);
    }
}

/* ── Clicking the document ───────────────────────────────────────────────── */

function onStageClick(event) {
    const hit = ui.viewer.locate(event);
    if (!hit) return;
    if (ui.tool === 'edit') openRun(hit);
    if (ui.tool === 'add') {
        ui.placementSeq += 1;
        ui.placements.push({
            id: ui.placementSeq, pageIndex: hit.pageIndex,
            x: Math.round(hit.x * 10) / 10, y: Math.round(hit.y * 10) / 10, text: '',
        });
        ui.viewer.redrawOverlays();
        paintInspector();
    }
}

function onStagePointerDown(event) {
    if (ui.tool !== 'crop' || event.button !== 0) return;
    const hit = ui.viewer.locate(event);
    if (!hit) return;
    event.preventDefault();
    startCrop(hit, event);
}

/* ── The inspector ───────────────────────────────────────────────────────── */

function paintInspector() {
    const panel = $('wbInspector');
    panel.textContent = '';
    ({
        pages: inspectPages, edit: inspectEdit, add: inspectAdd,
        crop: inspectCrop, form: inspectForm,
    }[ui.tool])(panel);
}

function h(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
}

function title(text) { return h('p', 'wb-insp-title', text); }

function metrics(rows) {
    const dl = h('dl', 'wb-metrics');
    for (const [key, value] of rows) {
        dl.append(h('dt', null, key), h('dd', null, String(value)));
    }
    return dl;
}

function note(tone, head, body) {
    const box = h('div', `pdf-field-note pdf-edit-note-${tone}`);
    box.append(h('strong', null, head), h('span', null, body));
    return box;
}

function action(text, handler, { ghost = false, disabled = false } = {}) {
    const button = h('button', `btn ${ghost ? 'btn-secondary' : 'btn-primary'}`, text);
    button.type = 'button';
    button.disabled = disabled || ui.busy;
    button.addEventListener('click', () => run(button, handler));
    return button;
}

async function run(button, handler) {
    if (ui.busy) return;
    ui.busy = true;
    const label = button.textContent;
    button.disabled = true;
    button.textContent = 'Working…';
    $('pdfError').hidden = true;
    try {
        await handler();
    } catch (err) {
        const box = $('pdfError');
        box.textContent = err?.message || String(err);
        box.hidden = false;
    } finally {
        ui.busy = false;
        button.textContent = label;
        button.disabled = false;
        paintInspector();
    }
}

/* Pages ------------------------------------------------------------------- */

function inspectPages(panel) {
    const count = wb.doc.lib.getPageCount();
    const picked = [...ui.selection].sort((a, b) => a - b);
    panel.append(title('Pages'));
    panel.append(metrics([
        ['In document', count],
        ['Selected', picked.length ? picked.map((i) => i + 1).join(', ') : 'none'],
    ]));

    const row = h('div', 'pdf-actions-bar');
    for (const [label, fn] of [['All', () => ui.selection = new Set([...Array(count).keys()])],
                               ['None', () => ui.selection.clear()],
                               ['Invert', () => {
                                   const next = new Set();
                                   for (let i = 0; i < count; i += 1) if (!ui.selection.has(i)) next.add(i);
                                   ui.selection = next;
                               }]]) {
        const b = h('button', 'pdf-small-btn', label);
        b.type = 'button';
        b.addEventListener('click', () => { fn(); paintRail(); paintInspector(); });
        row.append(b);
    }
    panel.append(row);

    panel.append(title('Rotate the selected pages'));
    const turns = h('div', 'pdf-actions-bar');
    for (const [label, angle] of [['↺ 90°', -90], ['↻ 90°', 90], ['180°', 180]]) {
        const b = h('button', 'pdf-small-btn', label);
        b.type = 'button';
        b.disabled = !picked.length;
        b.addEventListener('click', () => run(b, async () => {
            const angles = {};
            for (const index of picked) angles[index] = angle;
            const result = await ops.rotate(wb.doc.lib, wb.doc.name, angles);
            await wb.apply({ ...result, label: 'rotate' });
        }));
        turns.append(b);
    }
    panel.append(turns);

    panel.append(note('info', 'Keeping pages is not deleting them',
        'Pages left out do not reach the output, and neither does anything only they reached — '
        + 'form fields, layers, destinations. What could not be carried over is listed after.'));

    panel.append(action('Keep only the selected pages', async () => {
        if (!picked.length) throw new Error('Select at least one page.');
        if (picked.length === wb.doc.lib.getPageCount()) throw new Error('That is every page.');
        const result = await ops.extract(wb.doc.lib, wb.doc.name, picked);
        await wb.apply({ ...result, label: 'keep pages' });
        ui.selection = new Set([...Array(picked.length).keys()]);
    }, { disabled: !picked.length }));
}

/* Edit text --------------------------------------------------------------- */

function inspectEdit(panel) {
    panel.append(title('Edit text'));
    const run_ = ui.activeRun;
    if (!run_) {
        panel.append(note('info', 'Click any outlined text',
            'Every piece of text this tool can read is outlined. Clicking one puts the cursor in '
            + 'it; the page redraws with the real replacement as you type.'));
        return;
    }

    const edit = ui.edits[run_.id];
    panel.append(provenance('original', run_.font.name, run_.size));

    const slot = h('div', 'wb-plan');
    panel.append(slot);
    paintPlan(slot, run_, edit.text);
}

/* The verdict for the text as typed. Asynchronous, because answering it may
 * mean fetching a font file to see whether the missing glyphs can be had. */
async function paintPlan(slot, run_, text) {
    const token = ++ui.planToken;
    let plan = null;
    try {
        plan = await planEdit(wb.doc.lib, wb.doc.lib.getPage(run_.pageIndex), run_, text);
    } catch { /* shown as "could not be planned" below */ }
    if (token !== ui.planToken || !slot.isConnected) return;

    slot.textContent = '';
    slot.append(metrics([
        ['Size', `${run_.size} pt`],
        ['Origin', `${run_.x.toFixed(1)}, ${run_.y.toFixed(1)} pt`],
        ['Width', plan && !plan.blocked
            ? `${plan.oldWidth} pt → ${plan.newWidth} pt` : `${runBox(run_).width.toFixed(1)} pt`],
    ]));

    if (plan?.blocked) {
        slot.append(note('block', 'This font cannot write that text', plan.explain));
        if (plan.needsFont) slot.append(fontSearch(slot, run_, text, plan.needsFont));
    } else if (plan) {
        for (const item of plan.notes) slot.append(note('warn', 'Worth knowing', item));
    }

    slot.append(action('Apply this change', async () => {
        commitField();
        const list = Object.entries(ui.edits)
            .filter(([, v]) => v.text && v.text !== v.original)
            .map(([id, v]) => ({ pageIndex: v.pageIndex, runId: Number(id), newText: v.text }));
        if (!list.length) throw new Error('Change the wording first.');
        const result = await replaceText(wb.doc.lib, wb.doc.name, list);
        ui.edits = {};
        ui.activeRun = null;
        await wb.apply({ ...result, label: 'edit text' });
    }, { disabled: !plan || plan.blocked }));
}

/* When the document's subset lacks the glyphs and we have no copy of the face,
 * the way forward is to find one — not to quietly write something else. */
function fontSearch(slot, run_, text, needed) {
    const wrap = h('div', 'wb-fontsearch');
    wrap.append(h('p', 'wb-insp-title', `Find ${needed}`));

    if (fonts.canReadLocalFonts() && !fonts.localFontsReady()) {
        const grant = h('button', 'btn btn-secondary', 'Use the fonts on this computer');
        grant.type = 'button';
        grant.addEventListener('click', () => run(grant, async () => {
            const result = await fonts.grantLocalFonts();
            if (!result.granted) {
                throw new Error(result.reason === 'denied'
                    ? 'Permission to read this computer\'s fonts was declined.'
                    : 'This browser could not list the fonts on this computer.');
            }
            paintPlan(slot, run_, text);
        }));
        wrap.append(grant);
        wrap.append(h('p', 'wb-hint', 'The browser asks first, and the font is read here in '
            + 'the tab — nothing about it is sent anywhere.'));
    }

    const pick = h('label', 'btn btn-secondary wb-filebtn');
    pick.append(document.createTextNode('Choose a font file…'));
    const input = h('input');
    input.type = 'file';
    input.accept = '.ttf,.otf,.ttc,font/ttf,font/otf';
    input.hidden = true;
    input.addEventListener('change', async () => {
        if (!input.files?.length) return;
        try {
            const loaded = await fonts.addUserFont(input.files[0]);
            paintPlan(slot, run_, text);
            if (fonts.normaliseName(loaded) !== fonts.normaliseName(needed)) {
                slot.prepend(note('warn', `That file is ${loaded}, not ${needed}`,
                    'It was added to the list, but it will not be used for this text: a '
                    + 'different face embedded under this one\'s name is the silent '
                    + 'substitution these tools refuse.'));
            }
        } catch (err) {
            slot.prepend(note('block', 'That file could not be read', err.message));
        }
        input.value = '';
    });
    pick.append(input);
    wrap.append(pick);
    return wrap;
}

const PROVENANCE = {
    original:   ['from the document', 'doc'],
    USER:       ['set by you', 'doc'],
    SUBSTITUTE: ['substitute', 'sub'],
    ESTIMATED:  ['estimated', 'est'],
    DEFAULT:    ['default', 'est'],
};

function provenance(source, face, size) {
    const [label, tone] = PROVENANCE[source] ?? [source, 'sub'];
    const badge = h('span', `pdf-prov pdf-prov-${tone}`);
    badge.append(h('span', 'pdf-prov-dot'), h('span', 'pdf-prov-face', face ?? '—'),
                 h('span', 'pdf-prov-sep', '·'),
                 h('span', 'pdf-prov-src', size ? `${label} · ${size}pt` : label));
    return badge;
}

/* The field that sits on the page, over the run it edits. */
function openRun(hit) {
    let runs = [];
    try { runs = readableRuns(wb.doc.lib, wb.doc.lib.getPage(hit.pageIndex)); } catch { return; }
    const run_ = runAtPoint(runs, hit.x, hit.y);
    commitField();
    if (!run_) { ui.activeRun = null; ui.viewer.redrawOverlays(); paintInspector(); return; }

    run_.pageIndex = hit.pageIndex;
    ui.activeRun = run_;
    if (!ui.edits[run_.id]) {
        ui.edits[run_.id] = { pageIndex: hit.pageIndex, text: run_.text, original: run_.text };
    }

    const box = runBox(run_);
    const [x1, y1] = hit.viewport.convertToViewportPoint(box.x, box.top);
    const [x2, y2] = hit.viewport.convertToViewportPoint(box.x + box.width, box.bottom);

    const field = document.createElement('input');
    field.type = 'text';
    field.className = 'pdf-edit-field';
    field.value = ui.edits[run_.id].text;
    field.spellcheck = false;
    field.style.fontSize = `${run_.size * hit.viewport.scale}px`;
    field.style.left = `${Math.min(x1, x2)}px`;
    field.style.top = `${Math.min(y1, y2)}px`;
    field.style.width = `${Math.abs(x2 - x1) + 2}px`;
    field.style.height = `${Math.abs(y2 - y1)}px`;
    field.addEventListener('input', () => {
        ui.edits[run_.id].text = field.value;
        clearTimeout(ui.timer);
        ui.timer = setTimeout(paintInspector, 160);
    });
    field.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            event.preventDefault();
            delete ui.edits[run_.id];
            ui.activeRun = null;
            commitField();
            ui.viewer.redrawOverlays();
            paintInspector();
        }
        if (event.key === 'Enter') { event.preventDefault(); commitField(); paintInspector(); }
    });

    ui.field = field;
    hit.layer.append(field);
    ui.viewer.redrawOverlays();
    hit.layer.append(field);
    field.focus();
    field.select();
    paintInspector();
}

function commitField() {
    ui.field?.remove();
    ui.field = null;
}

/* Add text ---------------------------------------------------------------- */

function inspectAdd(panel) {
    panel.append(title('Add text'));

    const hidden = hiddenTextLayer(ui.page);
    if (hidden) {
        panel.append(note('block', 'This page carries an invisible text layer',
            `${hidden} text operation(s) here draw no ink — the signature of an OCR layer under a `
            + 'scan. That text is not outlined and cannot be clicked, but it is in the file and a '
            + 'search will find it. Anything you add goes on top and leaves it in place.'));
    }

    if (!ui.placements.length) {
        panel.append(note('info', 'Click the page where the text should start',
            'The click point is the left end of the baseline. The font is read from that spot.'));
        return;
    }

    for (const place of ui.placements) {
        const card = h('div', 'pdf-field');
        const head = h('div', 'pdf-place-head');
        head.append(h('span', 'pdf-field-label', `Placement ${ui.placements.indexOf(place) + 1}`));
        const drop = h('button', 'pdf-icon-btn', '✕');
        drop.type = 'button';
        drop.addEventListener('click', () => {
            ui.placements = ui.placements.filter((p) => p !== place);
            ui.viewer.redrawOverlays();
            paintInspector();
        });
        head.append(drop);
        card.append(head);

        const input = h('input', 'pdf-field-input');
        input.type = 'text';
        input.placeholder = 'Text to add';
        input.value = place.text;
        card.append(input);

        // The badge is refreshed on its own, in place. Rebuilding the panel on
        // every keystroke would take the caret out of the field being typed
        // into, which is the difference between an editor and a form.
        const slot = h('div', 'pdf-place-slot');
        card.append(slot);
        input.addEventListener('input', () => {
            place.text = input.value;
            clearTimeout(place.timer);
            place.timer = setTimeout(() => refreshPlacement(place, slot), 200);
        });
        refreshPlacement(place, slot);
        panel.append(card);
    }

    panel.append(action('Add the text', async () => {
        const ready = ui.placements.filter((p) => p.text && p.text.trim());
        if (!ready.length) throw new Error('Type the text first.');
        const result = await addOverlay(wb.doc.lib, wb.doc.name, ready);
        ui.placements = [];
        await wb.apply({ ...result, label: 'add text' });
    }));
}

/* One placement's font verdict, replaced in place. */
function refreshPlacement(place, slot) {
    slot.textContent = '';
    if (!place.text) return;
    let plan = null;
    let stop = null;
    try {
        const result = planOverlay(wb.doc.lib, [place]);
        plan = result.plans[0];
        stop = result.blocked[0];
    } catch { /* an unplannable placement simply gets no badge */ }
    if (stop) {
        slot.append(note('block', 'Cannot write this text here', stop.explain));
        return;
    }
    if (plan) slot.append(provenance(plan.source, plan.face ?? plan.font?.name, plan.size));
}

function hiddenTextLayer(pageIndex) {
    try {
        const { signals } = classifyPage(wb.doc.lib, wb.doc.lib.getPage(pageIndex));
        const invisible = signals.textOps - signals.visibleTextOps;
        return invisible > 0 && signals.visibleTextOps === 0 ? invisible : 0;
    } catch { return 0; }
}

/* Crop -------------------------------------------------------------------- */

function startCrop(hit, event) {
    const layer = hit.layer;
    const box = layer.getBoundingClientRect();
    const originX = event.clientX - box.left;
    const originY = event.clientY - box.top;
    const viewport = hit.viewport;

    const move = (e) => {
        const x = Math.max(0, Math.min(e.clientX - box.left, box.width));
        const y = Math.max(0, Math.min(e.clientY - box.top, box.height));
        const [ax, ay] = viewport.convertToPdfPoint(Math.min(originX, x), Math.min(originY, y));
        const [bx, by] = viewport.convertToPdfPoint(Math.max(originX, x), Math.max(originY, y));
        ui.cropRect = {
            pageIndex: hit.pageIndex,
            x: Math.min(ax, bx), y: Math.min(ay, by),
            width: Math.abs(bx - ax), height: Math.abs(by - ay),
        };
        ui.cropAccepted = false;
        ui.viewer.redrawOverlays();
    };
    const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        if (ui.cropRect && (ui.cropRect.width < 4 || ui.cropRect.height < 4)) ui.cropRect = null;
        replanCrop();
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
}

function replanCrop() {
    clearTimeout(ui.timer);
    ui.timer = setTimeout(() => {
        try {
            ui.cropPlan = ui.cropRect
                ? planCrop(wb.doc.lib, wb.doc.lib.getPage(ui.cropRect.pageIndex), ui.cropRect)
                : null;
        } catch { ui.cropPlan = null; }
        ui.viewer.redrawOverlays();
        paintInspector();
        paintFidelity();
    }, 160);
}

function inspectCrop(panel) {
    panel.append(title('Crop'));
    if (!ui.cropRect) {
        panel.append(note('info', 'Drag a rectangle over the page',
            'Everything outside it is deleted from the file — not hidden behind a smaller page, '
            + 'which is what "crop" normally means and what leaves every removed word '
            + 'recoverable.'));
        return;
    }

    const r = ui.cropRect;
    panel.append(metrics([
        ['Keeping', `${Math.round(r.width)} × ${Math.round(r.height)} pt`],
        ['Origin', `${r.x.toFixed(1)}, ${r.y.toFixed(1)} pt`],
        ['To delete', ui.cropPlan ? `${ui.cropPlan.remove.length} operation(s)` : '…'],
        ['To shorten', ui.cropPlan ? `${ui.cropPlan.split.length} line(s)` : '…'],
    ]));

    const blocked = ui.cropPlan?.blocked ?? [];
    const grouped = new Map();
    for (const item of blocked) {
        if (!grouped.has(item.reason)) grouped.set(item.reason, { count: 0, detail: item.detail });
        grouped.get(item.reason).count += 1;
    }
    for (const [, { count, detail }] of grouped) {
        panel.append(note('block', count === 1
            ? '1 thing outside the crop cannot be removed'
            : `${count} things outside the crop cannot be removed`, detail));
    }

    if (blocked.length) {
        const consent = h('label', 'pdf-crop-accept');
        const box = h('input');
        box.type = 'checkbox';
        box.checked = ui.cropAccepted;
        box.addEventListener('change', () => { ui.cropAccepted = box.checked; paintInspector(); });
        consent.append(box, h('span', null,
            `I understand that ${blocked.length} thing(s) outside the crop stay in the file and `
            + 'can be recovered from it. This output is not redacted.'));
        panel.append(consent);
    }

    panel.append(action('Crop the page', async () => {
        const result = await cropPages(wb.doc.lib, wb.doc.name,
            [{ pageIndex: r.pageIndex, rect: r }], { acceptUnremovable: ui.cropAccepted });
        ui.cropRect = null;
        ui.cropPlan = null;
        ui.cropAccepted = false;
        await wb.apply({ ...result, label: 'crop' });
    }, { disabled: blocked.length > 0 && !ui.cropAccepted }));
}

/* Forms ------------------------------------------------------------------- */

function inspectForm(panel) {
    panel.append(title('Form fields'));
    let fields = [];
    try { fields = listTextFields(wb.doc.lib); } catch { /* */ }
    if (!fields.length) {
        panel.append(note('info', 'This document has no fillable text fields',
            'Only text fields are offered. Checkboxes, radio groups and dropdowns are left alone.'));
        return;
    }

    ui.values ??= {};
    for (const field of fields) {
        const wrap = h('div', 'pdf-field');
        wrap.append(h('span', 'pdf-field-label', field.name));
        const input = h('input', 'pdf-field-input');
        input.type = 'text';
        input.value = ui.values[field.name] ?? field.currentValue ?? '';
        input.addEventListener('input', () => { ui.values[field.name] = input.value; });
        wrap.append(input);
        panel.append(wrap);
    }

    panel.append(note('info', 'Field appearances are not regenerated',
        'Left to itself the library would redraw every field with its own fonts and layout, '
        + 'silently changing how the form prints.'));

    panel.append(action('Fill the form', async () => {
        const values = Object.entries(ui.values).filter(([, v]) => v !== '');
        if (!values.length) throw new Error('Type a value into at least one field.');
        const result = await fillForm(wb.doc.lib, wb.doc.name, Object.fromEntries(values));
        await wb.apply({ ...result, label: 'fill form' });
    }));
}

export { ui, wb };
