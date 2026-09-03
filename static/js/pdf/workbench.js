/* Security Buddy — the document workbench.
 * ============================================================================
 *
 * What was wrong before this file existed: the tools were a form. You picked
 * one, filled it in, and got a file to download. Doing a second thing meant
 * loading the file you had just downloaded. The document on screen never
 * changed, there was no zoom, no undo, and no keyboard — so working on 10pt
 * text in a 520px preview meant clicking blind and hoping.
 *
 * An editor is the other way round: there is ONE document, operations change
 * it, and you save when you are done. That is what this holds.
 *
 *   * the working document, and the stack of states behind it (undo/redo)
 *   * the viewer: every page in one scroller, with zoom and panning
 *   * the accumulated fidelity report, because a document that has been
 *     through four operations has four operations' worth of consequences and
 *     the user is entitled to all of them at once, not one card at a time
 *
 * Every operation still goes through the same verified engine calls. What
 * changed is where their output goes: back into the document, instead of into
 * a download card at the bottom of the page.
 */

import { loadDocument } from './preserve.js';
import { openForPreview, renderForPlacement, renderThumbnail } from './preview.js';

/* Zoom stops, in the order the +/- keys walk them. "Fit" is not a stop: it is
 * recomputed from the viewport, so resizing the window keeps the page fitted. */
export const ZOOM_STOPS = [0.5, 0.75, 1, 1.25, 1.5, 2, 3, 4];
const MAX_HISTORY = 20;         // byte snapshots; a scan is megabytes each

export const doc = {
    name: '',
    bytes: null,
    pdf: null,             // pdf.js document for the current bytes
    lib: null,             // pdf-lib document for the current bytes
    history: [],           // [{ bytes, label }] — states BEFORE each operation
    future: [],
    report: { preserved: [], rebuilt: [], dropped: [], blocked: [], confirm: [] },
    dirty: false,
};

const listeners = new Set();
export function onChange(fn) { listeners.add(fn); return () => listeners.delete(fn); }
function announce(what) { for (const fn of listeners) fn(what); }

/* ── The working document ────────────────────────────────────────────────── */

export async function open(name, bytes) {
    doc.name = name;
    doc.history = [];
    doc.future = [];
    doc.report = { preserved: [], rebuilt: [], dropped: [], blocked: [], confirm: [] };
    doc.dirty = false;
    await install(bytes);
    announce('open');
}

async function install(bytes) {
    doc.pdf?.destroy?.();
    doc.bytes = bytes;
    doc.lib = (await loadDocument(bytes, doc.name)).doc;
    doc.pdf = await openForPreview(bytes);
}

/* Apply an operation's output as the new working document.
 *
 * The engine functions all produce a fresh document rather than mutating the
 * one they were given, so each step is the same verified transform it was when
 * it produced a file to download — it just lands here instead. Reloading the
 * bytes is also what keeps the next operation honest: it plans against what is
 * actually in the file now, not against what we think we did to it.
 */
export async function apply({ bytes, report, label }) {
    doc.history.push({ bytes: doc.bytes, label });
    if (doc.history.length > MAX_HISTORY) doc.history.shift();
    doc.future = [];
    await install(bytes);
    mergeReport(report);
    doc.dirty = true;
    announce('apply');
}

export function canUndo() { return doc.history.length > 0; }
export function canRedo() { return doc.future.length > 0; }
export function lastLabel() { return doc.history.at(-1)?.label ?? null; }
export function nextLabel() { return doc.future.at(-1)?.label ?? null; }

export async function undo() {
    if (!canUndo()) return;
    const previous = doc.history.pop();
    doc.future.push({ bytes: doc.bytes, label: previous.label });
    await install(previous.bytes);
    doc.dirty = doc.history.length > 0;
    announce('undo');
}

export async function redo() {
    if (!canRedo()) return;
    const next = doc.future.pop();
    doc.history.push({ bytes: doc.bytes, label: next.label });
    await install(next.bytes);
    doc.dirty = true;
    announce('redo');
}

/* Reports accumulate. Four operations leave four operations' worth of
 * consequences, and showing only the last one would quietly drop the rest. */
function mergeReport(report) {
    if (!report) return;
    for (const key of Object.keys(doc.report)) {
        for (const entry of report[key] ?? []) {
            const already = doc.report[key].some(
                (e) => e.item === entry.item && e.detail === entry.detail);
            if (!already) doc.report[key].push(entry);
        }
    }
}

export function reportCount(kind) { return doc.report[kind]?.length ?? 0; }

/* ── The viewer ──────────────────────────────────────────────────────────── */

/* One scroller holding every page, so the document scrolls the way a document
 * does instead of being paged through with buttons. Pages render when they come
 * near the viewport: a 200-page file must not render 200 canvases to show the
 * first one. */
export class Viewer {
    constructor(scroller, { onPage, onOverlay } = {}) {
        this.scroller = scroller;
        this.onPage = onPage;                 // (index) => void, the page in view
        this.onOverlay = onOverlay;           // (index, layer, viewport) => void
        this.zoom = 'fit';
        this.pages = [];                      // [{ wrap, canvas, layer, rendered, viewport }]
        this.current = 0;
        this.observer = null;
        this.pending = new Set();
    }

    get scale() {
        return this.zoom === 'fit' ? this.fitScale() : this.zoom;
    }

    /* "Fit" means the whole page, not the whole width: fitting width alone
     * leaves a portrait page taller than a short viewport, which is the one
     * thing "fit" is supposed to prevent. */
    fitScale() {
        const first = this.pages[0];
        if (!first?.width) return 1;
        const wide = Math.max(240, this.scroller.clientWidth - 48) / first.width;
        const tall = Math.max(200, this.scroller.clientHeight - 40) / first.height;
        return Math.min(wide, tall, 1.6);
    }

    async build() {
        this.observer?.disconnect();
        this.scroller.textContent = '';
        this.pages = [];
        this.pending.clear();

        const count = doc.pdf.numPages;
        for (let i = 0; i < count; i += 1) {
            const page = await doc.pdf.getPage(i + 1);
            const rotation = ((page.rotate || 0) % 360 + 360) % 360;
            const unscaled = page.getViewport({ scale: 1, rotation });

            const wrap = document.createElement('div');
            wrap.className = 'wb-page';
            wrap.dataset.page = String(i);
            const canvas = document.createElement('canvas');
            canvas.className = 'wb-canvas';
            const layer = document.createElement('div');
            layer.className = 'wb-layer';
            const tag = document.createElement('span');
            tag.className = 'wb-page-tag';
            tag.textContent = String(i + 1);
            wrap.append(canvas, layer, tag);
            this.scroller.append(wrap);

            this.pages.push({
                wrap, canvas, layer, page, rotation,
                width: unscaled.width, height: unscaled.height,
                rendered: false, viewport: null,
            });
        }
        this.layout();

        // rootMargin renders a screenful ahead, so scrolling never shows a gap.
        this.observer = new IntersectionObserver((entries) => {
            for (const entry of entries) {
                const index = Number(entry.target.dataset.page);
                if (entry.isIntersecting) this.draw(index);
                if (entry.intersectionRatio > 0.5) this.setCurrent(index);
            }
        }, { root: this.scroller, rootMargin: '400px 0px', threshold: [0, 0.5] });
        for (const p of this.pages) this.observer.observe(p.wrap);
    }

    /* Size every page box up front so the scrollbar is right before anything
     * has been drawn — a scroller that grows as it renders jumps under the
     * cursor, which is the single most irritating thing a viewer can do. */
    layout() {
        const scale = this.scale;
        for (const p of this.pages) {
            p.wrap.style.width = `${Math.floor(p.width * scale)}px`;
            p.wrap.style.height = `${Math.floor(p.height * scale)}px`;
            p.rendered = false;
        }
    }

    async draw(index) {
        const p = this.pages[index];
        if (!p || p.rendered || this.pending.has(index)) return;
        this.pending.add(index);
        try {
            p.viewport = await renderForPlacement(
                doc.pdf, index + 1, p.canvas, p.width * this.scale);
            p.rendered = true;
            p.layer.textContent = '';
            this.onOverlay?.(index, p.layer, p.viewport);
        } catch {
            /* a page that will not render simply stays blank */
        } finally {
            this.pending.delete(index);
        }
    }

    redrawOverlays() {
        for (const [index, p] of this.pages.entries()) {
            if (!p.rendered) continue;
            p.layer.textContent = '';
            this.onOverlay?.(index, p.layer, p.viewport);
        }
    }

    setCurrent(index) {
        if (this.current === index) return;
        this.current = index;
        this.onPage?.(index);
    }

    /* Zooming keeps the point under the cursor — or the middle of the view —
     * where it was, which is what makes zoom feel like a lens and not a jump. */
    setZoom(next, anchor) {
        const before = this.scale;
        this.zoom = next;
        const after = this.scale;
        const ratio = after / before;
        const s = this.scroller;
        const ax = anchor?.x ?? s.clientWidth / 2;
        const ay = anchor?.y ?? s.clientHeight / 2;
        const left = (s.scrollLeft + ax) * ratio - ax;
        const top = (s.scrollTop + ay) * ratio - ay;
        this.layout();
        s.scrollLeft = left;
        s.scrollTop = top;
        for (const [index, p] of this.pages.entries()) {
            if (this.near(p)) this.draw(index);
        }
    }

    near(p) {
        const box = p.wrap.getBoundingClientRect();
        const view = this.scroller.getBoundingClientRect();
        return box.bottom > view.top - 400 && box.top < view.bottom + 400;
    }

    zoomBy(direction, anchor) {
        const current = this.scale;
        const stops = ZOOM_STOPS;
        const next = direction > 0
            ? stops.find((z) => z > current + 0.001)
            : [...stops].reverse().find((z) => z < current - 0.001);
        if (next) this.setZoom(next, anchor);
    }

    goTo(index) {
        const p = this.pages[index];
        if (!p) return;
        this.scroller.scrollTo({ top: p.wrap.offsetTop - 14, behavior: 'smooth' });
    }

    /* A click anywhere in the scroller, answered in PDF points on a page. */
    locate(event) {
        for (const [index, p] of this.pages.entries()) {
            if (!p.rendered) continue;
            const box = p.canvas.getBoundingClientRect();
            if (event.clientX < box.left || event.clientX > box.right) continue;
            if (event.clientY < box.top || event.clientY > box.bottom) continue;
            const [x, y] = p.viewport.convertToPdfPoint(
                event.clientX - box.left, event.clientY - box.top);
            return { pageIndex: index, x, y, viewport: p.viewport, layer: p.layer };
        }
        return null;
    }
}

/* ── Thumbnails ──────────────────────────────────────────────────────────── */

export async function paintThumbnails(rail, { current, onPick, onReorder }) {
    rail.textContent = '';
    const count = doc.pdf.numPages;
    for (let i = 0; i < count; i += 1) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'wb-thumb';
        button.dataset.index = String(i);
        button.setAttribute('aria-current', String(i === current));
        if (onReorder) button.draggable = true;
        const shell = document.createElement('span');
        shell.className = 'wb-thumb-page';
        const canvas = document.createElement('canvas');
        shell.append(canvas);
        const label = document.createElement('span');
        label.className = 'wb-thumb-num';
        label.textContent = String(i + 1);
        button.append(shell, label);
        button.addEventListener('click', () => onPick(i));
        rail.append(button);
        renderThumbnail(doc.pdf, i + 1, canvas, 118).catch(() => {});
    }
    if (onReorder) enableReorder(rail, onReorder);
}

/* Drag a thumbnail to a new position. The order it produces is the new page
 * sequence, handed to the reorder engine, which copies pages — it never
 * rebuilds them, so the reordered pages are byte-identical to the originals. */
function enableReorder(rail, onReorder) {
    let dragging = null;
    rail.addEventListener('dragstart', (e) => {
        dragging = e.target.closest('.wb-thumb');
        if (dragging) dragging.classList.add('wb-thumb-dragging');
    });
    rail.addEventListener('dragend', () => {
        dragging?.classList.remove('wb-thumb-dragging');
        dragging = null;
    });
    rail.addEventListener('dragover', (e) => {
        e.preventDefault();
        const over = e.target.closest('.wb-thumb');
        if (!over || over === dragging || !dragging) return;
        const rect = over.getBoundingClientRect();
        const after = (e.clientY - rect.top) > rect.height / 2;
        rail.insertBefore(dragging, after ? over.nextSibling : over);
    });
    rail.addEventListener('drop', (e) => {
        e.preventDefault();
        const order = [...rail.querySelectorAll('.wb-thumb')]
            .map((t) => Number(t.dataset.index));
        // No change if the sequence is still 0,1,2,…
        if (order.some((v, i) => v !== i)) onReorder(order);
    });
}
