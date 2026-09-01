/* Security Buddy — full-screen page viewer.
 *
 * Available from every tool that shows pages. A 130px thumbnail is enough to
 * recognise a page but not to decide anything about it: whether this is the
 * annex you meant to drop, whether that page really is upside down, whether the
 * form field you are about to fill is the one you think it is. The viewer
 * answers those without leaving the tool.
 *
 * It renders through the same pdf.js path as the thumbnails, so a page never
 * looks different up close than it did small, and it never participates in
 * writing an output file.
 */

import { renderToFit } from './preview.js';

let overlay = null;
let session = null;

function build() {
    if (overlay) return overlay;

    overlay = document.createElement('div');
    overlay.className = 'pdf-viewer';
    overlay.hidden = true;
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Page preview');

    overlay.innerHTML = `
        <div class="pdf-viewer-bar">
            <span class="pdf-viewer-title" data-role="title"></span>
            <span class="pdf-viewer-meta" data-role="meta"></span>
            <span class="pdf-viewer-spacer"></span>
            <button type="button" class="pdf-viewer-btn" data-role="prev"
                    aria-label="Previous page">&#9664;</button>
            <span class="pdf-viewer-count" data-role="count"></span>
            <button type="button" class="pdf-viewer-btn" data-role="next"
                    aria-label="Next page">&#9654;</button>
            <button type="button" class="pdf-viewer-btn pdf-viewer-close" data-role="close"
                    aria-label="Close preview">&#10005;</button>
        </div>
        <div class="pdf-viewer-stage" data-role="stage">
            <canvas data-role="canvas"></canvas>
        </div>
        <p class="pdf-viewer-hint">Arrow keys to move between pages · Esc to close</p>
    `;

    overlay.querySelector('[data-role="close"]').addEventListener('click', close);
    overlay.querySelector('[data-role="prev"]').addEventListener('click', () => step(-1));
    overlay.querySelector('[data-role="next"]').addEventListener('click', () => step(1));
    overlay.addEventListener('click', (event) => {
        // Clicking the backdrop closes; clicking the page or the bar does not.
        if (event.target === overlay) close();
    });

    document.body.append(overlay);
    return overlay;
}

function onKeydown(event) {
    if (!session) return;
    if (event.key === 'Escape') { event.preventDefault(); close(); }
    else if (event.key === 'ArrowLeft') { event.preventDefault(); step(-1); }
    else if (event.key === 'ArrowRight') { event.preventDefault(); step(1); }
}

/* `pages` is the sequence the tool is showing, in ITS order — so the viewer
 * walks a reordered document the way the user arranged it, not the way the file
 * happens to store it. Each entry is { pageIndex, label, rotation }. */
export async function open(pdf, pages, startAt, documentName) {
    if (!pdf || !pages.length) return;
    build();

    session = { pdf, pages, position: Math.max(0, Math.min(startAt, pages.length - 1)), documentName };
    overlay.hidden = false;
    document.body.style.overflow = 'hidden';
    document.addEventListener('keydown', onKeydown);
    overlay.querySelector('[data-role="close"]').focus();
    await paint();
}

export function close() {
    if (!overlay || overlay.hidden) return;
    overlay.hidden = true;
    document.body.style.overflow = '';
    document.removeEventListener('keydown', onKeydown);
    session = null;
}

function step(delta) {
    if (!session) return;
    const next = session.position + delta;
    if (next < 0 || next >= session.pages.length) return;
    session.position = next;
    paint();
}

async function paint() {
    if (!session) return;
    const entry = session.pages[session.position];
    const stage = overlay.querySelector('[data-role="stage"]');
    const canvas = overlay.querySelector('[data-role="canvas"]');

    overlay.querySelector('[data-role="title"]').textContent = session.documentName || '';
    overlay.querySelector('[data-role="count"]').textContent =
        `${session.position + 1} / ${session.pages.length}`;
    overlay.querySelector('[data-role="prev"]').disabled = session.position === 0;
    overlay.querySelector('[data-role="next"]').disabled =
        session.position === session.pages.length - 1;

    const box = stage.getBoundingClientRect();
    try {
        const info = await renderToFit(
            session.pdf, entry.pageIndex + 1, canvas,
            Math.max(box.width - 32, 200), Math.max(box.height - 32, 200),
            entry.rotation || 0,
        );
        const size = `${Math.round(info.width)} × ${Math.round(info.height)} pt`;
        overlay.querySelector('[data-role="meta"]').textContent =
            `${entry.label} · ${size}` + (info.rotation ? ` · rotated ${info.rotation}°` : '');
    } catch (err) {
        overlay.querySelector('[data-role="meta"]').textContent =
            'This page could not be rendered for preview.';
    }
}

/* Re-render on resize so the page keeps filling the window. */
let resizeTimer = null;
window.addEventListener('resize', () => {
    if (!session) return;
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(paint, 120);
});
