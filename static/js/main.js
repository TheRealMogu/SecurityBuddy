/* Security Buddy — Main JS */

document.addEventListener('DOMContentLoaded', function () {
    initToasts();
    initTableSort();
    initInlineValidation();
    initPasswordStrength();
    initPasswordToggle();
    initFab();
    initCopyData();
});

/* ── Validate & clean domain/IP ─────────────────────────────────────────── */
function validateTarget(target) {
    if (!target) return false;
    target = cleanTarget(target);
    const ip     = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const domain = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return ip.test(target) || domain.test(target);
}

function cleanTarget(target) {
    return target
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .toLowerCase()
        .trim();
}

/* ── Generic clipboard helper ────────────────────────────────────────────── */
function copyText(text) {
    return navigator.clipboard.writeText(text);
}

/* ── data-copy attribute handler ────────────────────────────────────────── */
function initCopyData() {
    document.querySelectorAll('[data-copy]').forEach(btn => {
        btn.addEventListener('click', function () {
            copyText(this.dataset.copy).then(() => showToast('success', 'Copied to clipboard!'));
        });
    });
}

/* ── Toast notifications ─────────────────────────────────────────────────── */
const TOAST_ICONS = {
    success: '✓',
    warning: '⚠',
    error:   '✕',
    danger:  '✕',
    info:    'ℹ',
};
const TOAST_DURATION = 4000;

function showToast(category, message) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const existing = container.querySelectorAll('.app-toast');
    if (existing.length >= 4) existing[0].remove();

    const cat  = category || 'info';
    const icon = TOAST_ICONS[cat] || 'ℹ';

    const toast = document.createElement('div');
    toast.className = `app-toast app-toast-${cat}`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
      <div class="app-toast-body">
        <span class="app-toast-icon">${icon}</span>
        <span class="app-toast-text">${message}</span>
        <button class="app-toast-close" aria-label="Close">×</button>
      </div>
      <div class="app-toast-progress" style="animation-duration:${TOAST_DURATION}ms;"></div>`;

    container.appendChild(toast);
    toast.querySelector('.app-toast-close').addEventListener('click', () => dismissToast(toast));
    toast._timer = setTimeout(() => dismissToast(toast), TOAST_DURATION);
}

function dismissToast(toast) {
    clearTimeout(toast._timer);
    toast.classList.add('toast-hiding');
    toast.addEventListener('transitionend', () => toast.remove(), { once: true });
}

function initToasts() {
    const dataEl = document.getElementById('flash-data');
    if (!dataEl) return;
    try {
        const messages = JSON.parse(dataEl.textContent);
        setTimeout(() => {
            messages.forEach(([cat, msg]) => showToast(cat, msg));
        }, 150);
    } catch (_) { /* skip malformed JSON */ }
}

/* ── Sortable table ──────────────────────────────────────────────────────── */
function initTableSort() {
    const table = document.getElementById('scansTable');
    if (!table) return;

    const headers = table.querySelectorAll('th.sortable-th');
    let currentCol = null, currentDir = 'asc';

    headers.forEach(th => {
        th.addEventListener('click', () => {
            const col  = parseInt(th.dataset.col, 10);
            const type = th.dataset.type;

            if (currentCol === col) {
                currentDir = currentDir === 'asc' ? 'desc' : 'asc';
            } else {
                currentCol = col;
                currentDir = 'asc';
            }

            headers.forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
                const ico = h.querySelector('.sort-icon');
                if (ico) ico.textContent = '⇅';
            });
            th.classList.add(currentDir === 'asc' ? 'sort-asc' : 'sort-desc');
            const ico = th.querySelector('.sort-icon');
            if (ico) ico.textContent = currentDir === 'asc' ? '↑' : '↓';

            const tbody = table.querySelector('tbody');
            const rows  = Array.from(tbody.querySelectorAll('tr'));
            rows.sort((a, b) => {
                const aCell = a.cells[col], bCell = b.cells[col];
                const aRaw  = aCell.dataset.sortValue ?? aCell.textContent.trim();
                const bRaw  = bCell.dataset.sortValue ?? bCell.textContent.trim();
                let cmp = type === 'num'
                    ? parseFloat(aRaw) - parseFloat(bRaw)
                    : aRaw.localeCompare(bRaw, undefined, { sensitivity: 'base' });
                return currentDir === 'asc' ? cmp : -cmp;
            });
            rows.forEach(r => tbody.appendChild(r));
        });
    });
}

/* ── Inline form validation ─────────────────────────────────────────────── */
function setFieldError(inputId, errorId, message) {
    const input = document.getElementById(inputId);
    const error = document.getElementById(errorId);
    if (!input || !error) return;
    error.textContent = message;
    input.classList.toggle('is-invalid', !!message);
}

function clearFieldError(inputId, errorId) {
    setFieldError(inputId, errorId, '');
}

function initInlineValidation() {
    /* Login */
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', e => {
            let ok = true;
            if (!document.getElementById('loginUsername')?.value.trim()) {
                setFieldError('loginUsername', 'loginUsernameError', 'Please enter your username.');
                ok = false;
            } else clearFieldError('loginUsername', 'loginUsernameError');

            if (!document.getElementById('loginPassword')?.value) {
                setFieldError('loginPassword', 'loginPasswordError', 'Please enter your password.');
                ok = false;
            } else clearFieldError('loginPassword', 'loginPasswordError');

            if (!ok) e.preventDefault();
        });
        ['loginUsername', 'loginPassword'].forEach(id => {
            document.getElementById(id)?.addEventListener('input', () => clearFieldError(id, id + 'Error'));
        });
    }

    /* Register */
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', e => {
            let ok = true;

            const user = document.getElementById('registerUsername');
            if (!user || user.value.trim().length < 3) {
                setFieldError('registerUsername', 'registerUsernameError', 'Username must be at least 3 characters.');
                ok = false;
            } else clearFieldError('registerUsername', 'registerUsernameError');

            const email = document.getElementById('registerEmail');
            if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) {
                setFieldError('registerEmail', 'registerEmailError', 'Please enter a valid email address.');
                ok = false;
            } else clearFieldError('registerEmail', 'registerEmailError');

            const pw = document.getElementById('registerPassword');
            if (!pw || pw.value.length < 6) {
                setFieldError('registerPassword', 'registerPasswordError', 'Password must be at least 6 characters.');
                ok = false;
            } else clearFieldError('registerPassword', 'registerPasswordError');

            const terms = document.getElementById('agreeTerms');
            if (!terms || !terms.checked) {
                setFieldError('agreeTerms', 'agreeTermsError', 'You must accept the Terms of Service.');
                ok = false;
            } else clearFieldError('agreeTerms', 'agreeTermsError');

            if (!ok) e.preventDefault();
        });
        ['registerUsername', 'registerEmail', 'registerPassword'].forEach(id => {
            document.getElementById(id)?.addEventListener('input', () => clearFieldError(id, id + 'Error'));
        });
    }
}

/* ── Password strength ───────────────────────────────────────────────────── */
function calcStrength(pw) {
    let s = 0;
    if (pw.length >= 8)  s++;
    if (pw.length >= 12) s++;
    if (/[A-Z]/.test(pw)) s++;
    if (/[0-9]/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    if (s <= 1) return { level: 'weak',   label: 'Weak' };
    if (s <= 3) return { level: 'medium', label: 'Medium' };
    return              { level: 'strong', label: 'Strong' };
}

function initPasswordStrength() {
    const input   = document.getElementById('registerPassword');
    const wrapper = document.getElementById('passwordStrengthWrapper');
    const label   = document.getElementById('passwordStrengthLabel');
    if (!input || !wrapper || !label) return;

    input.addEventListener('input', () => {
        const val = input.value;
        wrapper.style.display = val ? 'block' : 'none';
        if (!val) return;
        const { level, label: text } = calcStrength(val);
        wrapper.className = `password-strength mt-2 strength-${level}`;
        label.textContent = `Strength: ${text}`;
    });
}

/* ── Password show/hide ─────────────────────────────────────────────────── */
function initPasswordToggle() {
    document.querySelectorAll('.btn-toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = document.getElementById(btn.dataset.target);
            if (!input) return;
            input.type = input.type === 'password' ? 'text' : 'password';
            btn.setAttribute('aria-pressed', String(input.type === 'text'));
        });
    });
}

/* ── FAB (reveal on scroll) ─────────────────────────────────────────────── */
function initFab() {
    const fab = document.getElementById('fabRescan');
    if (!fab) return;
    function check() {
        fab.classList.toggle('fab-visible', window.scrollY > 200);
    }
    window.addEventListener('scroll', check, { passive: true });
    check();
}

/* ── Module exports (CLI/testing) ────────────────────────────────────────── */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { validateTarget, cleanTarget };
}
