// Security Buddy Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize user-friendly features
    initializeUserGuidance();
    initializeTutorial();
    addSecurityTooltips();
    improveAccessibility();

    // Scan form validation and enhancement
    const scanForm = document.querySelector('.scan-form');
    if (scanForm) {
        const targetInput = scanForm.querySelector('input[name="target"]');
        const submitButton = scanForm.querySelector('button[type="submit"]');
        
        // Real-time validation
        targetInput.addEventListener('input', function() {
            const value = this.value.trim();
            const isValid = validateTarget(value);
            
            if (value && !isValid) {
                this.classList.add('is-invalid');
                submitButton.disabled = true;
            } else {
                this.classList.remove('is-invalid');
                submitButton.disabled = false;
            }
        });

        // Form submission handling
        scanForm.addEventListener('submit', function(e) {
            const target = targetInput.value.trim();
            
            if (!target) {
                e.preventDefault();
                showAlert('Please enter a domain or IP address.', 'warning');
                return;
            }
            
            if (!validateTarget(target)) {
                e.preventDefault();
                showAlert('Please enter a valid domain or IP address.', 'error');
                return;
            }

            // Show loading state with progress simulation
            showScanProgress();
            
            // Clean up the target input
            targetInput.value = cleanTarget(target);
        });
    }

    // Auto-refresh scan results (for long-running scans)
    const scanResult = document.querySelector('.scan-result');
    if (scanResult && scanResult.dataset.scanId) {
        // Could implement WebSocket or polling for real-time updates
        console.log('Scan result loaded for ID:', scanResult.dataset.scanId);
    }

    // Copy to clipboard functionality
    document.querySelectorAll('[data-copy]').forEach(button => {
        button.addEventListener('click', function() {
            const text = this.dataset.copy;
            navigator.clipboard.writeText(text).then(() => {
                showAlert('Copied to clipboard!', 'success');
            }).catch(() => {
                showAlert('Failed to copy to clipboard.', 'error');
            });
        });
    });

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Auto-hide alerts after 5 seconds
    document.querySelectorAll('.alert:not(.alert-persistent)').forEach(alert => {
        if (!alert.querySelector('.btn-close')) {
            setTimeout(() => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        }
    });

    // Initialize progress bars with animation
    document.querySelectorAll('.progress-bar').forEach(bar => {
        const width = bar.style.width || bar.getAttribute('aria-valuenow') + '%';
        bar.style.width = '0%';
        setTimeout(() => {
            bar.style.width = width;
            bar.style.transition = 'width 1s ease-in-out';
        }, 100);
    });

    // Enhanced table interactions
    document.querySelectorAll('.table-hover tbody tr').forEach(row => {
        row.addEventListener('click', function(e) {
            // If the click was on a button or link, don't trigger row click
            if (e.target.closest('button, a')) return;
            
            const viewButton = this.querySelector('a[href*="/scan/"]');
            if (viewButton) {
                window.location.href = viewButton.href;
            }
        });
    });
});

/**
 * Validate domain or IP address
 */
function validateTarget(target) {
    if (!target) return false;
    
    // Clean the target first
    target = cleanTarget(target);
    
    // IP address pattern
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    
    // Domain pattern (basic)
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    return ipPattern.test(target) || domainPattern.test(target);
}

/**
 * Clean target input (remove protocols, trailing slashes, etc.)
 */
function cleanTarget(target) {
    return target
        .replace(/^https?:\/\//, '')  // Remove protocol
        .replace(/\/$/, '')           // Remove trailing slash
        .replace(/\/.*$/, '')         // Remove path
        .toLowerCase()
        .trim();
}

/**
 * Show alert message
 */
function showAlert(message, type = 'info') {
    const alertContainer = document.querySelector('.container');
    if (!alertContainer) return;
    
    const alertHtml = `
        <div class="alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show mt-3" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    alertContainer.insertAdjacentHTML('afterbegin', alertHtml);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        const alert = alertContainer.querySelector('.alert');
        if (alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }
    }, 5000);
}

/**
 * Format security score with color coding
 */
function formatSecurityScore(score) {
    let className = 'score-danger';
    if (score >= 80) className = 'score-success';
    else if (score >= 60) className = 'score-warning';
    
    return `<span class="score-badge ${className}">${score}/100</span>`;
}

/**
 * Format risk level badge
 */
function formatRiskLevel(score) {
    let level = 'critical';
    let className = 'danger';
    
    if (score >= 80) {
        level = 'low';
        className = 'success';
    } else if (score >= 60) {
        level = 'medium';
        className = 'warning';
    } else if (score >= 40) {
        level = 'high';
        className = 'danger';
    }
    
    return `<span class="badge bg-${className}">${level.charAt(0).toUpperCase() + level.slice(1)}</span>`;
}

/**
 * Enhanced clipboard functionality with feedback
 */
function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = button.innerHTML;
        button.innerHTML = '<i data-feather="check" class="me-2"></i>Copied!';
        button.classList.add('btn-success');
        button.classList.remove('btn-outline-secondary');
        
        // Reset after 2 seconds
        setTimeout(() => {
            button.innerHTML = originalText;
            button.classList.remove('btn-success');
            button.classList.add('btn-outline-secondary');
            // Re-initialize feather icons
            feather.replace();
        }, 2000);
    }).catch(() => {
        showAlert('Failed to copy to clipboard.', 'error');
    });
}

/**
 * Debounce function for input validation
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Check if element is in viewport
 */
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

/**
 * Animate counters
 */
function animateCounters() {
    document.querySelectorAll('.stat-number').forEach(counter => {
        const target = parseInt(counter.textContent);
        const increment = target / 50;
        let current = 0;
        
        const timer = setInterval(() => {
            current += increment;
            counter.textContent = Math.floor(current);
            
            if (current >= target) {
                counter.textContent = target;
                clearInterval(timer);
            }
        }, 20);
    });
}

// Initialize counter animation when stats come into view
const statsSection = document.querySelector('.stat-card');
if (statsSection) {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateCounters();
                observer.unobserve(entry.target);
            }
        });
    });
    
    observer.observe(statsSection);
}

// Service Worker registration for future PWA features
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        // navigator.registerSW('/sw.js'); // Uncomment when PWA features are added
    });
}

/**
 * Show scan progress with animated steps
 */
function showScanProgress() {
    const loadingIndicator = document.getElementById('loadingIndicator');
    const scanButton = document.getElementById('scanButton');
    const progressBar = document.getElementById('progressBar');
    const loadingStep = document.getElementById('loadingStep');
    
    if (!loadingIndicator || !scanButton || !progressBar || !loadingStep) return;
    
    // Show loading indicator and disable button
    loadingIndicator.style.display = 'block';
    scanButton.disabled = true;
    scanButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Scanning...';
    
    // Simulate progress steps
    const steps = [
        { text: 'Checking connectivity...', progress: 20 },
        { text: 'Verifying HTTPS and SSL...', progress: 40 },
        { text: 'Analyzing security headers...', progress: 60 },
        { text: 'Gathering domain information...', progress: 80 },
        { text: 'Calculating security score...', progress: 100 }
    ];
    
    let currentStep = 0;
    
    const progressInterval = setInterval(() => {
        if (currentStep < steps.length) {
            const step = steps[currentStep];
            loadingStep.textContent = step.text;
            progressBar.style.width = step.progress + '%';
            currentStep++;
        } else {
            clearInterval(progressInterval);
        }
    }, 800);
}

/**
 * Initialize user guidance features for non-technical users
 */
function initializeUserGuidance() {
    // Add helpful explanations to the main form
    const targetInput = document.getElementById('targetInput');
    if (targetInput) {
        // Add example text and guidance
        targetInput.addEventListener('focus', function() {
            if (!document.querySelector('.input-help')) {
                const helpText = document.createElement('div');
                helpText.className = 'input-help mt-2';
                helpText.innerHTML = `
                    <small class="text-muted">
                        <i data-feather="help-circle" style="width: 14px; height: 14px;"></i>
                        <strong>Examples:</strong> example.com, shop.acme.io, 192.168.1.1
                        &nbsp;—&nbsp; no need to type <code>www</code> or <code>https://</code>
                    </small>
                `;
                targetInput.parentNode.appendChild(helpText);
                feather.replace();
            }
        });
    }

    // Add encouraging messages
    addEncouragingMessages();
}

/**
 * Add encouraging messages throughout the interface
 */
function addEncouragingMessages() {
    // no-op: score ring handles visual feedback
}

/**
 * Initialize interactive tutorial for first-time users
 */
function initializeTutorial() {
    // Check if user has seen tutorial
    if (!localStorage.getItem('security_buddy_tutorial_completed')) {
        // Show tutorial only on homepage
        if (window.location.pathname === '/' || window.location.pathname === '') {
            setTimeout(startTutorial, 1000);
        }
    }

    // Add tutorial trigger button
    addTutorialButton();
}

/**
 * Start the interactive tutorial
 */
function startTutorial() {
    const tutorialSteps = [
        {
            target: '#scanForm',
            title: 'Welcome to Security Buddy',
            content: 'Run instant security checks on any domain or IP — no account required.',
            position: 'bottom'
        },
        {
            target: '#targetInput',
            title: 'Enter a target',
            content: 'Type a domain (e.g. example.com) or IP address. No need for https:// or www.',
            position: 'bottom'
        },
        {
            target: '#scanButton',
            title: 'Run the scan',
            content: 'Click to start 12+ automated security checks. Results are ready in under 30 seconds.',
            position: 'bottom'
        },
        {
            target: '.feature-card',
            title: 'What we check',
            content: 'HTTPS, SSL, headers, cookies, CORS, open ports, tech fingerprinting and more.',
            position: 'top'
        }
    ];

    let currentStep = 0;
    const overlay = createTutorialOverlay();
    
    function showStep(stepIndex) {
        if (stepIndex >= tutorialSteps.length) {
            completeTutorial();
            return;
        }

        const step = tutorialSteps[stepIndex];
        const target = document.querySelector(step.target);
        
        if (!target) {
            showStep(stepIndex + 1);
            return;
        }

        // Highlight target
        target.classList.add('tutorial-highlight');
        
        // Create step popup
        const stepPopup = createStepPopup(step, stepIndex, tutorialSteps.length);
        positionStepPopup(stepPopup, target, step.position);
        
        overlay.appendChild(stepPopup);
        overlay.style.display = 'block';

        // Next button handler
        stepPopup.querySelector('.tutorial-next').onclick = () => {
            target.classList.remove('tutorial-highlight');
            stepPopup.remove();
            showStep(stepIndex + 1);
        };

        // Skip tutorial handler
        stepPopup.querySelector('.tutorial-skip').onclick = () => {
            completeTutorial();
        };
    }

    function completeTutorial() {
        overlay.style.display = 'none';
        document.querySelectorAll('.tutorial-highlight').forEach(el => {
            el.classList.remove('tutorial-highlight');
        });
        localStorage.setItem('security_buddy_tutorial_completed', 'true');
        showAlert('You\'re all set — enter a domain and start scanning!', 'success');
    }

    showStep(0);
}

/**
 * Create tutorial overlay
 */
function createTutorialOverlay() {
    let overlay = document.querySelector('.tutorial-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.className = 'tutorial-overlay';
        document.body.appendChild(overlay);
    }
    return overlay;
}

/**
 * Create step popup
 */
function createStepPopup(step, stepIndex, totalSteps) {
    const popup = document.createElement('div');
    popup.className = `tutorial-step ${step.position}`;
    popup.innerHTML = `
        <div class="tutorial-header">
            <h5>${step.title}</h5>
            <span class="tutorial-progress">${stepIndex + 1}/${totalSteps}</span>
        </div>
        <p>${step.content}</p>
        <div class="tutorial-actions">
            <button class="btn btn-outline-secondary btn-sm tutorial-skip">Salta tutorial</button>
            <button class="btn btn-primary btn-sm tutorial-next">
                ${stepIndex === totalSteps - 1 ? 'Completa' : 'Avanti'} →
            </button>
        </div>
    `;
    return popup;
}

/**
 * Position step popup relative to target
 */
function positionStepPopup(popup, target, position) {
    // Wait for popup to be rendered
    setTimeout(() => {
        const targetRect = target.getBoundingClientRect();
        
        let top, left;
        const popupWidth = 300;
        const popupHeight = popup.offsetHeight || 200;
        
        if (position === 'bottom') {
            top = targetRect.bottom + 20;
            left = targetRect.left + (targetRect.width / 2) - (popupWidth / 2);
        } else if (position === 'top') {
            top = targetRect.top - popupHeight - 20;
            left = targetRect.left + (targetRect.width / 2) - (popupWidth / 2);
        }
        
        // Keep popup within viewport
        left = Math.max(20, Math.min(left, window.innerWidth - popupWidth - 20));
        top = Math.max(20, Math.min(top, window.innerHeight - popupHeight - 20));
        
        popup.style.top = top + 'px';
        popup.style.left = left + 'px';
        popup.style.position = 'fixed';
        popup.style.zIndex = '10000';
    }, 50);
}

/**
 * Add tutorial button to navigation
 */
function addTutorialButton() {
    const nav = document.querySelector('.navbar-nav');
    if (nav && !document.querySelector('.tutorial-trigger')) {
        const tutorialBtn = document.createElement('li');
        tutorialBtn.className = 'nav-item tutorial-trigger';
        tutorialBtn.innerHTML = `
            <a class="nav-link" href="#" onclick="startTutorial(); return false;">
                <i data-feather="help-circle" class="me-1"></i>Help
            </a>
        `;
        nav.appendChild(tutorialBtn);
        feather.replace();
    }
}

/**
 * Add security tooltips for technical terms
 */
function addSecurityTooltips() {
    const securityTerms = {
        'HSTS': 'HTTP Strict Transport Security — forces browsers to use HTTPS',
        'CSP': 'Content Security Policy — prevents XSS and injection attacks',
        'CORS': 'Cross-Origin Resource Sharing — controls which origins can call your API',
        'HttpOnly': 'Prevents JavaScript from reading the cookie — blocks XSS cookie theft',
        'SameSite': 'Protects against CSRF attacks by restricting cross-site cookie sending'
    };

    // Find and enhance security terms
    Object.keys(securityTerms).forEach(term => {
        const regex = new RegExp(`\\b${term}\\b`, 'gi');
        document.querySelectorAll('p, li, div:not(.security-tooltip)').forEach(element => {
            if (element.children.length === 0) { // Only text nodes
                const newHTML = element.innerHTML.replace(regex, 
                    `<span class="security-tooltip" data-tooltip="${securityTerms[term]}">$&</span>`
                );
                if (newHTML !== element.innerHTML) {
                    element.innerHTML = newHTML;
                }
            }
        });
    });
}

/**
 * Improve accessibility for non-technical users
 */
function improveAccessibility() {
    // Add ARIA labels for screen readers
    document.querySelectorAll('.security-score').forEach(scoreEl => {
        const score = scoreEl.textContent;
        scoreEl.setAttribute('aria-label', `Security score: ${score} out of 100`);
    });

    // Add keyboard navigation for tooltips
    document.querySelectorAll('.security-tooltip').forEach(tooltip => {
        tooltip.setAttribute('tabindex', '0');
        tooltip.addEventListener('focus', function() {
            this.classList.add('tooltip-focused');
        });
        tooltip.addEventListener('blur', function() {
            this.classList.remove('tooltip-focused');
        });
    });

    // Improve form accessibility
    const targetInput = document.getElementById('targetInput');
    if (targetInput) {
        targetInput.setAttribute('aria-describedby', 'target-help');
        
        // Add screen reader friendly description
        const helpDesc = document.createElement('div');
        helpDesc.id = 'target-help';
        helpDesc.className = 'sr-only';
        helpDesc.textContent = 'Enter the domain or IP address to scan, e.g. example.com';
        targetInput.parentNode.appendChild(helpDesc);
    }
}

/**
 * Enhanced progress display with user-friendly messages
 */
function showScanProgress() {
    const loadingIndicator = document.getElementById('loadingIndicator');
    const scanButton = document.getElementById('scanButton');
    const progressBar = document.getElementById('progressBar');
    const loadingStep = document.getElementById('loadingStep');
    
    if (!loadingIndicator || !scanButton || !progressBar || !loadingStep) return;
    
    // Show loading indicator and disable button
    loadingIndicator.style.display = 'block';
    scanButton.disabled = true;
    scanButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Scanning...';

    const steps = [
        { text: 'Checking connectivity...', progress: 12 },
        { text: 'Verifying HTTPS & SSL certificate...', progress: 28 },
        { text: 'Checking security headers...', progress: 44 },
        { text: 'Auditing cookie flags...', progress: 58 },
        { text: 'Analysing CORS & HTTP methods...', progress: 72 },
        { text: 'Scanning open ports...', progress: 86 },
        { text: 'Calculating security score...', progress: 100 }
    ];
    
    let currentStep = 0;
    
    const progressInterval = setInterval(() => {
        if (currentStep < steps.length) {
            const step = steps[currentStep];
            loadingStep.textContent = step.text;
            progressBar.style.width = step.progress + '%';
            progressBar.setAttribute('aria-valuenow', step.progress);
            currentStep++;
        } else {
            clearInterval(progressInterval);
        }
    }, 1200); // Slower, more reassuring pace
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Feather icons first
    if (typeof feather !== 'undefined') {
        feather.replace();
    }

    // Initialize user guidance
    initializeUserGuidance();

    // Animate counters when they come into view
    animateCounters();

    // Add security tooltips
    addSecurityTooltips();

    // Improve accessibility
    improveAccessibility();

    /* ---- NEW UX FEATURES ---- */
    initToasts();
    initScoreRing();
    initTableSort();
    initInlineValidation();
    initPasswordStrength();
    initPasswordToggle();
    initFab();
});

/* =======================================================================
   TOAST NOTIFICATIONS
   Reads flash messages serialised in #flash-data and shows them as toasts.
   ======================================================================= */
const TOAST_ICONS = {
    success: '✓',
    warning: '⚠',
    error:   '✕',
    danger:  '✕',
    info:    'ℹ',
};
const TOAST_DURATION = 4000; // ms

function showToast(category, message) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    // Cap at 4 visible toasts
    const existing = container.querySelectorAll('.app-toast');
    if (existing.length >= 4) existing[0].remove();

    const cat = category === 'error' ? 'error' : category;
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

    const closeBtn = toast.querySelector('.app-toast-close');
    closeBtn.addEventListener('click', () => dismissToast(toast));

    const timer = setTimeout(() => dismissToast(toast), TOAST_DURATION);
    toast._toastTimer = timer;
}

function dismissToast(toast) {
    clearTimeout(toast._toastTimer);
    toast.classList.add('toast-hiding');
    toast.addEventListener('transitionend', () => toast.remove(), { once: true });
}

function initToasts() {
    const dataEl = document.getElementById('flash-data');
    if (!dataEl) return;
    try {
        const messages = JSON.parse(dataEl.textContent);
        // Small delay so the page renders first
        setTimeout(() => {
            messages.forEach(([cat, msg]) => showToast(cat, msg));
        }, 150);
    } catch (e) { /* malformed JSON — skip */ }
}

/* =======================================================================
   ANIMATED SVG SCORE RING
   ======================================================================= */
function initScoreRing() {
    const wrapper = document.querySelector('.score-ring-wrapper');
    if (!wrapper) return;

    const score    = parseInt(wrapper.dataset.score, 10) || 0;
    const fill     = document.getElementById('scoreRingFill');
    const numEl    = document.getElementById('scoreRingNumber');
    if (!fill || !numEl) return;

    const CIRCUMFERENCE = 2 * Math.PI * 45; // r=45 → 282.74

    // Start hidden, animate after a short delay
    fill.style.strokeDashoffset = CIRCUMFERENCE;

    requestAnimationFrame(() => {
        setTimeout(() => {
            const offset = CIRCUMFERENCE * (1 - score / 100);
            fill.style.strokeDashoffset = offset;
        }, 100);
    });

    // Counter animation for the number
    const duration = 900;
    const start = performance.now();
    function tick(now) {
        const elapsed = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - elapsed, 3); // ease-out cubic
        numEl.textContent = Math.round(eased * score);
        if (elapsed < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

/* =======================================================================
   SORTABLE TABLE
   ======================================================================= */
function initTableSort() {
    const table = document.getElementById('scansTable');
    if (!table) return;

    const headers = table.querySelectorAll('th.sortable-th');
    let currentCol = null, currentDir = 'asc';

    headers.forEach(th => {
        th.addEventListener('click', () => {
            const col     = parseInt(th.dataset.col, 10);
            const type    = th.dataset.type; // 'text' | 'num'

            if (currentCol === col) {
                currentDir = currentDir === 'asc' ? 'desc' : 'asc';
            } else {
                currentCol = col;
                currentDir = 'asc';
            }

            // Update sort icon labels
            headers.forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
                const ico = h.querySelector('.sort-icon');
                if (ico) ico.textContent = '⇅';
            });
            th.classList.add(currentDir === 'asc' ? 'sort-asc' : 'sort-desc');
            const ico = th.querySelector('.sort-icon');
            if (ico) ico.textContent = currentDir === 'asc' ? '↑' : '↓';

            // Sort rows
            const tbody = table.querySelector('tbody');
            const rows  = Array.from(tbody.querySelectorAll('tr'));

            rows.sort((a, b) => {
                const aCell = a.cells[col];
                const bCell = b.cells[col];
                // Prefer data-sort-value if present
                const aRaw = aCell.dataset.sortValue !== undefined
                    ? aCell.dataset.sortValue
                    : aCell.textContent.trim();
                const bRaw = bCell.dataset.sortValue !== undefined
                    ? bCell.dataset.sortValue
                    : bCell.textContent.trim();

                let cmp;
                if (type === 'num') {
                    cmp = parseFloat(aRaw) - parseFloat(bRaw);
                } else {
                    cmp = aRaw.localeCompare(bRaw, undefined, { sensitivity: 'base' });
                }
                return currentDir === 'asc' ? cmp : -cmp;
            });

            rows.forEach(r => tbody.appendChild(r));
        });
    });
}

/* =======================================================================
   INLINE FORM VALIDATION
   ======================================================================= */
function setFieldError(inputId, errorId, message) {
    const input = document.getElementById(inputId);
    const error = document.getElementById(errorId);
    if (!input || !error) return;
    error.textContent = message;
    if (message) {
        input.classList.add('is-invalid');
    } else {
        input.classList.remove('is-invalid');
    }
}

function clearFieldError(inputId, errorId) {
    setFieldError(inputId, errorId, '');
}

function initInlineValidation() {
    /* Login form */
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            let valid = true;
            const username = document.getElementById('loginUsername');
            const password = document.getElementById('loginPassword');

            if (!username || !username.value.trim()) {
                setFieldError('loginUsername', 'loginUsernameError', 'Please enter your username.');
                valid = false;
            } else {
                clearFieldError('loginUsername', 'loginUsernameError');
            }

            if (!password || !password.value) {
                setFieldError('loginPassword', 'loginPasswordError', 'Please enter your password.');
                valid = false;
            } else {
                clearFieldError('loginPassword', 'loginPasswordError');
            }

            if (!valid) e.preventDefault();
        });

        // Clear errors on input
        ['loginUsername', 'loginPassword'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('input', () => clearFieldError(id, id + 'Error'));
        });
    }

    /* Register form */
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            let valid = true;

            const username = document.getElementById('registerUsername');
            if (!username || username.value.trim().length < 3) {
                setFieldError('registerUsername', 'registerUsernameError', 'Username must be at least 3 characters.');
                valid = false;
            } else {
                clearFieldError('registerUsername', 'registerUsernameError');
            }

            const email = document.getElementById('registerEmail');
            if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) {
                setFieldError('registerEmail', 'registerEmailError', 'Please enter a valid email address.');
                valid = false;
            } else {
                clearFieldError('registerEmail', 'registerEmailError');
            }

            const password = document.getElementById('registerPassword');
            if (!password || password.value.length < 6) {
                setFieldError('registerPassword', 'registerPasswordError', 'Password must be at least 6 characters.');
                valid = false;
            } else {
                clearFieldError('registerPassword', 'registerPasswordError');
            }

            const terms = document.getElementById('agreeTerms');
            if (!terms || !terms.checked) {
                setFieldError('agreeTerms', 'agreeTermsError', 'You must accept the Terms of Service.');
                valid = false;
            } else {
                clearFieldError('agreeTerms', 'agreeTermsError');
            }

            if (!valid) e.preventDefault();
        });

        ['registerUsername', 'registerEmail', 'registerPassword'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('input', () => clearFieldError(id, id + 'Error'));
        });
    }
}

/* =======================================================================
   PASSWORD STRENGTH METER
   ======================================================================= */
function calcPasswordStrength(password) {
    let score = 0;
    if (password.length >= 8)  score++;
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (score <= 1) return { level: 'weak',   label: 'Weak' };
    if (score <= 3) return { level: 'medium',  label: 'Medium' };
    return              { level: 'strong',  label: 'Strong' };
}

function initPasswordStrength() {
    const input   = document.getElementById('registerPassword');
    const wrapper = document.getElementById('passwordStrengthWrapper');
    const label   = document.getElementById('passwordStrengthLabel');
    if (!input || !wrapper || !label) return;

    input.addEventListener('input', () => {
        const val = input.value;
        if (!val) {
            wrapper.style.display = 'none';
            return;
        }
        wrapper.style.display = 'block';
        const { level, label: text } = calcPasswordStrength(val);
        wrapper.className = `password-strength mt-2 strength-${level}`;
        label.textContent = `Strength: ${text}`;
    });
}

/* =======================================================================
   PASSWORD SHOW/HIDE TOGGLE
   ======================================================================= */
function initPasswordToggle() {
    document.querySelectorAll('.btn-toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.target;
            const input    = document.getElementById(targetId);
            if (!input) return;
            input.type = input.type === 'password' ? 'text' : 'password';
            btn.setAttribute('aria-pressed', input.type === 'text');
        });
    });
}

/* =======================================================================
   FAB RESCAN — reveal on scroll
   ======================================================================= */
function initFab() {
    const fab = document.getElementById('fabRescan');
    if (!fab) return;

    function checkScroll() {
        if (window.scrollY > 200) {
            fab.classList.add('fab-visible');
        } else {
            fab.classList.remove('fab-visible');
        }
    }
    window.addEventListener('scroll', checkScroll, { passive: true });
    checkScroll();
}

// Export functions for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        validateTarget,
        cleanTarget,
        formatSecurityScore,
        formatRiskLevel,
        showScanProgress,
        startTutorial,
        initializeUserGuidance
    };
}
