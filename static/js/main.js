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
                        <strong>Esempi:</strong> miosito.com, negozio.it, blog.wordpress.com
                        <br>💡 <strong>Suggerimento:</strong> Non serve scrivere "www" o "https://"
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
    const scoreElements = document.querySelectorAll('.score-value');
    scoreElements.forEach(scoreEl => {
        const score = parseInt(scoreEl.textContent);
        const encouragement = document.createElement('div');
        encouragement.className = 'encouragement-message mt-1';
        
        if (score >= 90) {
            encouragement.innerHTML = '<small class="text-success">🌟 Fantastico!</small>';
        } else if (score >= 70) {
            encouragement.innerHTML = '<small class="text-info">👍 Ottimo lavoro!</small>';
        } else if (score >= 50) {
            encouragement.innerHTML = '<small class="text-warning">💪 Quasi perfetto!</small>';
        } else {
            encouragement.innerHTML = '<small class="text-primary">🚀 Ti aiutiamo noi!</small>';
        }
        
        scoreEl.parentNode.appendChild(encouragement);
    });
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
            title: 'Benvenuto in Security Buddy! 👋',
            content: 'Ti aiuteremo a controllare quanto è sicuro il tuo sito web, spiegandoti tutto in modo semplice!',
            position: 'bottom'
        },
        {
            target: '#targetInput',
            title: 'Inserisci il tuo sito 🌐',
            content: 'Scrivi l\'indirizzo del tuo sito qui. Ad esempio: "miosito.com" (senza www o https)',
            position: 'bottom'
        },
        {
            target: '#scanButton',
            title: 'Avvia la scansione 🔍',
            content: 'Clicca qui e noi controlleremo tutto per te! Ti spiegheremo ogni risultato in parole semplici.',
            position: 'bottom'
        },
        {
            target: '.feature-card',
            title: 'Cosa controlliamo 📋',
            content: 'Verifichiamo che il tuo sito sia sicuro per te e per i tuoi visitatori. Non serve essere esperti!',
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
        
        // Show completion message
        showAlert('Perfetto! Ora sei pronto per controllare la sicurezza del tuo sito! 🎉', 'success');
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
                <i data-feather="help-circle" class="me-1"></i>Tutorial
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
        'HTTPS': 'Connessione sicura che protegge i dati',
        'SSL': 'Certificato che verifica l\'identità del sito',
        'Headers': 'Regole di sicurezza per il browser',
        'Certificate': 'Documento digitale di identità',
        'Vulnerability': 'Punto debole che va sistemato',
        'Encryption': 'Codifica dei dati per proteggerli'
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
        scoreEl.setAttribute('aria-label', `Punteggio di sicurezza: ${score} su 100`);
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
        helpDesc.textContent = 'Inserisci l\'indirizzo del tuo sito web da controllare, ad esempio miosito.com';
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
    scanButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Analizzando...';
    
    // User-friendly progress steps
    const steps = [
        { text: '🌐 Mi sto collegando al tuo sito...', progress: 15 },
        { text: '🔒 Controllo se i dati sono protetti...', progress: 35 },
        { text: '🆔 Verifico l\'identità del sito...', progress: 55 },
        { text: '🛡️ Analizzo le protezioni di sicurezza...', progress: 75 },
        { text: '📊 Calcolo il punteggio finale...', progress: 90 },
        { text: '✅ Quasi pronto!', progress: 100 }
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
    
    // Tutorial button removed
    
    // Tutorial removed - was annoying
    
    // Animate counters when they come into view
    animateCounters();
    
    // Add security tooltips
    addSecurityTooltips();
    
    // Improve accessibility
    improveAccessibility();
});

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
