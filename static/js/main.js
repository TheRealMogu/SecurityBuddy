// Security Buddy Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

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

            // Show loading state
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Scanning...';
            
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

// Export functions for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        validateTarget,
        cleanTarget,
        formatSecurityScore,
        formatRiskLevel
    };
}
