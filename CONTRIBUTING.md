# Contributing to SecurityBuddy

Thank you for your interest in contributing! This document covers the process for reporting bugs, requesting features, and submitting code changes.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Report a Bug](#how-to-report-a-bug)
- [How to Request a Feature](#how-to-request-a-feature)
- [Development Setup](#development-setup)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Style Guidelines](#style-guidelines)
- [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

This project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## How to Report a Bug

1. **Search existing issues** to avoid duplicates.
2. Open a new issue and use the **Bug report** template if available.
3. Include:
   - A clear, descriptive title
   - Steps to reproduce (target domain if relevant, anonymise if needed)
   - Expected vs actual behaviour
   - Browser/OS/Python version
   - Any relevant error messages or screenshots

> **Security vulnerabilities** must **not** be reported as public issues. See [SECURITY.md](SECURITY.md).

## How to Request a Feature

1. Search existing issues and discussions first.
2. Open a new issue with the **Feature request** label.
3. Describe the problem your feature solves, not just the solution.
4. If you plan to implement it yourself, say so — it avoids duplicate work.

## Development Setup

```bash
# Clone your fork
git clone https://github.com/<your-username>/securitybuddy
cd securitybuddy

# Install dependencies (Python 3.11+ recommended)
uv pip install -e .

# Set a dev secret and run
SESSION_SECRET=dev python main.py
# → http://localhost:5000
```

The app uses SQLite automatically when `DATABASE_URL` is not set, so no database setup is needed for local development.

### Running Checks

There is currently no automated test suite. Before submitting a PR, please manually verify:

- The scanner returns sensible results for a live domain (e.g. `example.com`)
- The page you changed renders correctly on both light and dark themes
- No Python tracebacks appear in the terminal while exercising your changes
- `python -c "import app"` exits cleanly (import-time errors are caught)

### Frontend Guidelines

- No build step, no bundler — plain HTML, CSS, and vanilla JS only.
- Visual enhancements live in `static/js/enhancements.js` and must remain lazy-loaded (activated after `window.load` + `requestIdleCallback`).
- Every new JS effect needs a bail-out for `prefers-reduced-motion`, Save-Data header, and missing browser API.
- CSS follows the custom-property design system in `static/css/style.css` — use `var(--color-*)`, `var(--font-*)`, `var(--radius-*)` tokens instead of hardcoded values.

### Keeping the Bundle Small

`requirements.txt` is the Vercel deploy manifest — every package added there inflates the cold-start time of the serverless function. Only add a package if it is truly required at runtime. Development-only and optional dependencies belong in `pyproject.toml`.

## Submitting a Pull Request

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b fix/descriptive-name
   ```
2. Make your changes and commit with a clear message explaining *why*, not just *what*.
3. Keep each PR focused on a single concern. Large mixed PRs are hard to review.
4. Open the PR against `main` with:
   - A description of the change and the motivation
   - Steps to verify the change manually (no automated tests yet)
   - Screenshots for any visual change
5. A maintainer will review it. Please respond to feedback within a reasonable time; PRs with no activity for 30 days may be closed.

## Style Guidelines

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Prefer explicit over clever. This is security-critical code — readability matters.
- No new dependencies without discussion.

### HTML / Jinja2

- Use semantic elements.
- All form inputs need a corresponding `<label>`.
- CSRF tokens are required on every state-changing form (use `{{ csrf_token() }}`).

### JavaScript

- ES5 syntax in `enhancements.js` (must run without transpiling, matches existing code).
- No `console.log` left in production paths.
- Prefer `addEventListener` over inline `on*` attributes.

### CSS

- Mobile-first. Add `@media` breakpoints when wider layouts benefit.
- Use the existing CSS variable tokens (`--color-primary`, `--color-bg`, etc.).
- Dark mode is handled via `[data-theme="dark"]` on `<html>` — never use `prefers-color-scheme` directly.

## Security Vulnerabilities

Please do **not** open a public GitHub issue for security vulnerabilities. Read [SECURITY.md](SECURITY.md) for the responsible disclosure process.
