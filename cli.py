#!/usr/bin/env python3
"""
Security Buddy CLI
------------------
Run security scans from the terminal.

Usage:
    python cli.py example.com
    python cli.py example.com --min-score 80 --json
    python cli.py example.com --api-url https://securitybuddy.app --api-key sk-...

Install as a global command (after pip install -e .):
    securitybuddy example.com
"""
import argparse
import json
import os
import sys
import textwrap
from typing import Optional

try:
    import requests
except ImportError:
    print('Error: requests is not installed. Run: pip install requests')
    sys.exit(1)

# ── ANSI colours (disabled on Windows or when not a tty) ────────────────────
USE_COLOUR = sys.stdout.isatty() and os.name != 'nt'


def _c(code: str, text: str) -> str:
    return f'\033[{code}m{text}\033[0m' if USE_COLOUR else text


def green(t):  return _c('92', t)
def yellow(t): return _c('93', t)
def red(t):    return _c('91', t)
def bold(t):   return _c('1',  t)
def dim(t):    return _c('2',  t)
def cyan(t):   return _c('96', t)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _score_colour(score: int) -> str:
    if score >= 80:
        return green(str(score))
    if score >= 60:
        return yellow(str(score))
    return red(str(score))


def _risk_colour(risk: str) -> str:
    mapping = {'low': green, 'medium': yellow, 'high': red, 'critical': red}
    return mapping.get(risk, str)(risk.upper())


def _bar(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    empty  = width - filled
    colour = green if score >= 80 else yellow if score >= 60 else red
    return '[' + colour('█' * filled) + dim('░' * empty) + ']'


# ── Scan via local scanner (no network to API) ───────────────────────────────
def _run_local_scan(target: str) -> dict:
    sys.path.insert(0, os.path.dirname(__file__))
    from scanner import SecurityScanner
    scanner = SecurityScanner()
    return scanner.scan_target(target)


# ── Scan via Security Buddy API ──────────────────────────────────────────────
def _run_api_scan(target: str, api_url: str, api_key: str) -> dict:
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['X-API-Key'] = api_key
    url = api_url.rstrip('/') + '/api/v1/scan'
    resp = requests.post(url, json={'target': target}, headers=headers, timeout=120)
    resp.raise_for_status()
    return resp.json()


# ── Pretty-print report ──────────────────────────────────────────────────────
def _print_report(report: dict, verbose: bool = False) -> None:
    target    = report.get('target', '?')
    score     = report.get('overall_score', 0)
    risk      = report.get('risk_level', 'unknown')
    scan_time = report.get('scan_time', '')[:19].replace('T', ' ')
    checks    = report.get('checks', {})

    print()
    print(bold('━' * 56))
    print(bold(f'  Security Buddy — {target}'))
    print(dim(f'  Scanned: {scan_time} UTC'))
    print(bold('━' * 56))
    print()
    print(f'  Score  {_bar(score)}  {_score_colour(score)}/100')
    print(f'  Risk   {_risk_colour(risk)}')
    print()

    CHECK_LABELS = {
        'connectivity': 'Connectivity',
        'https':        'HTTPS & Redirect',
        'ssl':          'SSL Certificate',
        'headers':      'Security Headers',
        'cookies':      'Cookie Security',
        'cors':         'CORS Policy',
        'http_methods': 'HTTP Methods',
        'tech':         'Tech Fingerprint',
        'ports':        'Open Ports',
        'domain_info':  'Domain Info',
    }

    print(bold('  Checks'))
    print(dim('  ──────────────────────────────────────────────────'))

    all_issues = []

    for key, label in CHECK_LABELS.items():
        check = checks.get(key)
        if check is None:
            continue
        if not isinstance(check, dict):
            continue
        issues = check.get('issues', [])
        n      = len(issues)
        if n == 0:
            indicator = green('✓')
        elif n <= 2:
            indicator = yellow('⚠')
        else:
            indicator = red('✗')
        suffix = dim(f'  ({n} issue{"s" if n != 1 else ""})') if n else ''
        print(f'  {indicator}  {label:<24}{suffix}')
        all_issues.extend((label, i) for i in issues)

    if all_issues:
        print()
        print(bold('  Findings'))
        print(dim('  ──────────────────────────────────────────────────'))
        prev_label = None
        for label, issue in all_issues:
            if label != prev_label:
                print(f'\n  {cyan(label)}')
                prev_label = label
            wrapped = textwrap.fill(issue, width=70, initial_indent='    • ',
                                    subsequent_indent='      ')
            print(red(wrapped) if 'CRITICAL' in issue.upper() else yellow(wrapped))

    print()
    print(bold('━' * 56))

    # Remediation hints
    hints = _remediation_hints(checks)
    if hints:
        print()
        print(bold('  Quick Remediation'))
        print(dim('  ──────────────────────────────────────────────────'))
        for priority, title, cmd in hints[:5]:
            col = red if 'CRITICAL' in priority else yellow if 'HIGH' in priority else dim
            print(f'\n  {col(priority)}  {bold(title)}')
            if cmd:
                print(dim(f'    $ {cmd}'))
    print()


def _remediation_hints(checks):
    hints = []
    https = checks.get('https', {})
    if not https.get('https_available'):
        hints.append(('[CRITICAL]', 'Enable HTTPS', 'certbot --nginx -d yourdomain.com'))
    if not https.get('redirects_to_https'):
        hints.append(('[HIGH]', 'Force HTTPS redirect', None))

    ssl = checks.get('ssl', {})
    if ssl.get('expires_soon'):
        hints.append(('[HIGH]', 'Renew SSL certificate', 'certbot renew'))
    if not ssl.get('valid') and not ssl.get('expires_soon'):
        hints.append(('[CRITICAL]', 'Replace invalid SSL certificate', None))

    cors = checks.get('cors', {})
    if cors.get('credentials_with_wildcard'):
        hints.append(('[CRITICAL]', 'Fix CORS: wildcard + credentials', None))

    missing = checks.get('headers', {}).get('headers_missing', [])
    if 'Strict-Transport-Security' in missing:
        hints.append(('[HIGH]', 'Add HSTS header', None))
    if 'Content-Security-Policy' in missing:
        hints.append(('[HIGH]', 'Add Content-Security-Policy header', None))

    if checks.get('tech', {}).get('version_disclosed'):
        hints.append(('[LOW]', 'Remove server version from headers', None))

    open_ports = checks.get('ports', {}).get('open_ports', [])
    if open_ports:
        port = open_ports[0]['port']
        hints.append(('[MEDIUM]', f'Close exposed port {port}', f'ufw deny {port}'))

    return hints


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog='securitybuddy',
        description='Security Buddy CLI — instant web security scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              securitybuddy example.com
              securitybuddy example.com --min-score 80
              securitybuddy example.com --json --output report.json
              securitybuddy example.com --api-url https://securitybuddy.app --api-key sk-...
        '''),
    )
    parser.add_argument('target', help='Domain or IP address to scan')
    parser.add_argument('--api-url',   default='', help='Security Buddy API base URL (optional)')
    parser.add_argument('--api-key',   default=os.environ.get('SECURITY_BUDDY_API_KEY', ''),
                        help='API key (or set SECURITY_BUDDY_API_KEY env var)')
    parser.add_argument('--min-score', type=int, default=0,
                        help='Exit with code 1 if score is below this threshold')
    parser.add_argument('--fail-on-critical', action='store_true', default=False,
                        help='Exit with code 1 if risk level is critical')
    parser.add_argument('--json', action='store_true', help='Print raw JSON output')
    parser.add_argument('--output', metavar='FILE', help='Write JSON report to FILE')
    parser.add_argument('--verbose', '-v', action='store_true', help='Extra output')

    args = parser.parse_args()

    # Run the scan
    try:
        if args.api_url:
            print(dim(f'Scanning {args.target} via API ({args.api_url}) ...'))
            report = _run_api_scan(args.target, args.api_url, args.api_key)
        else:
            print(dim(f'Scanning {args.target} locally ...'))
            report = _run_local_scan(args.target)
    except KeyboardInterrupt:
        print('\nAborted.')
        sys.exit(130)
    except Exception as e:
        print(red(f'Error: {e}'))
        sys.exit(1)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(dim(f'Report saved to {args.output}'))

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report, verbose=args.verbose)

    # Exit code
    score = report.get('overall_score', 0)
    risk  = report.get('risk_level', '')
    failed = False
    if args.fail_on_critical and risk == 'critical':
        print(red(f'FAIL: risk level is critical for {args.target}'))
        failed = True
    if args.min_score and score < args.min_score:
        print(red(f'FAIL: score {score} is below minimum {args.min_score}'))
        failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
