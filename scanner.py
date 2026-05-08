import requests
import socket
import ssl
import json
import re
import uuid
from urllib.parse import urlparse
from datetime import datetime, timezone
import logging

SENSITIVE_PATHS = {
    '.env':              ['DB_PASSWORD', 'API_KEY', 'SECRET_KEY', 'APP_KEY', 'DATABASE_URL', 'AWS_SECRET'],
    '.env.local':        ['DB_PASSWORD', 'API_KEY', 'SECRET_KEY', 'APP_KEY'],
    '.env.production':   ['DB_PASSWORD', 'API_KEY', 'SECRET_KEY', 'APP_KEY'],
    'wp-config.php':     ['DB_NAME', 'DB_USER', 'DB_PASSWORD', "define("],
    '.git/config':       ['[core]', '[remote', 'repositoryformatversion'],
    '.git/HEAD':         ['ref:', 'refs/heads'],
    'config.php':        ['password', 'db_pass', 'mysql_pass'],
    'database.yml':      ['password:', 'username:', 'database:'],
    'credentials':       ['aws_access_key_id', 'aws_secret_access_key'],
    '.htpasswd':         [':'],
}

ADMIN_PATHS = [
    '/admin', '/admin/', '/administrator', '/wp-admin', '/phpmyadmin',
    '/manager', '/cpanel', '/dashboard', '/backend',
]

RISKY_PORTS = {
    21:    'FTP — plaintext file transfer',
    22:    'SSH — verify it is intentionally exposed',
    23:    'Telnet — plaintext, replace with SSH',
    25:    'SMTP — mail relay, check for open relay',
    3306:  'MySQL — database should not be publicly reachable',
    5432:  'PostgreSQL — database should not be publicly reachable',
    6379:  'Redis — often unauthenticated, high-severity exposure',
    8080:  'HTTP alt port — often an unprotected admin interface',
    8443:  'HTTPS alt port — verify it enforces the same security policy',
    27017: 'MongoDB — database should not be publicly reachable',
    9200:  'Elasticsearch — often unauthenticated, high-severity exposure',
}


class SecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = True
        self.session.headers.update({
            'User-Agent': 'SecurityBuddy/2.0 (Security Scanner)'
        })
        self.timeout = 10

    def scan_target(self, target):
        results = {
            'target': target,
            'scan_time': datetime.utcnow().isoformat(),
            'checks': {},
            'overall_score': 0,
            'risk_level': 'unknown',
        }

        is_ip = self._is_ip_address(target)
        results['scan_type'] = 'ip' if is_ip else 'domain'

        if not target.startswith(('http://', 'https://')):
            target_url = f'https://{target}'
        else:
            target_url = target

        try:
            baseline = self._get_404_baseline(target_url)
            results['spa_detected'] = baseline['is_spa']

            results['checks']['connectivity'] = self._check_connectivity(target_url)
            results['checks']['https']        = self._check_https(target_url)
            results['checks']['ssl']          = self._check_ssl_certificate(target)
            results['checks']['headers']      = self._check_security_headers(target_url)
            results['checks']['cookies']      = self._check_cookie_security(target_url)
            results['checks']['cors']         = self._check_cors(target_url)
            results['checks']['http_methods'] = self._check_http_methods(target_url)
            results['checks']['tech']         = self._check_technology_disclosure(target_url)
            results['checks']['ports']        = self._check_open_ports(target)
            results['checks']['sensitive_files'] = self._check_sensitive_files(target_url, baseline)
            results['checks']['admin_panels']    = self._check_admin_panels(target_url, baseline)
            if not is_ip:
                results['checks']['domain_info'] = self._get_domain_info(target)

            results['overall_score'] = self._calculate_score(results['checks'])
            results['risk_level']    = self._determine_risk_level(results['overall_score'])

        except Exception as e:
            logging.error(f'Error scanning {target}: {str(e)}')
            results['error'] = str(e)

        return results

    # ------------------------------------------------------------------
    # Existing checks (unchanged)
    # ------------------------------------------------------------------

    def _is_ip_address(self, target):
        try:
            socket.inet_aton(target.split(':')[0])
            return True
        except socket.error:
            return False

    def _check_connectivity(self, target_url):
        try:
            response = self.session.head(target_url, timeout=self.timeout, allow_redirects=True)
            return {
                'status': 'success',
                'reachable': True,
                'status_code': response.status_code,
                'message': 'Target is reachable',
            }
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'reachable': False,
                'message': f'Target unreachable: {str(e)}',
            }

    def _check_https(self, target_url):
        results = {
            'https_available': False,
            'redirects_to_https': False,
            'mixed_content_risk': False,
            'score': 0,
            'issues': [],
        }
        try:
            if target_url.startswith('https://'):
                self.session.get(target_url, timeout=self.timeout)
                results['https_available'] = True
                results['score'] += 40

            http_url = target_url.replace('https://', 'http://')
            try:
                http_response = self.session.get(http_url, timeout=self.timeout, allow_redirects=False)
                if http_response.status_code in [301, 302, 307, 308]:
                    location = http_response.headers.get('Location', '')
                    if location.startswith('https://'):
                        results['redirects_to_https'] = True
                        results['score'] += 30
                    else:
                        results['issues'].append('HTTP does not redirect to HTTPS')
                else:
                    results['issues'].append('HTTP version is accessible without redirect')
            except Exception:
                pass
        except requests.exceptions.SSLError:
            results['issues'].append('SSL/TLS connection failed')
        except requests.exceptions.RequestException as e:
            results['issues'].append(f'HTTPS check failed: {str(e)}')
        return results

    def _check_ssl_certificate(self, target):
        results = {
            'valid': False,
            'expires_soon': False,
            'self_signed': False,
            'days_until_expiry': None,
            'issuer': None,
            'score': 0,
            'issues': [],
        }
        try:
            if '://' in target:
                hostname = urlparse(target).netloc
            else:
                hostname = target
            if ':' in hostname:
                host, port = hostname.rsplit(':', 1)
                port = int(port)
            else:
                host, port = hostname, 443

            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_until_expiry = (expiry_date - now).days

                    results['days_until_expiry'] = days_until_expiry
                    results['valid'] = True
                    results['score'] += 50

                    if days_until_expiry < 30:
                        results['expires_soon'] = True
                        results['issues'].append(f'Certificate expires in {days_until_expiry} days — renew now')
                        results['score'] -= 20

                    issuer = dict(x[0] for x in cert['issuer'])
                    results['issuer'] = issuer.get('organizationName', 'Unknown')
        except ssl.SSLError as e:
            results['issues'].append(f'SSL Error: {str(e)}')
        except Exception as e:
            results['issues'].append(f'Certificate check failed: {str(e)}')
        return results

    def _check_security_headers(self, target_url):
        results = {
            'score': 0,
            'headers_found': [],
            'headers_missing': [],
            'csp_quality': None,
            'issues': [],
        }
        security_headers = {
            'Strict-Transport-Security': 'HSTS not enabled',
            'Content-Security-Policy': 'CSP not configured',
            'X-Frame-Options': 'Clickjacking protection (X-Frame-Options) missing',
            'X-Content-Type-Options': 'MIME-sniffing protection (X-Content-Type-Options) missing',
            'Referrer-Policy': 'Referrer-Policy not set',
            'Permissions-Policy': 'Permissions-Policy not configured',
        }
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            headers = response.headers

            for header, issue in security_headers.items():
                if header in headers:
                    results['headers_found'].append({'name': header, 'value': headers[header]})
                    results['score'] += 15
                else:
                    results['headers_missing'].append(header)
                    results['issues'].append(issue)

            # CSP quality analysis
            csp = headers.get('Content-Security-Policy', '')
            if csp:
                results['csp_quality'] = self._analyse_csp(csp)

            if 'Server' in headers:
                sv = headers['Server']
                if any(t in sv.lower() for t in ['apache/', 'nginx/', 'iis/']):
                    results['issues'].append(f'Server version disclosed: {sv}')
        except requests.exceptions.RequestException as e:
            results['issues'].append(f'Header check failed: {str(e)}')
        return results

    # ------------------------------------------------------------------
    # New checks
    # ------------------------------------------------------------------

    def _check_cookie_security(self, target_url):
        results = {
            'total_cookies': 0,
            'insecure_cookies': [],
            'secure_cookies': [],
            'score': 0,
            'issues': [],
        }
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            cookies = response.cookies

            results['total_cookies'] = len(cookies)
            all_secure = True

            for cookie in cookies:
                flags = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'http_only': cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'),
                    'same_site': cookie.get_nonstandard_attr('SameSite') or cookie.get_nonstandard_attr('samesite'),
                }
                missing = []
                if not flags['secure']:
                    missing.append('Secure')
                if not flags['http_only']:
                    missing.append('HttpOnly')
                if not flags['same_site']:
                    missing.append('SameSite')

                if missing:
                    all_secure = False
                    results['insecure_cookies'].append({
                        'name': cookie.name,
                        'missing_flags': missing,
                    })
                    results['issues'].append(
                        f'Cookie "{cookie.name}" missing: {", ".join(missing)}'
                    )
                else:
                    results['secure_cookies'].append(cookie.name)

            if results['total_cookies'] == 0:
                results['score'] = 10
            elif all_secure:
                results['score'] = 20
            else:
                results['score'] = max(0, 20 - len(results['insecure_cookies']) * 5)
        except Exception as e:
            results['issues'].append(f'Cookie check failed: {str(e)}')
        return results

    def _check_cors(self, target_url):
        results = {
            'wildcard_origin': False,
            'credentials_with_wildcard': False,
            'cors_header_present': False,
            'score': 10,
            'issues': [],
        }
        try:
            headers = {'Origin': 'https://evil.example.com'}
            response = self.session.get(target_url, headers=headers, timeout=self.timeout)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if acao:
                results['cors_header_present'] = True
                if acao == '*':
                    results['wildcard_origin'] = True
                    results['score'] -= 5
                    results['issues'].append(
                        'Access-Control-Allow-Origin: * allows any site to read responses'
                    )
                    if acac.lower() == 'true':
                        results['credentials_with_wildcard'] = True
                        results['score'] -= 5
                        results['issues'].append(
                            'CRITICAL: Access-Control-Allow-Credentials: true combined with wildcard origin '
                            'allows cross-origin credential theft'
                        )
        except Exception as e:
            results['issues'].append(f'CORS check failed: {str(e)}')
        results['score'] = max(0, results['score'])
        return results

    def _check_http_methods(self, target_url):
        results = {
            'allowed_methods': [],
            'dangerous_methods': [],
            'score': 10,
            'issues': [],
        }
        dangerous = {'TRACE', 'TRACK', 'DELETE', 'PUT', 'PATCH'}
        try:
            response = self.session.options(target_url, timeout=self.timeout)
            allow_header = response.headers.get('Allow', '') or response.headers.get('Access-Control-Allow-Methods', '')
            methods = [m.strip().upper() for m in allow_header.split(',') if m.strip()]
            results['allowed_methods'] = methods

            for method in methods:
                if method in dangerous:
                    results['dangerous_methods'].append(method)
                    results['score'] -= 3
                    results['issues'].append(
                        f'HTTP method {method} is allowed — restrict if not required'
                    )
            if 'TRACE' in methods or 'TRACK' in methods:
                results['issues'].append(
                    'TRACE/TRACK methods enable Cross-Site Tracing (XST) attacks — disable immediately'
                )
        except Exception as e:
            results['issues'].append(f'HTTP methods check failed: {str(e)}')
        results['score'] = max(0, results['score'])
        return results

    def _check_technology_disclosure(self, target_url):
        results = {
            'technologies': [],
            'version_disclosed': False,
            'score': 10,
            'issues': [],
        }
        version_patterns = [
            (r'Apache/([\d.]+)',    'Apache'),
            (r'nginx/([\d.]+)',     'Nginx'),
            (r'PHP/([\d.]+)',       'PHP'),
            (r'ASP\.NET',           'ASP.NET'),
            (r'Express',            'Express.js'),
            (r'WordPress/([\d.]+)', 'WordPress'),
            (r'Drupal/([\d.]+)',    'Drupal'),
            (r'Joomla',             'Joomla'),
            (r'OpenSSL/([\d.]+)',   'OpenSSL'),
        ]
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            header_blob = ' '.join([
                response.headers.get('Server', ''),
                response.headers.get('X-Powered-By', ''),
                response.headers.get('X-Generator', ''),
                response.headers.get('X-Drupal-Cache', ''),
            ])

            for pattern, name in version_patterns:
                match = re.search(pattern, header_blob, re.IGNORECASE)
                if match:
                    groups = match.groups()
                    version = groups[0] if groups else None
                    entry = {'name': name}
                    if version:
                        entry['version'] = version
                        results['version_disclosed'] = True
                        results['score'] -= 3
                        results['issues'].append(
                            f'{name} version {version} disclosed in headers — remove or mask version info'
                        )
                    results['technologies'].append(entry)

            if response.headers.get('X-Powered-By'):
                results['issues'].append(
                    f'X-Powered-By header reveals technology stack: {response.headers["X-Powered-By"]}'
                )
        except Exception as e:
            results['issues'].append(f'Technology fingerprint failed: {str(e)}')
        results['score'] = max(0, results['score'])
        return results

    def _get_404_baseline(self, target_url):
        fake_path = f'/{uuid.uuid4().hex}'
        try:
            response = self.session.get(
                f'{target_url.rstrip("/")}{fake_path}',
                timeout=self.timeout,
                allow_redirects=True,
            )
            return {
                'status': response.status_code,
                'size': len(response.content),
                'is_spa': response.status_code == 200,
            }
        except Exception:
            return {'status': None, 'size': 0, 'is_spa': False}

    def _is_false_positive(self, response, baseline):
        size_diff = abs(len(response.content) - baseline['size'])
        return size_diff < 50

    def _is_real_exposure(self, path, response_text):
        patterns = SENSITIVE_PATHS.get(path, [])
        if not patterns:
            return True
        return any(p in response_text for p in patterns)

    def _check_sensitive_files(self, target_url, baseline):
        results = {
            'exposed_files': [],
            'skipped_spa': baseline['is_spa'],
            'score': 10,
            'issues': [],
        }

        if baseline['is_spa']:
            results['issues'].append(
                'SPA detected — sensitive file exposure checks skipped to avoid false positives'
            )
            return results

        base = target_url.rstrip('/')
        for path, _ in SENSITIVE_PATHS.items():
            url = f'{base}/{path}'
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if response.status_code != 200:
                    continue
                if self._is_false_positive(response, baseline):
                    continue
                if not self._is_real_exposure(path, response.text):
                    continue
                results['exposed_files'].append({'path': path, 'url': url})
                results['score'] -= 5
                results['issues'].append(
                    f'Sensitive file exposed: /{path} — remove from public web root immediately'
                )
            except Exception:
                pass

        results['score'] = max(0, results['score'])
        return results

    def _check_admin_panels(self, target_url, baseline):
        results = {
            'exposed_panels': [],
            'skipped_spa': baseline['is_spa'],
            'score': 10,
            'issues': [],
        }

        if baseline['is_spa']:
            results['issues'].append(
                'SPA detected — admin panel discovery skipped to avoid false positives'
            )
            return results

        base = target_url.rstrip('/')
        for path in ADMIN_PATHS:
            url = f'{base}{path}'
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if response.status_code not in (200, 401, 403):
                    continue
                if response.status_code == 200 and self._is_false_positive(response, baseline):
                    continue
                results['exposed_panels'].append({'path': path, 'status': response.status_code})
                results['score'] -= 3
                results['issues'].append(
                    f'Admin panel reachable at {path} (HTTP {response.status_code})'
                )
            except Exception:
                pass

        results['score'] = max(0, results['score'])
        return results

    def _check_open_ports(self, target):
        results = {
            'open_ports': [],
            'score': 10,
            'issues': [],
        }
        if '://' in target:
            host = urlparse(target).hostname or target
        else:
            host = target.split(':')[0]

        for port, description in RISKY_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                connected = sock.connect_ex((host, port)) == 0
                sock.close()
                if connected:
                    results['open_ports'].append({'port': port, 'description': description})
                    results['score'] -= 2
                    results['issues'].append(f'Port {port} open — {description}')
            except Exception:
                pass
        results['score'] = max(0, results['score'])
        return results

    def _get_domain_info(self, domain):
        results = {
            'domain': domain,
            'info_available': False,
            'issues': [],
        }
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.timeout)
            try:
                ip_address = socket.gethostbyname(domain)
                results['ip_address'] = ip_address
                results['info_available'] = True
            finally:
                socket.setdefaulttimeout(old_timeout)
        except socket.gaierror as e:
            results['issues'].append(f'DNS resolution failed: {str(e)}')
        except Exception as e:
            results['issues'].append(f'Domain info check failed: {str(e)}')
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _analyse_csp(self, csp):
        quality = {
            'has_default_src': False,
            'allows_unsafe_inline': False,
            'allows_unsafe_eval': False,
            'allows_wildcard_src': False,
            'issues': [],
            'rating': 'good',
        }
        if 'default-src' in csp:
            quality['has_default_src'] = True
        if "'unsafe-inline'" in csp:
            quality['allows_unsafe_inline'] = True
            quality['issues'].append("CSP contains 'unsafe-inline' — negates XSS protection")
        if "'unsafe-eval'" in csp:
            quality['allows_unsafe_eval'] = True
            quality['issues'].append("CSP contains 'unsafe-eval' — allows arbitrary JS execution")
        if re.search(r"src\s+['\"]?\*", csp):
            quality['allows_wildcard_src'] = True
            quality['issues'].append("CSP uses wildcard (*) source — too permissive")

        if quality['issues']:
            quality['rating'] = 'weak' if len(quality['issues']) >= 2 else 'moderate'
        return quality

    def _calculate_score(self, checks):
        total = 0
        total += 10 if checks.get('connectivity', {}).get('status') == 'success' else 0
        total += min(checks.get('https', {}).get('score', 0), 25)
        total += min(checks.get('ssl', {}).get('score', 0), 25)
        total += min(checks.get('headers', {}).get('score', 0), 20)
        total += min(checks.get('cookies', {}).get('score', 0), 5)
        total += min(checks.get('cors', {}).get('score', 0), 5)
        total += min(checks.get('http_methods', {}).get('score', 0), 5)
        total += min(checks.get('tech', {}).get('score', 0), 5)
        total += min(checks.get('ports', {}).get('score', 0), 5)

        # Sensitive file and admin panel checks are only counted when not SPA-skipped,
        # ensuring that bypassed checks don't penalise the score unfairly.
        sensitive = checks.get('sensitive_files', {})
        if not sensitive.get('skipped_spa'):
            total += min(sensitive.get('score', 10), 10)

        admin = checks.get('admin_panels', {})
        if not admin.get('skipped_spa'):
            total += min(admin.get('score', 10), 10)

        # CSP quality bonus / penalty
        csp_quality = checks.get('headers', {}).get('csp_quality')
        if csp_quality:
            if csp_quality['rating'] == 'good':
                total += 3
            elif csp_quality['rating'] == 'weak':
                total -= 5
        return min(max(total, 0), 100)

    def _determine_risk_level(self, score):
        if score >= 80:
            return 'low'
        elif score >= 60:
            return 'medium'
        elif score >= 40:
            return 'high'
        else:
            return 'critical'
