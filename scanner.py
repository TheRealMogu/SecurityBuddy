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

COMMON_DIRS = [
    '/images/', '/img/', '/uploads/', '/static/', '/assets/',
    '/files/', '/backup/', '/media/', '/data/', '/js/', '/css/',
]

DANGLING_CNAME_SIGNATURES = {
    'github.io':          ["There isn't a GitHub Pages site here", "404 There is no GitHub Pages"],
    '.herokudns.com':     ['No such app', 'herokucdn.com/error-pages/no-such-app'],
    'amazonaws.com':      ['NoSuchBucket', '<Code>NoSuchKey</Code>'],
    'shopify.com':        ['Sorry, this shop is currently unavailable'],
    'fastly.net':         ['Fastly error: unknown domain'],
    'zendesk.com':        ['Help Center Closed'],
    'ghost.io':           ["The thing you were looking for is no longer here"],
    'surge.sh':           ['project not found'],
    'bitbucket.io':       ['Repository not found'],
    'netlify.app':        ['Not Found - Request ID:'],
    'azurewebsites.net':  ['Error 404 - Web app not found'],
    'cloudfront.net':     ['The request could not be satisfied'],
}

OPEN_REDIRECT_PARAMS = [
    'redirect', 'url', 'next', 'return', 'returnUrl',
    'goto', 'dest', 'redir', 'continue',
]

_REDIRECT_CANARY = 'https://redirect-test.securitybuddy.invalid'


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
                hostname = urlparse(target_url).hostname or target.split('/')[0]
                results['checks']['dns_security'] = self._check_dns_security(hostname)

            results['checks']['robots_txt']        = self._check_robots_txt(target_url)
            results['checks']['mixed_content']     = self._check_mixed_content(target_url)
            results['checks']['directory_listing'] = self._check_directory_listing(target_url, baseline)
            results['checks']['html_comments']     = self._check_html_comments(target_url)
            results['checks']['open_redirect']     = self._check_open_redirect(target_url)
            if not is_ip:
                hostname = urlparse(target_url).hostname or target.split('/')[0]
                results['checks']['hsts_quality']        = self._check_hsts_quality(target_url)
                results['checks']['subdomain_takeover']  = self._check_subdomain_takeover(hostname)
                results['checks']['http2']               = self._check_http2_support(hostname)

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

                    tls_ver = ssock.version()
                    results['tls_version'] = tls_ver
                    if tls_ver == 'TLSv1.3':
                        results['score'] += 5
                    elif tls_ver not in ('TLSv1.3', 'TLSv1.2'):
                        results['issues'].append(
                            f'Outdated TLS version: {tls_ver} — upgrade to TLS 1.2 minimum, TLS 1.3 recommended'
                        )
                        results['score'] -= 10
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

    def _check_dns_security(self, domain):
        results = {
            'spf_record': None,
            'spf_valid': False,
            'dmarc_record': None,
            'dmarc_valid': False,
            'score': 0,
            'issues': [],
        }
        try:
            import dns.resolver
            try:
                for rdata in dns.resolver.resolve(domain, 'TXT'):
                    txt = str(rdata).strip('"')
                    if txt.startswith('v=spf1'):
                        results['spf_record'] = txt
                        results['spf_valid'] = True
                        results['score'] += 5
                        break
            except Exception:
                pass

            if not results['spf_valid']:
                results['issues'].append(
                    'No SPF record found — domain can be used to forge sender addresses'
                )

            try:
                for rdata in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
                    txt = str(rdata).strip('"')
                    if txt.startswith('v=DMARC1'):
                        results['dmarc_record'] = txt
                        results['dmarc_valid'] = True
                        results['score'] += 5
                        if 'p=none' in txt:
                            results['issues'].append(
                                'DMARC policy is "none" — spoofed emails are monitored but not blocked; '
                                'upgrade to p=quarantine or p=reject'
                            )
                            results['score'] -= 2
                        break
            except Exception:
                pass

            if not results['dmarc_valid']:
                results['issues'].append(
                    'No DMARC record found — email authentication policy not configured'
                )
        except ImportError:
            results['issues'].append('DNS check unavailable (dnspython not installed)')
        except Exception as e:
            results['issues'].append(f'DNS security check failed: {str(e)}')

        results['score'] = max(0, results['score'])
        return results

    def _check_robots_txt(self, target_url):
        results = {
            'found': False,
            'disallowed_paths': [],
            'reveals_sensitive_paths': False,
            'issues': [],
        }
        try:
            resp = self.session.get(
                f"{target_url.rstrip('/')}/robots.txt",
                timeout=self.timeout,
                allow_redirects=True,
            )
            if resp.status_code == 200 and len(resp.content) < 100_000:
                body_lower = resp.content.lower()
                if b'user-agent' in body_lower or b'disallow' in body_lower:
                    results['found'] = True
                    disallowed = []
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path:
                                disallowed.append(path)
                    results['disallowed_paths'] = disallowed[:20]

                    sensitive_kw = [
                        'admin', 'backup', 'config', 'private', 'secret',
                        'api', 'internal', 'login', 'password', 'credential',
                        'database', 'db', 'env',
                    ]
                    sensitive = [p for p in disallowed if any(kw in p.lower() for kw in sensitive_kw)]
                    if sensitive:
                        results['reveals_sensitive_paths'] = True
                        preview = ', '.join(sensitive[:3])
                        more = f' (+{len(sensitive)-3} more)' if len(sensitive) > 3 else ''
                        results['issues'].append(
                            f'robots.txt reveals {len(sensitive)} sensitive path(s): {preview}{more}'
                        )
        except Exception as e:
            results['issues'].append(f'robots.txt check failed: {str(e)}')
        return results

    def _check_mixed_content(self, target_url):
        results = {
            'mixed_content_found': False,
            'insecure_resources': [],
            'score': 5,
            'issues': [],
        }
        if not target_url.startswith('https://'):
            return results
        try:
            resp = self.session.get(target_url, timeout=self.timeout)
            pattern = r'''(?:src|href|action|data)\s*=\s*['"]?(http://[^'">\s]+)'''
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            seen = set()
            unique = [m for m in matches if not (m in seen or seen.add(m))]
            if unique:
                results['mixed_content_found'] = True
                results['insecure_resources'] = unique[:10]
                results['score'] = 0
                results['issues'].append(
                    f'{len(unique)} insecure HTTP resource(s) on HTTPS page — '
                    'mixed content can be intercepted and weakens HTTPS'
                )
        except Exception as e:
            results['issues'].append(f'Mixed content check failed: {str(e)}')
        return results

    def _check_hsts_quality(self, target_url):
        results = {
            'present': False,
            'max_age': None,
            'includes_subdomains': False,
            'preload': False,
            'score': 0,
            'issues': [],
        }
        if not target_url.startswith('https://'):
            results['issues'].append('HSTS only applies to HTTPS — site is HTTP only')
            return results
        try:
            resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=True)
            hsts = resp.headers.get('Strict-Transport-Security', '')
            if not hsts:
                results['issues'].append('HSTS header missing — browsers will not enforce HTTPS-only')
                return results

            results['present'] = True
            results['score'] += 2

            ma = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
            if ma:
                max_age = int(ma.group(1))
                results['max_age'] = max_age
                if max_age >= 31_536_000:
                    results['score'] += 2
                elif max_age >= 2_592_000:
                    results['score'] += 1
                    results['issues'].append(
                        f'HSTS max-age {max_age}s is short — set to ≥31536000 (1 year)'
                    )
                else:
                    results['issues'].append(
                        f'HSTS max-age {max_age}s is too short — minimum 31536000 (1 year)'
                    )

            if 'includesubdomains' in hsts.lower():
                results['includes_subdomains'] = True
                results['score'] += 1
            else:
                results['issues'].append('HSTS missing includeSubDomains — subdomains are unprotected')

            if 'preload' in hsts.lower():
                results['preload'] = True
                results['score'] += 1
            else:
                results['issues'].append('HSTS missing preload directive — not eligible for browser preload list')
        except Exception as e:
            results['issues'].append(f'HSTS quality check failed: {str(e)}')
        results['score'] = max(0, results['score'])
        return results

    def _check_subdomain_takeover(self, domain):
        results = {
            'vulnerable': False,
            'cname_chain': [],
            'at_risk_service': None,
            'score': 5,
            'issues': [],
        }
        try:
            import dns.resolver
            try:
                for rdata in dns.resolver.resolve(domain, 'CNAME'):
                    cname_target = str(rdata.target).rstrip('.')
                    results['cname_chain'].append(cname_target)

                    for pattern, fingerprints in DANGLING_CNAME_SIGNATURES.items():
                        if pattern in cname_target:
                            try:
                                resp = self.session.get(
                                    f'https://{cname_target}',
                                    timeout=self.timeout,
                                    allow_redirects=True,
                                )
                                body = resp.text
                                if any(fp.lower() in body.lower() for fp in fingerprints):
                                    results['vulnerable'] = True
                                    results['at_risk_service'] = pattern
                                    results['score'] = 0
                                    results['issues'].append(
                                        f'Subdomain takeover risk: CNAME {cname_target} '
                                        f'points to unclaimed resource on {pattern}'
                                    )
                            except Exception:
                                pass
            except Exception:
                pass
        except ImportError:
            results['issues'].append('Subdomain check unavailable (dnspython not installed)')
        except Exception as e:
            results['issues'].append(f'Subdomain takeover check failed: {str(e)}')
        results['score'] = max(0, results['score'])
        return results

    def _check_directory_listing(self, target_url, baseline):
        results = {
            'exposed_dirs': [],
            'score': 5,
            'issues': [],
        }
        if baseline['is_spa']:
            return results

        base = target_url.rstrip('/')
        listing_markers = [
            'Index of /', '<title>Index of', 'Directory listing for',
            'Parent Directory', '[To Parent Directory]',
        ]
        for path in COMMON_DIRS:
            url = f'{base}{path}'
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code != 200:
                    continue
                if self._is_false_positive(resp, baseline):
                    continue
                if any(m in resp.text for m in listing_markers):
                    results['exposed_dirs'].append({'path': path, 'url': url})
                    results['score'] -= 2
                    results['issues'].append(f'Directory listing enabled at {path}')
            except Exception:
                pass
        results['score'] = max(0, results['score'])
        return results

    def _check_http2_support(self, hostname):
        results = {
            'http2_supported': False,
            'negotiated_protocol': None,
            'issues': [],
        }
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    proto = ssock.selected_alpn_protocol()
                    results['negotiated_protocol'] = proto
                    if proto == 'h2':
                        results['http2_supported'] = True
        except Exception as e:
            results['issues'].append(f'HTTP/2 check failed: {str(e)}')
        return results

    def _check_html_comments(self, target_url):
        results = {
            'generator_meta': None,
            'suspicious_comments': [],
            'version_disclosed': False,
            'score': 3,
            'issues': [],
        }
        try:
            resp = self.session.get(target_url, timeout=self.timeout)
            text = resp.text

            gen = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']'
                r'|<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
                text, re.IGNORECASE,
            )
            if gen:
                val = gen.group(1) or gen.group(2)
                results['generator_meta'] = val
                results['version_disclosed'] = True
                results['score'] -= 2
                results['issues'].append(
                    f'<meta name="generator"> reveals: {val}'
                )

            comments = re.findall(r'<!--(.*?)-->', text, re.DOTALL)
            ver_pattern = re.compile(
                r'(?:version|ver\.?\s*\d|v\d+\.\d+|powered by|generated by|built with)',
                re.IGNORECASE,
            )
            found = []
            for c in comments[:60]:
                c = c.strip()
                if 3 <= len(c) <= 300 and ver_pattern.search(c):
                    found.append(c[:120])
            if found:
                results['suspicious_comments'] = found[:5]
                results['version_disclosed'] = True
                results['score'] -= 1
                results['issues'].append(
                    f'{len(found)} HTML comment(s) may disclose version or stack info'
                )
        except Exception as e:
            results['issues'].append(f'HTML comment check failed: {str(e)}')
        results['score'] = max(0, results['score'])
        return results

    def _check_open_redirect(self, target_url):
        results = {
            'vulnerable_params': [],
            'score': 5,
            'issues': [],
        }
        base = target_url.rstrip('/')
        for param in OPEN_REDIRECT_PARAMS:
            test_url = f'{base}/?{param}={_REDIRECT_CANARY}'
            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get('Location', '')
                    if 'securitybuddy.invalid' in loc or _REDIRECT_CANARY in loc:
                        results['vulnerable_params'].append(param)
                        results['score'] = 0
                        results['issues'].append(
                            f'Open redirect via ?{param}= — attacker can send users to arbitrary URLs'
                        )
                        break
            except Exception:
                pass
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

        # DNS security (domain scans only)
        dns_sec = checks.get('dns_security', {})
        if dns_sec:
            total += min(dns_sec.get('score', 0), 10)

        # Mixed content
        mixed = checks.get('mixed_content', {})
        if mixed:
            total += min(mixed.get('score', 5), 5)

        # New checks
        if checks.get('hsts_quality'):
            total += min(checks['hsts_quality'].get('score', 0), 5)

        if checks.get('subdomain_takeover'):
            total += min(checks['subdomain_takeover'].get('score', 5), 5)

        if checks.get('directory_listing'):
            total += min(checks['directory_listing'].get('score', 5), 5)

        if checks.get('html_comments'):
            total += min(checks['html_comments'].get('score', 3), 3)

        if checks.get('open_redirect'):
            total += min(checks['open_redirect'].get('score', 5), 5)

        # HTTP/2 bonus (+1 for modern protocol support)
        if checks.get('http2', {}).get('http2_supported'):
            total += 1

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
